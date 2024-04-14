#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <linux/loop.h>
#include <linux/vt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void wait_for_pid1() {
    int wstatus;
    if (waitpid(1, &wstatus, 0) == -1) {
        perror("Failed to wait for PID 1");
        exit(2);
    }

    if (!WIFSTOPPED(wstatus)) {
        fputs("Expected PID 1 to be stopped, got another wait status instead\n", stderr);
        exit(2);
    }
}

[[noreturn]] void init() {
    // If a failure occurs here, we don't want the kernel to panic so that the user can check error
    // messages.

    // No error checking around logging
    int log_fd = open("/run/dexec/dexec.log", O_WRONLY | O_CREAT, 0600);
    if (log_fd == -1) {
        dup2(log_fd, 2);
    }

    int console_fd = open("/dev/console", O_RDWR);
    if (console_fd == -1) {
        perror("Failed to open /dev/console");
        goto err;
    }

    // Use tty 3, as tty 1/2 are commonly used by DEs and display managers
    if (ioctl(console_fd, VT_ACTIVATE, 3) == -1) {
        perror("Failed to activate virtual terminal");
        goto err;
    }

    if (ioctl(console_fd, KDSETMODE, KD_TEXT) == -1) {
        perror("Failed to switch virtual terminal to text mode");
        goto err;
    }

    close(console_fd);

    int tty_fd = open("/dev/tty3", O_RDWR);
    if (tty_fd == -1) {
        perror("Failed to open /dev/tty3");
        goto err;
    }

    for (int fd = 0; fd < 3; fd++) {
        if (dup2(tty_fd, fd) == -1) {
            perror("Failed to redirect stdio to VT");
            goto err;
        }
    }

    close(tty_fd);

    // We are now attached to the virtual terminal the user supposedly has access to.

    fputs("dexec: dexec is now online\n", stderr);
    fflush(stdout);

    // Close all fds, include non-loexec
    if (syscall(SYS_close_range, 3, ~0, 0) == -1) {
        perror("dexec: Failed to close fds");
        goto err;
    }

    int argv_fd = open("/run/dexec/argv", O_RDONLY);
    if (argv_fd == -1) {
        perror("Failed to open /run/dexec/argv");
        goto err;
    }
    char argv_buffer[65537];
    size_t argv_offset = 0;
    for (;;) {
        size_t n_read = read(argv_fd, argv_buffer + argv_offset, sizeof(argv_buffer) - 1 - argv_offset);
        if (n_read == -1) {
            perror("Failed to read /run/dexec/argv");
            goto err;
        }
        if (n_read == 0) {
            break;
        }
        argv_offset += n_read;
    }
    argv_buffer[argv_offset] = '\0';
    close(argv_fd);

    char *argv_pointers[256];
    char *p = argv_buffer;
    int i = 0;
    while (i < 255 && p != argv_buffer + argv_offset) {
        argv_pointers[i++] = p;
        p += strlen(p) + 1;
    }
    argv_pointers[i] = NULL;
    if (p != argv_buffer + argv_offset) {
        fputs("Invalid init command line\n", stderr);
        goto err;
    }

    fputs("dexec: Sending SIGTERM to all processes\n", stderr);
    fflush(stdout);
    if (kill(-1, SIGTERM) == -1) {
        perror("dexec: Failed to send SIGTERM");
        goto err;
    }

    // Sleep for 3 seconds
    usleep(3000000);

    fputs("dexec: Sending SIGKILL to all processes\n", stderr);
    fflush(stdout);
    if (kill(-1, SIGKILL) == -1) {
        perror("Failed to send SIGKILL");
        goto err;
    }

    int wstatus;
    while (wait(&wstatus) != -1) {}
    if (errno != ECHILD) {
        perror("Failed to wait for children to terminate");
        goto err;
    }

    // We are now the only process alive.

    if (chdir("/run/dexec/root") == -1) {
        perror("Failed to chdir to /run/dexec/root");
        goto err;
    }
    if (syscall(SYS_pivot_root, ".", ".") == -1) {
        perror("Failed to pivot_root");
        goto err;
    }
    if (umount2(".", MNT_DETACH) == -1) {
        perror("Failed to unmount old root");
        goto err;
    }
    if (chdir("/") == -1) {
        perror("Failed to chdir to /");
        goto err;
    }

    char *envp[] = {"TERM=linux", NULL};
    execve(argv_pointers[0], argv_pointers, envp);
    perror("Failed to exec init");

err:
    fputs("dexec: Entering recovery shell\n", stderr);
    fflush(stdout);
    fflush(stderr);

    execle("/bin/sh", "sh", NULL, envp);
    perror("Failed to execute /bin/sh");
    fflush(stderr);

    for (;;) {
        pause();
    }
}

int main(int argc, char **argv) {
    if (getpid() == 1) {
        init();
    }

    // This interface is visible to the user.
    if (argc < 3) {
        fputs("dexec: Replace running system with a system from a Docker image\n", stderr);
        fprintf(stderr, "Usage: %s <docker image ID> <init command>\n", argv[0]);
        return 1;
    }
    if (argv[2][0] != '/') {
        fputs("init command must have an absolute path\n", stderr);
        return 1;
    }

    if (getuid() != 0) {
        fputs("You are not root, aborting\n", stderr);
        return 1;
    }

    if (system("swapoff --all") != 0) {
        fputs("Failed to disable swap", stderr);
        return 2;
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname) - 3) == -1) {
        perror("Failed to get hostname");
    }
    hostname[sizeof(hostname) - 1] = '\0';

    if (mkdir("/run/dexec", 0700) == -1 && errno != EEXIST) {
        perror("Failed to create /run/dexec");
        return 2;
    }
    if (mkdir("/run/dexec/root", 0700) == -1 && errno != EEXIST) {
        perror("Failed to create /run/dexec/root");
        return 2;
    }
    if (mount(NULL, "/run/dexec/root", "tmpfs", 0, NULL) == -1) {
        perror("Failed to mount tmpfs on /run/dexec/root");
        return 2;
    }

    int argv_fd = open("/run/dexec/argv", O_WRONLY | O_CREAT, 0600);
    if (argv_fd == -1) {
        perror("Failed to open /run/dexec/argv");
        return 2;
    }
    if (argc > 256) {
        fputs("Too many arguments\n", stderr);
        return 1;
    }
    size_t total_length = 0;
    for (int i = 2; i < argc; i++) {
        size_t count_written = 0;
        size_t count = strlen(argv[i]) + 1;
        total_length += count;
        while (count_written < count) {
            ssize_t result = write(argv_fd, argv[i] + count_written, count - count_written);
            if (result == -1) {
                perror("Failed to write to /run/dexec/argv");
                return 2;
            }
            count_written += result;
        }
    }
    if (total_length > 65536) {
        fputs("argv too long\n", stderr);
        return 1;
    }
    if (close(argv_fd) == -1) {
        perror("Failed to close /run/dexec/argv");
        return 2;
    }

    int fds[2];
    if (pipe(fds) == -1) {
        perror("Failed to create pipe");
        umount("/run/dexec/root");
        return 2;
    }
    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("Failed to fork");
        umount("/run/dexec/root");
        return 2;
    }
    if (child_pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], 1) == -1) {
            perror("Failed to redirect stdout");
            return 2;
        }
        execlp("docker", "docker", "create", argv[1], NULL);
        perror("Failed to exec docker create");
        return 2;
    }
    close(fds[1]);
    int wstatus;
    if (waitpid(child_pid, &wstatus, 0) == -1) {
        perror("Failed to wait for child");
        umount("/run/dexec/root");
        return 2;
    }
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        fputs("docker create failed\n", stderr);
        umount("/run/dexec/root");
        return 2;
    }
    char container_id[256];
    ssize_t container_id_length = read(fds[0], container_id, sizeof(container_id));
    if (container_id_length == -1) {
        perror("Failed to receive container ID from docker create");
        umount("/run/dexec/root");
        return 2;
    }
    close(fds[0]);
    while (container_id_length > 0 && isspace((int)container_id[container_id_length - 1])) {
        container_id_length--;
    }
    container_id[container_id_length] = '\0';

    if (pipe(fds) == -1) {
        perror("Failed to create pipe");
        umount("/run/dexec/root");
        return 2;
    }

    fputs("Copying root filesystem to rootfs...\n", stderr);
    fflush(stderr);

    char cmdline[4096];
    sprintf(cmdline, "docker cp %s:/ - | pv | tar xf /dev/stdin -C /run/dexec/root", container_id);
    int cp_is_success = system(cmdline) == 0;

    sprintf(cmdline, "docker rm %s >/dev/null", container_id);
    if (system(cmdline) != 0) {
        fputs("docker rm failed\n", stderr);
        umount("/run/dexec/root");
        return 2;
    }

    if (!cp_is_success) {
        fputs("Copying root to ramfs failed\n", stderr);
        umount("/run/dexec/root");
        return 2;
    }

    int etc_hostname_fd = open("/run/dexec/root/etc/hostname", O_WRONLY | O_CREAT, 0644);
    if (etc_hostname_fd == -1) {
        perror("Failed to open /run/dexec/root/etc/hostname");
        umount("/run/dexec/root");
        return 2;
    }
    errno = 0;
    if (write(etc_hostname_fd, hostname, strlen(hostname)) != strlen(hostname)) {
        perror("Failed to write hostname");
        umount("/run/dexec/root");
        return 2;
    }
    close(etc_hostname_fd);

    int etc_hosts_fd = open("/run/dexec/root/etc/hosts", O_WRONLY | O_CREAT, 0644);
    if (etc_hosts_fd == -1) {
        perror("Failed to open /run/dexec/root/etc/hosts");
        umount("/run/dexec/root");
        return 2;
    }
    char hosts[4096];
    sprintf(hosts, "127.0.0.1 localhost\n127.0.0.1 %s\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n", hostname);
    errno = 0;
    if (write(etc_hosts_fd, hosts, strlen(hosts)) != strlen(hosts)) {
        perror("Failed to write hosts");
        umount("/run/dexec/root");
        return 2;
    }
    close(etc_hosts_fd);

    int etc_resolv_conf_fd = open("/run/dexec/root/etc/resolv.conf", O_WRONLY | O_CREAT, 0644);
    if (etc_resolv_conf_fd == -1) {
        perror("Failed to open /run/dexec/root/etc/resolv.conf");
        umount("/run/dexec/root");
        return 2;
    }
    errno = 0;
    if (write(etc_resolv_conf_fd, "nameserver 8.8.8.8\n", 19) != 19) {
        perror("Failed to write resolv.conf");
        umount("/run/dexec/root");
        return 2;
    }
    close(etc_resolv_conf_fd);

    int root_fd = open("/run/dexec/root", __O_PATH);
    if (root_fd == -1) {
        perror("Failed to open /run/dexec/root");
        umount("/run/dexec/root");
        return 2;
    }
    int init_fd = openat(root_fd, argv[2] + 1, O_RDONLY);
    if (init_fd == -1) {
        perror("init path is invalid");
        close(root_fd);
        umount("/run/dexec/root");
        return 1;
    }
    close(root_fd);
    close(init_fd);

    // Sanity checks
    int console_fd = open("/dev/console", O_RDWR);
    if (console_fd == -1) {
        perror("Failed to open /dev/console");
        umount("/run/dexec/root");
        return 2;
    }
    close(console_fd);

    if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) == -1) {
        perror("Failed to remount all filesystems private");
        umount("/run/dexec/root");
        return 2;
    }

    if (ptrace(PTRACE_ATTACH, 1) == -1) {
        perror("Failed to attach to PID 1");
        umount("/run/dexec/root");
        return 2;
    }

    wait_for_pid1();

    // init is stopped by SIGSTOP now.

    if (ptrace(PTRACE_SYSCALL, 1, NULL, 0) == -1) {
        // If we can't manage to PTRACE_SYSCALL PID 1, we aren't going to be able to continue it
        // either, so no smart error handling here.
        perror("Failed to keep PID 1 running until a syscall");
        umount("/run/dexec/root");
        return 2;
    }

    wait_for_pid1();

    struct user_regs_struct registers;
    struct iovec registers_iov = {
        .iov_base = &registers,
        .iov_len = sizeof(registers),
    };
    if (ptrace(PTRACE_GETREGSET, 1, NT_PRSTATUS, &registers_iov) == -1) {
        perror("Failed to get registers of PID 1");
        // Best-effort: keep init running.
        ptrace(PTRACE_CONT, 1, NULL, 0);
        umount("/run/dexec/root");
        return 2;
    }

    unsigned long base_address = registers.rsp - 256;

    char exe_path[24];
    sprintf(exe_path, "/proc/%d/exe", getpid());
    unsigned long pathname_address = base_address;
    base_address += sizeof(exe_path);
    for (size_t i = 0; i < sizeof(exe_path); i += sizeof(long)) {
        long word;
        memcpy(&word, exe_path + i, sizeof(long));
        if (ptrace(PTRACE_POKEDATA, 1, pathname_address + i, word) == -1) {
            perror("Failed to write \"/proc/<pid>/exe\" to PID 1 memory");
            // Best-effort: keep init running.
            ptrace(PTRACE_CONT, 1, NULL, 0);
            umount("/run/dexec/root");
            return 2;
        }
    }

    long word;
    memcpy(&word, "dexec", 6);
    unsigned long argv0_address = base_address;
    base_address += 8;
    if (ptrace(PTRACE_POKEDATA, 1, argv0_address, word) == -1) {
        perror("Failed to write \"dexec\" to PID 1 memory");
        // Best-effort: keep init running.
        ptrace(PTRACE_CONT, 1, NULL, 0);
        umount("/run/dexec/root");
        return 2;
    }

    unsigned long argv_address = base_address;
    base_address += sizeof(long);
    if (ptrace(PTRACE_POKEDATA, 1, argv_address, argv0_address) == -1) {
        perror("Failed to write argv to PID 1 memory");
        // Best-effort: keep init running.
        ptrace(PTRACE_CONT, 1, NULL, 0);
        umount("/run/dexec/root");
        return 2;
    }

    unsigned long envp_address = base_address;
    base_address += sizeof(long);
    // This NULL also acts as an argv terminator
    if (ptrace(PTRACE_POKEDATA, 1, envp_address, NULL) == -1) {
        perror("Failed to write envp to PID 1 memory");
        // Best-effort: keep init running.
        ptrace(PTRACE_CONT, 1, NULL, 0);
        umount("/run/dexec/root");
        return 2;
    }

    unsigned long old_orig_rax = registers.orig_rax;
    unsigned long old_rdi = registers.rdi;
    unsigned long old_rsi = registers.rsi;
    unsigned long old_rdx = registers.rdx;

    registers.orig_rax = SYS_execve;
    registers.rdi = pathname_address;
    registers.rsi = argv_address;
    registers.rdx = envp_address;

    if (ptrace(PTRACE_SETREGSET, 1, NT_PRSTATUS, &registers_iov) == -1) {
        perror("Failed to set registers of PID 1");
        // Best-effort: keep init running.
        ptrace(PTRACE_CONT, 1, NULL, 0);
        umount("/run/dexec/root");
        return 2;
    }

    // We have just asked PID 1 to perform a syscall. If execve fails, we need to execute the
    // syscall that we have just replaced.

    if (ptrace(PTRACE_SYSCALL, 1, NULL, 0) == -1) {
        perror("Failed to wait for PID 1 to perform a syscall");
        // If we can't manage to PTRACE_SYSCALL PID 1, we aren't going to be able to continue it
        // either, so no smart error handling here.
        umount("/run/dexec/root");
        return 2;
    }

    wait_for_pid1();

    struct user_regs_struct registers_new;
    struct iovec registers_new_iov = {
        .iov_base = &registers_new,
        .iov_len = sizeof(registers_new),
    };
    if (ptrace(PTRACE_GETREGSET, 1, NT_PRSTATUS, &registers_new_iov) == -1) {
        perror("Failed to get registers of PID 1");
        // Best-effort: keep init running.
        ptrace(PTRACE_CONT, 1, NULL, 0);
        umount("/run/dexec/root");
        return 2;
    }

    errno = -registers_new.rax;
    if (errno != 0) {
        perror("Failed to make PID 1 do an execve");
        umount("/run/dexec/root");

        registers.orig_rax = old_orig_rax;
        registers.rdi = old_rdi;
        registers.rsi = old_rsi;
        registers.rdx = old_rdx;

        if (ptrace(PTRACE_SETREGSET, 1, NT_PRSTATUS, &registers_iov) == -1) {
            perror("Failed to restore registers of PID 1");
            // Best-effort: keep init running.
            ptrace(PTRACE_CONT, 1, NULL, 0);
            return 2;
        }

        if (ptrace(PTRACE_CONT, 1, NULL, 0) == -1) {
            perror("Failed to continue PID 1");
            return 2;
        }

        return 2;
    }

    // Successful execve

    if (ptrace(PTRACE_CONT, 1, NULL, 0) == -1) {
        perror("Failed to continue PID 1");
        return 2;
    }

    return 2;
}
