# docker-boot

https://github.com/purplesyringa/docker-boot/assets/16370781/0f2a24e1-7c5f-47a6-9730-479f853af25a

> Like `execve`, but for userspace.

docker-boot replaces your current running system with an in-memory root filesystem constructed from a Docker image.

Example with GUI:

**Dockerfile**

```dockerfile
FROM ubuntu
RUN apt update
RUN apt-get install -y software-properties-common && add-apt-repository ppa:mozillateam/ppa
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y sudo htop systemd sddm kde-plasma-desktop firefox-esr
RUN useradd --create-home --shell /bin/bash --groups sudo --password "$(perl -e "print crypt('cutie', 'sa');")" --user-group purplesyringa
RUN echo "InputMethod=" >/etc/sddm.conf
```

```shell
$ docker build . -t workstation
<...>

$ sudo docker-boot workstation /bin/systemd
<The host system is shut down, Ubuntu with lightdm/KDE starts>
```

Example without GUI:

**Dockerfile**

```shell
$ sudo docker-boot ubuntu /bin/bash -c "mount -t proc proc proc; mount -t sysfs sys sys; exec bash -i"
<The host system is shut down, Ubuntu starts in single-user mode>
```

(Or make `systemd` mount the filesystems for you if you're feeling adventurous.)


## Building

Just do `make`.

You're going to need `docker`, `swapoff`, `tar`, and `dd` installed.


## Why?

1. I'm a Nix contrarian, so naturally I wanted *something* to be to Docker like NixOS is to Nix. docker-boot fills this niche.
2. Injecting into `init` is based, I've always wanted to do that; this project is my excuse.
3. If you need to move partitions on your boot disk, you probably want to run a system off RAM. This is typically accomplished by creating a tmpfs, `debootstrap`ing an OS into it, `pivot_root`ing and killing services that use the real disk. That's a bit ridiculous of a manual; this project attempts to reduce the gap.


## How it works

First, `docker-boot` creates a directory at `/run/dboot/root`, mounts `tmpfs` on top of it, and exports the Docker image there. Other useful metadata, such as the program to launch as `init` from the image, is stored in other files in `/run/dboot`.

`docker-boot` then attaches to PID 1 via ptrace, just like a debugger would. It waits for init (typically `systemd`) to start a syscall and interrupts the process just before the syscall is executed. Processor registers are then updated in the process to execute another syscall in place of the one intended by real `init`.

The substituted syscall is `execve("/proc/<pid>/exe", {"dboot", NULL}, NULL)`, where the `<pid>` is the PID of the `docker-boot` process. The path `/proc/<pid>/exe` refers to the executable of the corresponding process, so this is an easy way to replace PID 1 with a copy of `docker-boot` regardless of (the length of) the path to `docker-boot`. The strings `/proc/<pid>/exe` and `dboot` are stored below the red zone, i.e. 128 bytes below `rsp`. That is a region of stack that is almost always safe to overwrite.

`docker-boot` then asks the kernel to execute exactly one instruction in the `init` process and checks whether the `errno` is `0`. If not, the `execve` is assumed to have failed, and the processor registers are restored to the state before `execve`, so that the system can keep functioning.

On success, `docker-boot` continues execution in PID 1. It switches graphics to TTY 3, kills all processes, and switches the root filesystem to `/run/dboot/root` via `pivot_root`, which is a more robust and modern alternative to `chroot` that allows `docker-boot` to safely unmount the host filesystem after changing roots. Finally, the process uses `execve` to execute the process requested by the user, typically systemd or a shell.
