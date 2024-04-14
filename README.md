# docker-boot

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
$ sudo docker-boot ubuntu /bin/bash
<The host system is shut down, Ubuntu starts in single-user mode>
```


## Building

Just do `make`.

You're going to need `docker`, `swapoff`, `tar`, and `pv` installed.


## Why?

1. So that those dirty NixOS evangelists can suck dick.
2. Injecting into `init` is based, I've always wanted to do that; this project is my excuse.
3. If you need to move partitions on your boot disk, you probably want to run a system off RAM. This is typically accomplished by creating a tmpfs, `debootstrap`ing an OS into it, `pivot_root`ing and killing services that use the real disk. That's a bit ridiculous of a manual; this project attempts to reduce the gap.
