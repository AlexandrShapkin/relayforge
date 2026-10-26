FROM archlinux/archlinux@sha256:676f4d5b2cacc259ab30b1e871a272bd4a2e023a901f725fb1b12c84dc355f10
RUN echo 'Server = https://archive.archlinux.org/repos/2026/09/25/$repo/os/$arch' > /etc/pacman.d/mirrorlist \
 && pacman -Syu --noconfirm --needed base-devel rust python git systemd bubblewrap sudo openssh iproute2 \
 && useradd --create-home builder \
 && echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/disposable-builder
ENV container=docker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
