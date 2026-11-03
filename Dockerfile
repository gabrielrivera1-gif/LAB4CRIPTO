FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y openssh-server && \
    mkdir -p /var/run/sshd

RUN ssh-keygen -A && \
    echo "y" | ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

COPY sshd_config /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash labuser && \
    echo labuser:labpass123 | chpasswd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]