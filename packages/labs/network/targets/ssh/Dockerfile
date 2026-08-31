FROM alpine:3.22

RUN apk add --no-cache openssh-server \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh lab \
    && echo 'lab:aegis-lab' | chpasswd \
    && mkdir -p /run/sshd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "UsePAM=no", "-o", "PermitRootLogin=no", "-o", "PasswordAuthentication=yes"]
