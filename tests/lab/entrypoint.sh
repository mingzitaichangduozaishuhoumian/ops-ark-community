#!/bin/sh
set -eu

test -s /run/lab/client_key.pub
install -d -m 700 -o opsark-readonly -g opsark-readonly /home/opsark-readonly/.ssh
install -m 600 -o opsark-readonly -g opsark-readonly \
    /run/lab/client_key.pub /home/opsark-readonly/.ssh/authorized_keys
ssh-keygen -A >/dev/null
touch /var/log/nginx/error.log
chown www-data:adm /var/log/nginx/error.log
chmod 640 /var/log/nginx/error.log
python3 /opt/opsark-lab/control.py start
nginx -t
nginx
exec /usr/sbin/sshd -D -e
