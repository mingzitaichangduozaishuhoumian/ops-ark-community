#!/bin/sh
set -eu
test "$OPSARK_DISPOSABLE_ACTIVATION_LAB" = 1
mkdir -p /run/sshd
if grep -Eq ' /sys/fs/cgroup cgroup2 ro([, ]|$)' /proc/mounts; then
    mount -o remount,rw /sys/fs/cgroup
fi
systemd-machine-id-setup
ssh-keygen -A
exec /sbin/init
