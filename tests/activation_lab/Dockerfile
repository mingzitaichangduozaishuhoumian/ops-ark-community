ARG BASE_IMAGE=debian:12
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install --no-install-recommends -y systemd systemd-sysv dbus \
       openssh-server openssh-client sudo python3 python3-apt ca-certificates zlib1g \
    && systemctl enable ssh.service \
    && systemctl mask apt-daily.service apt-daily-upgrade.service \
       apt-daily.timer apt-daily-upgrade.timer \
    && rm -f /etc/machine-id /var/lib/dbus/machine-id /etc/ssh/ssh_host_* \
    && useradd --create-home --shell /bin/sh opsark-repair \
    && usermod --password '*' opsark-repair
COPY root/ /usr/local/libexec/opsark-patch/
COPY fixture.py /opt/opsark-activation-lab/fixture.py
COPY acceptance.py /opt/opsark-activation-lab/acceptance.py
COPY tcp_relay.py /usr/local/libexec/opsark-activation-lab-relay.py
COPY web_probe.py /opt/opsark-activation-lab/web_probe.py
COPY entrypoint.sh /usr/local/sbin/opsark-activation-lab-entry
RUN chmod 755 /usr/local/sbin/opsark-activation-lab-entry \
    && chmod -R go-w /usr/local/libexec/opsark-patch /opt/opsark-activation-lab
LABEL io.opsark.activation-lab="v1"
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/sbin/opsark-activation-lab-entry"]
