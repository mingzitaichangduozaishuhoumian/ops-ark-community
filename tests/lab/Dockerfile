ARG OPSARK_LAB_BASE_IMAGE=ubuntu:24.04
FROM ${OPSARK_LAB_BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server nginx python3 curl iproute2 coreutils passwd ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --force adm \
    && useradd --create-home --user-group --shell /bin/sh --groups adm opsark-readonly \
    && passwd --delete opsark-readonly \
    && rm -f /etc/ssh/ssh_host_* \
    && rm -f /etc/nginx/sites-enabled/default \
    && mkdir -p /run/sshd /opt/opsark-lab

COPY sshd_config /etc/ssh/sshd_config
COPY shop.conf /etc/nginx/conf.d/shop.conf
COPY upstream.py control.py /opt/opsark-lab/
COPY entrypoint.sh /usr/local/bin/opsark-lab-entrypoint
RUN chmod 755 /usr/local/bin/opsark-lab-entrypoint \
    && chmod 644 /etc/nginx/conf.d/shop.conf

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/opsark-lab-entrypoint"]
