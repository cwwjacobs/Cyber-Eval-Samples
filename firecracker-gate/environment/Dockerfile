# Agent image: real Firecracker, a guest kernel and a read-only guest root filesystem.
# The VM needs /dev/kvm, passed through by docker-compose.yaml, and nothing else from the host.
FROM debian@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS guest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 busybox-static \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man /var/cache/apt
COPY guest/init /init
COPY guest/labguest.py /opt/lab/labguest.py
RUN chmod 0755 /init && mkdir -p /job

FROM debian@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 PAGER=cat GIT_PAGER=cat
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl e2fsprogs git jq procps python3 lsof strace file tree tmux \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /bin/bash agent \
 && git config --system user.email agent@task.local && git config --system user.name Agent

RUN curl -fsSL -o /tmp/fc.tgz https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz \
 && echo "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558  /tmp/fc.tgz" | sha256sum -c - \
 && tar -xzf /tmp/fc.tgz -C /tmp \
 && install -m 0755 /tmp/release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64 /usr/local/bin/firecracker \
 && rm -rf /tmp/fc.tgz /tmp/release-v1.17.0-x86_64
RUN mkdir -p /opt/lab && curl -fsSL -o /opt/lab/vmlinux https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261016-5732b8331e1e-0/x86_64/vmlinux-6.1.188 \
 && echo "c16288854c798ded46c45b3ccab4bc85b8041552ab50f899fecbad550a641e92  /opt/lab/vmlinux" | sha256sum -c -

COPY --from=guest / /opt/lab/tree/
RUN truncate -s 300M /opt/lab/rootfs.ext4 && mke2fs -q -t ext4 -d /opt/lab/tree /opt/lab/rootfs.ext4 && rm -rf /opt/lab/tree
COPY guest/labguest.py /opt/lab/labguest.py
COPY setup/gen_lock.py /opt/setup/gen_lock.py
RUN python3 /opt/setup/gen_lock.py && rm -rf /opt/setup && chmod -R a+rX /opt/lab

COPY workspace/ /app/
RUN chmod +x /app/tools/*.py && chown -R agent:agent /app
WORKDIR /app

RUN mkdir -p /logs/agent /sandbox-timer
COPY sandbox_timer.sh /usr/local/bin/sandbox-timer
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/sandbox-timer && chmod 0700 /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
