# Host tools the OpenWrt SDK needs (gawk, python3, ...), for hosts that lack them.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gawk python3 python3-setuptools rsync file wget unzip zstd \
    git ca-certificates libncurses-dev swig xz-utils bzip2 gettext \
 && rm -rf /var/lib/apt/lists/*
