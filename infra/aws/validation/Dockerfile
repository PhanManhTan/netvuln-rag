FROM ubuntu:22.04@sha256:74b12b11ffa550fba1929ad4d8d16533c34f6612728469671afba1b03b66881c
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool libtool-bin pkg-config cmake bison flex texinfo \
    python3-dev python3-pip python3-venv libssl-dev zlib1g-dev libpcre2-dev libpcre3-dev \
    libreadline-dev libjson-c-dev libc-ares-dev libcap-dev libelf-dev libunwind-dev \
    libprotobuf-c-dev protobuf-c-compiler libapr1-dev libaprutil1-dev libuv1-dev \
    libxml2-dev libcmocka-dev liblzo2-dev liblz4-dev libpam0g-dev libnl-genl-3-dev \
    libsystemd-dev nettle-dev libdbus-1-dev liblua5.3-dev libedit-dev ca-certificates curl \
    iproute2 iputils-ping dnsutils openssl openssh-client openssh-server \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
RUN apt-get update && apt-get install -y --no-install-recommends libcap-ng-dev \
    && rm -rf /var/lib/apt/lists/*
