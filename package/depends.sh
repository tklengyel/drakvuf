#!/bin/sh

set -e

apt-get update
apt-get install -y lsb-release patch

SYSTEM=$(lsb_release -is)
DISTRIBUTION=$(lsb_release -cs)

if [ "$SYSTEM" = "Debian" ]
then
    echo "deb-src http://deb.debian.org/debian ${DISTRIBUTION} main" >> /etc/apt/sources.list
else
    if [ "$DISTRIBUTION" = "noble" ]; then
        sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
    else
        sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
    fi
fi

apt-get update
apt-get --quiet --yes install build-essential git wget curl cmake flex bison \
    libjson-c-dev autoconf-archive clang python3-dev libsystemd-dev nasm bc \
    libx11-dev ninja-build python3-pip meson llvm lld zlib1g-dev python3-tomli

if [ $(apt-cache show gcc-9 2>/dev/null | wc -l) -gt 0 ]; then
    apt-get --quiet --yes install gcc-9
fi

wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz -O /usr/local/go1.21.6.linux-amd64.tar.gz
tar -C /usr/local -xzf /usr/local/go1.21.6.linux-amd64.tar.gz

HAS_PYTHON_IS_PYTHON=$(apt-cache search --names-only '^python-is-python2$')

if [ ! -z "$HAS_PYTHON_IS_PYTHON" ]
then
    apt-get --quiet --yes install python-is-python2
fi

# libgnutls28 is required for the password-protected VNC to work in Xen 4.16+.
# See: https://bugs.gentoo.org/832494
apt-get install -y libgnutls28-dev
apt-get --quiet --yes build-dep xen
apt-get autoremove -y
apt-get clean

rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
