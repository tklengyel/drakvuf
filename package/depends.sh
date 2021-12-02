#!/bin/sh

set -e

apt-get update
apt-get install -y lsb-release patch

SYSTEM=$(lsb_release -is)
DISTRIBUTION=$(lsb_release -cs)

if [ "$SYSTEM" = "Debian" ]
then
    echo "deb-src http://deb.debian.org/debian ${DISTRIBUTION} main" >> /etc/apt/sources.list
    apt-get update
else
    sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
    apt-get update
fi

apt-get --quiet --yes install build-essential git wget curl cmake flex bison libjson-c-dev autoconf-archive clang python3-dev libsystemd-dev nasm bc libx11-dev ninja-build

wget -O /usr/local/go1.15.3.linux-amd64.tar.gz https://golang.org/dl/go1.15.3.linux-amd64.tar.gz
tar -C /usr/local -xzf /usr/local/go1.15.3.linux-amd64.tar.gz

HAS_PYTHON_IS_PYTHON=$(apt-cache search --names-only '^python-is-python2$')

if [ ! -z "$HAS_PYTHON_IS_PYTHON" ]
then
    apt-get --quiet --yes install python-is-python2
fi

apt-get --quiet --yes build-dep xen
apt-get autoremove -y
apt-get clean

rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
