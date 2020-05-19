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

apt-get --quiet --yes install build-essential git wget curl cmake flex bison libjson-c-dev autoconf-archive clang python-dev gcc-7 g++-7

HAS_PYTHON_IS_PYTHON=$(apt-cache search --names-only '^python-is-python2$')

if [ ! -z "$HAS_PYTHON_IS_PYTHON" ]
then
    apt-get --quiet --yes install python-is-python2
fi

apt-get --quiet --yes build-dep xen
apt-get autoremove -y
apt-get clean

if [ "$SYSTEM" = "Debian" ]
then
    patch /usr/include/linux/swab.h /tmp/swab.patch
fi

rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*

rm /usr/bin/gcc /usr/bin/g++
ln -s /usr/bin/gcc-7 /usr/bin/gcc
ln -s /usr/bin/g++-7 /usr/bin/g++

