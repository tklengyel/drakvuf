#!/bin/bash

# Building OVMF is broken with gcc-11 (default on jammy)
# Unfortunately we can't just set CC in the environment because the edk2 build system is insane

GCC_VERSION=$(gcc --version | head -n1 | awk '{ print $4 }' | awk -F'.' '{ print $1 }')
if [ ${GCC_VERSION} -gt 9 ]; then
    rm /usr/bin/gcc
    ln -s /usr/bin/gcc-9 /usr/bin/gcc
fi

./configure --prefix=/usr --enable-githttp --disable-pvshim --enable-systemd --enable-ovmf

exit 0
