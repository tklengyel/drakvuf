#!/bin/bash

# Building OVMF is broken with gcc-11 (default on jammy)
# Unfortunately we can't just set CC in the environment because the edk2 build system is insane
# gcc-9 is not available on bookworm so there we build with no ovmf at all

OVMF=""
GCC_VERSION=$(gcc --version | head -n1 | awk '{ print $4 }' | awk -F'.' '{ print $1 }')
if [ ${GCC_VERSION} -gt 9 ] && [ -f /usr/bin/gcc-9 ]; then
    rm /usr/bin/gcc
    ln -s /usr/bin/gcc-9 /usr/bin/gcc
    OVMF="--enable-ovmf"
fi

./configure --prefix=/usr --enable-githttp \
    --disable-pvshim --disable-werror \
    --with-extra-qemuu-configure-args="--disable-werror --disable-sdl" \
    --enable-systemd $OVMF

echo CONFIG_EXPERT=y > xen/.config
echo CONFIG_MEM_SHARING=y >> xen/.config
make -C xen olddefconfig

exit 0
