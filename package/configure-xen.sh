#!/bin/bash

# Building OVMF may be broken on some distributions
ovmf="--enable-ovmf"

ubuntu=$(cat /etc/os-release | grep UBUNTU_CODENAME | awk -F'=' '{ print $2 }')
if [ $ubuntu == "jammy" ]; then
    ovmf=""
fi

./configure --prefix=/usr --enable-githttp --disable-pvshim --enable-systemd ${ovmf}

exit 0
