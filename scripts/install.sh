#!/bin/bash

get_debian() {
    VERSION=$1

    case $VERSION in
    buster)
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_10-slim_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_10-slim_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    bullseye)
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_11-slim_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_11-slim_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    *)
        echo "Unsupported Debian version"
        exit 1
        ;;
    esac
}

get_ubuntu() {
    VERSION=$1

    case $VERSION in
    focal)
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_focal_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_focal_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    jammy)
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_jammy_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_jammy_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    *)
        echo "Unsupported Ubuntu version"
        exit 1
        ;;
    esac
}

get_packages() {
    DISTRO=$(cat /etc/os-release | grep ID)
    VERSION=$(cat /etc/os-release | grep VERSION_CODENAME)

    DIR=$PWD
    mkdir -p debs
    cd debs

    case $DISTRO in
    ubuntu)
        get_ubuntu $VERSION
        ;;

    debian)
        get_debian $VERSION
        ;;

    *)
        cd $DIR
        echo "This script only supports Debian or Ubuntu"
        exit 1
        ;;
    esac

    cd $DIR
}

#################
OPT=${1:"-"}

# Grab latest debs
if [ ! -d $OPT ]; then
    get_packages
fi

# Install
sudo apt-get update
for p in $(dpkg -I debs/*.deb | grep Depends | awk -F':' '{ print $2 }' | tr -d ',' | tr -d '|'); do
    sudo apt-get --quiet --yes install $p || :
done

sudo apt-get install python3 python3-pip
sudo pip3 install pefile construct

sudo dpkg -i debs/*xen*.deb
sudo dpkg -i debs/*drakvuf-bundle*.deb

echo "DRAKVUF was successfully installed"
echo "You should reboot your system now and pick Xen in your GRUB menu"
