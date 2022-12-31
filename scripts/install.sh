#!/bin/bash

get_debian() {
    VERSION=$1

    case $VERSION in
    buster)
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_10-slim_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_10-slim_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    bullseye)
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_11-slim_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_11-slim_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    *)
        echo "Unsupported Debian version: $VERSION"
        exit 1
        ;;
    esac
}

get_ubuntu() {
    VERSION=$1

    case $VERSION in
    focal)
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_focal_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_focal_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    jammy)
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_jammy_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb
        wget -q https://github.com/tklengyel/drakvuf/releases/download/1.0/ubuntu_jammy_xen-hypervisor-4.17.0-generic-amd64.deb
        ;;
    *)
        echo "Unsupported Ubuntu version: $VERSION"
        exit 1
        ;;
    esac
}

get_packages() {
    TARGET=$1
    PACKAGE_DIR=$2
    DISTRO=$(cat /etc/os-release | grep ID)
    VERSION=$(cat /etc/os-release | grep VERSION_CODENAME)

    DIR=$PWD
    mkdir -p $PACKAGE_DIR
    cd packages

    if [ $TARGET == "LATEST" ]; then
        debs=$(curl -s https://api.github.com/repos/tklengyel/drakvuf-builds/releases/latest | grep "browser_download_url.*deb" | awk '{ print $2 }' | tr -d '"')
        for deb in $debs; do
            if [ $(echo $deb | grep $DISTRO | grep $VERSION | wc -l) -ne 0 ]; then
                wget -q $deb
            fi
        done

        if [ $(ls -la *.deb 2>/dev/null | wc -l ) -eq 0 ]; then
            echo "$DISTRO $VERSION is not supported by this script"
            exit 1
        fi
    fi

    if [ $TARGET == "STABLE" ]; then
        case $DISTRO in
        ubuntu)
            get_ubuntu $VERSION
            ;;
        ubuntu)
            get_debian $VERSION
            ;;
        *)
            echo "Unsupported distribution: $DISTRO"
            exit 1
        esac
    fi

    cd $DIR
}

#################
VERSION=${1:"STABLE"}
PACKAGE_DIR=packages

# Grab latest debs
if [ ! -d $VERSION ]; then
    get_packages $OPT $PACKAGE_DIR
else
    PACKAGE_DIR=$OPT
fi

# Install
sudo apt-get update
for p in $(dpkg -I debs/*.deb | grep Depends | awk -F':' '{ print $2 }' | tr -d ',' | tr -d '|'); do
    sudo apt-get --quiet --yes install $p || :
done

sudo apt-get --quiet --yes install python3-pip
sudo pip3 install pefile construct

sudo dpkg -i $PACKAGE_DIR/*xen*.deb
sudo dpkg -i $PACKAGE_DIR/*drakvuf-bundle*.deb

echo "DRAKVUF was successfully installed"
echo "You should reboot your system now and pick Xen in your GRUB menu"
exit 0
