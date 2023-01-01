#!/bin/bash
set -e
trap error EXIT

error() {
    apt-get --yes remove xen* || :
    apt-get --yes remove libxen* || :
    apt-get --yes remove drakvuf* || :

    echo "An error was encountered while trying to install DRAKVUF"
    exit 1
}

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
VERSION=${1:-"STABLE"}
PACKAGE_DIR=packages

if [ $1 == "--help" ] || [ $1 == "-h" ]; then
    echo "./scripts/install.sh {STABLE|LATEST|<folder>}"
    exit 0
fi

# Grab latest debs
if [ ! -d $VERSION ]; then
    get_packages $VERSION $PACKAGE_DIR
else
    PACKAGE_DIR=$VERSION
fi

# Install
apt-get update
apt-get --yes remove xen* libxen*
apt-get -f --yes install

for deb in $(ls $PACKAGE_DIR/*.deb); do
    for p in $(dpkg -I $deb | grep Depends | awk -F':' '{ print $2 }' | tr -d ',' | tr -d '|'); do
        apt-get --quiet --yes install $p || :
    done
done

dpkg -i $PACKAGE_DIR/*xen*.deb
dpkg -i $PACKAGE_DIR/*drakvuf-bundle*.deb

apt-get -f --yes install
apt-get --quiet --yes install python3-pip

cd /opt/volatility3
python3 setup.py build
python3 -m pip install .
pip3 install pefile construct

echo "DRAKVUF was successfully installed"
echo "You should reboot your system now and pick Xen in your GRUB menu"
trap - EXIT
exit 0
