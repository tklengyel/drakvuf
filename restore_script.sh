#!/bin/bash
set -x
if [[ `sudo lvscan` == *$OS_FUZZ_XEN_DRIVE* ]]; then
		sudo lvremove $OS_FUZZ_XEN_DRIVE -y;
fi
sudo lvcreate -s -L 10G -n $OS_FUZZ_XEN_DRIVE $OS_FUZZ_XEN_DRIVE_SAVED 
sudo xl restore $OS_FUZZ_XEN_SAV_FILE
remmina $OS_FUZZ_REMMINA_FILE &
set +x
