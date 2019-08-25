#!/bin/bash
set -x
if [[ `sudo lvscan` == *$OS_FUZZ_DOMAIN_VOLUME* ]]; then
		sudo lvremove $OS_FUZZ_DOMAIN_VOLUME -y;
fi
sudo lvcreate -s -L 10G -n $OS_FUZZ_DOMAIN_VOLUME $OS_FUZZ_DOMAIN_SAVED_VOLUME
sudo xl restore $OS_FUZZ_XEN_SAV_FILE
set +x