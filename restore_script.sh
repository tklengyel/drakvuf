#!/bin/bash
set -x
sudo lvremove /dev/xen/fuzz -y;
sudo lvcreate -s -L 10G -n /dev/xen/fuzz /dev/xen/fuzz-saved
sudo xl restore /home/ajinkya/College/gsoc19/xen-saved-vms/win10-fresh.sav
remmina /home/ajinkya/.local/share/remmina/1561582469535.remmina &
set +x
