#/bin/bash
set -x
rm screenlog.0
 sudo src/drakvuf -r /root/lin.json -d $1 -i $2 -e gnome-calc -m createproc -v -a cpuidmon
