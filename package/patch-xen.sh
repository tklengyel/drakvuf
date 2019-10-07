#!/bin/bash

grep -q 'source/configure --enable-xen --target-list=i386-softmmu' 'tools/Makefile'

if [ $? -ne 0 ]
then
    echo 'Failed to patch Xen tools/Makefile'
    exit 1
fi

echo 'Patched qemu to include --disable-sdl option'
sed -i 's#source/configure --enable-xen --target-list=i386-softmmu#source/configure --enable-xen --target-list=i386-softmmu --disable-sdl#g' tools/Makefile
