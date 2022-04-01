#!/bin/bash

ctypesgen=$1
libdrakvufh=$2
libdrakvufpy=$3

$ctypesgen $libdrakvufh -l repl `pkg-config --cflags-only-I --libs-only-L glib-2.0 libvmi` -o $libdrakvufpy 2> /dev/null
