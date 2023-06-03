#!/bin/sh
version=$(head -n2 meson.build | tail -1 | awk '{ print $3 }' | awk -F"'" '{ print $2 }')

if [ $# = 1 ]
then
    gda=$(git describe --always)
    version="$version-$gda"
fi

echo $version
