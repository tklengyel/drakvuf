#!/bin/bash

# run ./package/build.sh

docker build -f package/Dockerfile -t xen-deb . && docker run -v $(pwd)/log:/log -v $(pwd)/out:/out xen-deb
