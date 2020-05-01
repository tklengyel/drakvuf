#!/bin/bash

# run ./package/build.sh

IMAGE="ubuntu:18.04"

if [ ! -z "$1" ]
then
    IMAGE="$1"
    echo "Overriding base image for build to: $IMAGE"
    shift
fi

XEN_HASH=$(git ls-files -s xen | cut -f2 '-d ')

mkdir -p package/cache
mkdir -p package/log

if [ ! -f "package/cache/xen-intermediate-$IMAGE-$XEN_HASH.tar.gz" ]
then
    echo Building Xen intermediate $XEN_HASH...
    docker build --build-arg "IMAGE=$IMAGE" -f package/Dockerfile-xen -t xen-intermediate . 2>&1 >package/log/xen-build.log
    if [ $? -ne 0 ]; then echo Xen intermediate image build failed, build log tail below ; tail -n 200 package/log/xen-build.log ; exit 1 ; fi
    echo Removing old Xen intermediate image...
    rm -f package/cache/xen-intermediate-*.tar.gz
    echo Saving Xen intermediate...
    docker save xen-intermediate | gzip -c > "package/cache/xen-intermediate-$IMAGE-$XEN_HASH.tar.gz"
    if [ $? -ne 0 ]; then echo Failed to save Xen intermediate image ; rm package/cache/xen-intermediate-*.tar.gz ; exit 1 ; fi
else
    echo Loading cached Xen intermediate $IMAGE-$XEN_HASH...
    docker load < "package/cache/xen-intermediate-$IMAGE-$XEN_HASH.tar.gz"
    if [ $? -ne 0 ]; then echo Failed to load Xen intermediate image ; exit 1 ; fi
fi

echo Building final image...
docker build -f package/Dockerfile-final -t deb-build . && docker run -v $(pwd)/package/out:/out deb-build ./package/mkdeb $@
if [ $? -ne 0 ]; then echo Failed to build package ; exit 1 ; fi
