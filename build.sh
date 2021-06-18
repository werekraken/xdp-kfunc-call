#!/bin/bash

set -e

kver="5.12.7"
BUILD_NUMBER=`date +%s`

tar cJf SOURCES/linux-"$kver".tar.xz linux-"$kver"/. --exclude-vcs

rpmbuild \
  --define "_topdir `pwd`" \
  -bs \
  --with kdump \
  --without kabichk \
  --without debug \
  --without doc \
  SPECS/kernel-*.spec

mock -r epel-7-x86_64 --init

mock -r epel-7-x86_64 --install \
   ../dwarves-ml/packages/1624041734/{libdwarves1,dwarves}-1.21-1.el7.x86_64.rpm

mkdir -p packages/"$BUILD_NUMBER"

mock \
    -r epel-7-x86_64 \
    --define 'dist .el7' \
    --no-clean `find SRPMS/ -type f | tail -1` \
  && mv -i /var/lib/mock/epel-7-x86_64/result/*.rpm packages/"$BUILD_NUMBER"/
