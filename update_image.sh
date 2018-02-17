#!/bin/sh

URL="https://build.ffh.zone/job/gluon-nightly/ws/download/images/factory/"

filename=$(curl -s ${URL} | grep 'gluon.*x86-generic.img.gz' | sed 's_^.*\(gluon.*x86-generic.img.gz\).*$_\1_g')

tmpfile=/tmp/${filename%.gz}

echo Downloading ${filename} to ${tmpfile}.gz
curl -s ${URL}/${filename} -o ${tmpfile}.gz

echo Unpacking ${tmpfile}.gz to ${tmpfile}
gzip -d ${tmpfile}.gz

echo Copy to here ./image.img
cp ${tmpfile} ./image.img
