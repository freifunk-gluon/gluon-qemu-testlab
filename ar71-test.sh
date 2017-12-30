#!/bin/sh

URL="http://130.75.178.7:8000/images/factory/"

if ! ip link show br0 &> /dev/null; then
	echo br0 does not exist! Creating now: 1>&2
	sudo ip link add name br0 type bridge
fi

filename=$(curl -s ${URL} | grep 'gluon.*x86-generic.img.gz' | sed 's_^.*\(gluon.*x86-generic.img.gz\).*$_\1_g')

tmpfile=/tmp/${filename%.gz}

echo Downloading ${filename} to ${tmpfile}.gz
curl -s ${URL}/${filename} -o ${tmpfile}.gz

echo Unpacking ${tmpfile}.gz to ${tmpfile}
gzip -d ${tmpfile}.gz

echo Starting QEmu
qemu-system-x86_64 ${tmpfile} \
    -nographic \
    -net nic,addr=0x10 -net user \
    -netdev bridge,id=hn0 -device e1000,addr=0x09,netdev=hn0,id=nic1
