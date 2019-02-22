#!/bin/sh

set -e 

for i in 0 $(seq 10 23) 99; do
	nodename=noize-messstation-one-$i
	echo Generating keys for $nodename

	mkdir $nodename

	fastd --generate-key 2>&1 | awk ' \
/^Secret/ { print $2 > "'$nodename'/secret" } \
/^Public/ { print $2 > "'$nodename'/public" }'
done

