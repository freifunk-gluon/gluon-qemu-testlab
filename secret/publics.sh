#!/bin/sh

for d in noise*; do
	sh ~/bin/node.sh $d $(cat $d/public | tr -d "\n")
done
