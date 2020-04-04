#!/bin/sh

script=$(basename "$0")

if ! echo "$script" | grep node > /dev/null; then
	echo Do not call this script directly. Use the symlinks in \$PROJECT_DIR/ssh/.
	exit 1
fi

node_id=$(echo "$script" | sed 's_^node__' | sed 's_.sh__')

ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $(dirname "$0")/id_rsa.key root@localhost -p $(python -c "print(22100+$node_id)")
