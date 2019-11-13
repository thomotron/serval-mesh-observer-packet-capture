#!/bin/bash

# Stop services and destroy Rhizome content
for host in meshex{1..14}; do
    echo "Clearing logs on $host"
    sshpass -p root ssh $host "rm -rf /serval-var/servald-dump* /serval-var/lbard.log /serval-var/serval.log /serval-var/log/"
    echo ""
done
