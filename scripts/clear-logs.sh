#!/bin/bash

# Stop services and destroy Rhizome content
for host in 192.168.1.1{01..14}; do
    echo "Clearing logs on $host"
    sshpass -p root ssh $host "rm -rf /serval-var/servald-dump* /serval-var/lbard.log /serval-var/serval.log /serval-var/log/"
    echo ""
done
