#!/bin/sh

# Kills LBARD and servald, then wipes the Rhizome database on all Mesh Extenders (1-14)

# Stop services and destroy Rhizome content
for host in meshex{1..14}; do
    echo "Stopping servald and LBARD on $host"
    sshpass -p root ssh $host "ps | grep -E \"(servald)|(lbard)\" | cut -d ' ' -f 1 | xargs kill"
    sshpass -p root ssh $host "ps | grep -E \"(servald)|(lbard)\" | cut -d ' ' -f 2 | xargs kill"
    echo "Nuking Rhizome database"
    sshpass -p root ssh $host "rm -rf /serval-var/rhizome/*"
    echo ""
done