#!/bin/sh

# Starts LBARD as a daemon on all Mesh Extenders in the test network (1-14)

for host in 192.168.1.10{1..14}; do
    echo "Starting LBARD on $host"
    SID=$(sshpass -p root ssh $host "servald start && sleep 5 ; servald id self" | tail -n 1)
    sshpass -p root ssh $host "start-stop-daemon -S -b -x lbard localhost:4110 lbard:lbard $SID $SID /dev/ttyATH0"
done