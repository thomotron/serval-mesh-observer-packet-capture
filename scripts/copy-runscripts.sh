#!/bin/bash

for host in 192.168.1.1{01..14}; do
    # Start an nc listener for runlbard, then for runservald, and do it in the background (it will die automatically)
    nc -l 12344 < runlbard &
    nc -l 12345 < runservald &

    echo "Copying runlbard to $host"
    sshpass -p root ssh -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" root@$host "nc 192.168.1.41 12344 > /etc/serval/runlbard" &

    echo "Copying runservald to $host"
    sshpass -p root ssh -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" root@$host "nc 192.168.1.41 12345 > /etc/serval/runservald" &

    # Wait until the SSH jobs are done
    wait %3 %4

    # Kill the nc jobs just to be sure
    kill %1 %2
    wait

    echo ""
done
