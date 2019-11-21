#!/bin/bash

for host in 192.168.1.1{01..14}; do
    echo "Rebooting $host"
    sshpass -p root ssh $host reboot
done
