#!/bin/bash

for host in meshex{1..14}; do
    echo "Rebooting $host"
    sshpass -p root ssh $host reboot
done
