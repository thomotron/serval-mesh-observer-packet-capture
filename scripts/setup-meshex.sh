#!/bin/sh

# Configures a freshly-flashed Mesh Extender with the given IP address
# and enables persistent SSH access with the password 'root'.
# 
# This script depends on another script named '.setup-meshex.script.sh'
# which is piped into the shell on the target device. This script
# merely opens a shell instance and pipes it.

# Make sure we get an IP address
if [ ! "$1" ]; then
    echo "Usage: $0 <ip address>"
    exit 1
fi

# Make sure the script is here
if [ ! -e .setup-meshex-script.sh ]; then
    echo "Couldn't find '.setup-meshex.script.sh', are you in the correct directory?"
    exit 1
fi

# Run the commands via SSH
sed -E "s/ADDRESS/$1/" .setup-meshex-script.sh | sshpass -p root ssh root@192.168.1.1 "ash -s"
