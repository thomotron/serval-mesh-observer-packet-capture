#!/bin/sh

# Toggle whether we should use persistence workaround
# This is true by default to encourage use of JFFS2 and so we can use this on Mesh Observers too
IS_FS_PERSISTENT=true

# Make sure the USB is detected otherwise none of what we do here will persist after rebooting
if [ ! -e /dev/sda ] && [ "$IS_FS_PERSISTENT" != true ]; then
    echo "/dev/sda is not present, aborting"
    exit 1
fi

# Set up the network template override
# The address will be overwritten by sed in the main script
echo -n "Overriding network template with IP address 'ADDRESS'... "
if [ "$IS_FS_PERSISTENT" == true ]; then
    sed -E "s/\toption ipaddr '192.168.1.1'$/\toption ipaddr 'ADDRESS'/" /etc/config/network.template > /etc/config/network.template.new
    sed -E "s/\toption ipaddr '192.168.1.1'$/\toption ipaddr 'ADDRESS'/" /etc/config/network > /etc/config/network.new
    mv /etc/config/network.template.new /etc/config/network.template
    mv /etc/config/network.new /etc/config/network
else
    sed -E "s/\toption ipaddr '192.168.1.1'$/\toption ipaddr 'ADDRESS'/" /etc/config/network.template > /dos/network.template
fi
echo "Done"

# Enable persistent SSH access
if [ -e /dos/noroot ]; then
    echo -n "Removing /dos/noroot... "
    rm /dos/noroot
    echo "Done"
fi
echo -n "Setting /dos/yesroot with password 'root'... "
echo root > /dos/yesroot
echo "Done"

# Reboot
echo "Rebooting..."
reboot