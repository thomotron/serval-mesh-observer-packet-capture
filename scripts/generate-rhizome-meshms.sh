#!/bin/sh

# Generates a Rhizome database with dummy MeshMS messages between random SIDs
# and packs it into a TAR archive

# Stop servald
sudo servald stop

# Delete the current Rhizome database
sudo rm -rf /usr/local/var/cache/serval/rhizome/

# Start servald
sudo servald start

# Generate 64 messages with random recipients
for i in {1..64}; do
    sudo servald meshms send message $(sudo servald id self | tail -n 1) $(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 64 | head -n 1) "This is a sample message" 
done

# Stop servald to make sure the db is written to disk
sudo servald stop

# Pack the database into a tarball
sudo tar -cf rhizome.tar /usr/local/var/cache/serval/rhizome/

# Set the tarball owner
sudo chown $(whoami) rhizome.tar