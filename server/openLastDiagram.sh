#!/bin/sh

# I'm sick of trying to sift through all of these timestamps, so
# here's a oneliner that will open the latest one with eog
find -regex .\*\\.png | sort | tail -n 1 | sed -e "s/\ /\\\ /g" | xargs xdg-open &