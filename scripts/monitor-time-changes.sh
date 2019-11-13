#!/bin/sh

# Generates a CSV file with the current date of each Mesh Extender to
# help with detecting system time excursions.
# 
# This script does not stop itself, it needs to be killed with Ctrl+C

FILENAME="time-changes.csv"

# Create a CSV with a header if we don't have one already
if [ ! -e "$FILENAME" ]; then
    echo "Us,ME1,ME2,ME3,ME4,ME5,ME6,ME7,ME8,ME9,ME10,ME11,ME12,ME13,ME14" > "$FILENAME"
fi

# Skip a line in case we terminated early
echo "" >> "$FILENAME"

# Begin collecting date output from each mesh extender
echo -e "Starting date collection\nPress Ctrl+C to stop"
while [ true ]; do
    # Get our current time
    echo -n "$(date -u +%Y-%m-%d\ %H:%M:%S)," >> "$FILENAME"

    # Get the time from each meshex
    for host in meshex{1..14}; do
        OUTPUT="$(sshpass -p root ssh $host date -u +\"%Y-%m-%d %H:%M:%S\" 2> /dev/null),"
        if [ ! $(wc -l <<< "$OUTPUT") -eq 1 ]; then
            OUTPUT=","
        fi
        echo -n "$OUTPUT" >> "$FILENAME"
    done
    echo "" >> "$FILENAME"

    # Read out the line we just wrote to file
    tail -n 1 "$FILENAME"
done