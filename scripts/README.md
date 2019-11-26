# Mesh Extender and Observer scripts
This directory contains a variety of scripts used to test the 2019 Mesh Extender Test Network at Tonsley. There are also several alternate runscripts and configuration files within the [`alternate-runscripts-and-configs/`](alternate-runscripts-and-configs/) directory, and Rhizome database samples in the [`rhizome-databases/`](rhizome-databases/) directory.

The table below has some descriptions about each script, what they do, and how they might be useful:

| Script                       | Function                                                                                                    | Uses                                                                          |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `clear-logs.sh`              | Removes all logs from `/serval-var/` on each Mesh Extender                                                  | Cleaning the network                                                          |
| `copy-runscripts.sh`         | Copies `runservald` and `runlbard` scripts onto each Mesh Extender                                          | Manually overriding servald and LBARD runscripts                              |
| `generate-rhizome-meshms.sh` | Generates a Rhizome database with dummy MeshMS messages between random SIDs and packs it into a TAR archive | Generating content for Rhizome propagation tests                              |
| `monitor-time-changes.sh`    | Generates a CSV file with the current date of each Mesh Extender                                            | Debugging time excursions and NTP issues                                      |
| `nuke-rhizome.sh`            | Stops all Serval services and deletes the Rhizome database on each Mesh Extender                            | Cleaning the network                                                          |
| `reboot-all.sh`              | Reboots each Mesh Extender                                                                                  | Applying configuration changes en-masse, restarting Serval services naturally |
| `setup-meshex.sh`            | Configures Ethernet interface address and enables SSH access on a newly-flashed Mesh Extender               | Quickly configuring Mesh Extenders for deployment in the test network         |
| `start-lbard.sh`             | Starts LBARD as a daemon on each Mesh Extender                                                              | Starting LBARD on each device                                                 |
