# Mesh Observer Packet Capture
These are the client and server programs used for capturing Serval Mesh packets with a Mesh Observer device.

There are also some scripts used internally for conducting tests of the 2019 Mesh Extender test network at Tonsley. These are all kept within the [`scripts/`](scripts/) directory.

# Building
## Prerequisites
1. libpcap

For Debian/Ubuntu machines, use apt: `sudo apt install libpcap-dev`  
For Fedora machines, use dnf: `sudo dnf install libpcap-devel`

## Build process
1. Clone the repo: `git clone https://github.com/jLanc/MeshObserver-Packet-Capture.git`
2. Compile with make: `make`

The client and server programs will be available at `client/capture` and `server/svrCap` respectively.

# Usage
## Client
To start capturing packets and send them to a capture server, run `capture <address>`. When you are done capturing, press `Ctrl+C` to stop.  
By default the capture program will capture UHF and Wi-Fi packets and send them to the given address at port 3940.
When capturing Wi-Fi packets, make sure to use a [filter](#user-content-filters) to strip away irrelevant packets.

The following is the help text printed by the client program:
```
Usage: capture [OPTION...] ADDRESS

  -d, --wifidev=wifidev      Wi-Fi capture device
  -f, --filter=filter        Pcap filter for Wi-Fi packets
      --nouhf[=nouhf]        Disables UHF LBARD capture
      --nowifi[=nowifi]      Disables Wi-Fi packet capture
  -p, --port=port            Server port
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

## Server
To start capturing and analysing packets sent by the client program, run `svrCap`. When you are done capturing, press `Ctrl+C` to start generating a timing diagram.  
By default the server program will listen on port 3940 across all interfaces using the PlantUML jarfile packaged in the repository.

The following is the help text printed by the server program:
```
Usage: svrCap [OPTION...] 

  -a, --address=address      Address to bind to
  -j, --jarpath=path         PlantUML jarfile path
  -n, --packets=packets      Number of packets to capture
  -p, --port=port            Port to listen on
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

## Additional usage notes
### Filters
The Wi-Fi packet capture mode uses [libpcap](https://www.tcpdump.org/) to capture packets directly from the Wi-Fi radio.
By default this will capture *all* traffic and forward it to the capture server.
It is recommended that you use [filters](https://www.tcpdump.org/manpages/pcap-filter.7.html) to discard any irrelevant traffic to avoid bogging down the capture server and to generate a cleaner diagram.
Filters can be passed to the client program through the `-f` or `--filter` option.

#### Examples
Only capture frames from the MAC address `e2:95:6e:4c:a8:c6`:
```sh
capture -f "ether host e2:95:6e:4c:a8:c6" 192.168.1.41
```
As above, but only [data frames](https://en.wikipedia.org/wiki/IEEE_802.11#Data_frames) or [control frames](https://en.wikipedia.org/wiki/IEEE_802.11#Control_frames):
```sh
capture -f "ether host e2:95:6e:4c:a8:c6 && (wlan type data || wlan type ctl)" 192.168.1.41
```
Only capture frames containing UDP packets with the destination port 4110 ([Rhizome](https://github.com/servalproject/serval-dna/blob/development/doc/REST-API-Rhizome.md) packets) that are standard, unencrypted [data frames](https://en.wikipedia.org/wiki/IEEE_802.11#Data_frames):
```sh
capture -f "udp dst port 4110 && wlan type data subtype data" 192.168.1.41
```

### Generating large diagrams
PlantUML will generate diagrams up to 4096px\*4096px by default. Diagrams that are larger than this will be truncated to fit within the space. To generate larger diagrams, you will have to run PlantUML yourself and provide it with the `PLANTUML_LIMIT_SIZE` parameter.

To regenerate the diagram at a larger size, run:
```sh
java -DPLANTUML_LIMIT_SIZE=<size> -jar plantuml.jar <diagram_txt>
```
where `<size>` is the maximum size in pixels for both axes, and `<diagram_txt>` is the path to the diagram text file that PlantUML should read from (usually named something like `timingDiagram_... .txt`). It may take a while for PlantUML to regenerate the diagram, especially if it is very large. A PNG file of the diagram will appear when the process is complete.
