# MeshObserver Packet Capture
These are the client and server programs used for capturing Serval Mesh packets with a Mesh Observer device.

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