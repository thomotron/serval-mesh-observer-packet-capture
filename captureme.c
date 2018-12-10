/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   captureme.c
 * Author: honours
 *
 * Created on November 13, 2018, 5:53 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libnet.h>
#include <time.h>
#define SVR_IP "192.168.2.2"
/*
 * 
 */
//copied from the following file
//packetforward.c https://code.google.com/archive/p/packetforward/source/default/source
//builds udp packet and sends down the wire.
void send_packet(int sport2, int dport2, int id, int ttl, struct packet)
{

    char errbuf[LIBNET_ERRBUF_SIZE]; /* error buffer */
    struct libnet_link_int *network; /* pointer to link interface struct */
    int packet_size;                 /* size of our packet */
    int ip_size;                     /* size of our ip */
    int udp_size;                    /* size of our udp */
    int c;
    u_char *packet = packet.pkt_data; /* pointer to our packet buffer */
    //somehow build packet payload string from struct
    int payload_size

        //  Step 1: Network Initialization (interchangable with step 2).

        if ((network = libnet_open_link_interface(dev2, errbuf)) == NULL)
    {
        libnet_error(LIBNET_ERR_FATAL, "libnet_open_link_interface: %s\n", errbuf);
    }

    /*
     *  We're going to build a UDP packet with a payload using the
     *  link-layer API, so this time we need memory for a ethernet header
     *  as well as memory for the ICMP and IP headers and our payload.
     */
    //because we are using the UDP protocol (we don't needs acks because of time constraints and serial programming constraints)
    //this was a design decision ***************************************************************************
    //must talk about this in thesis************************************************************************
    packet_size = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_UDP_H + payload_size;
    ip_size = LIBNET_IP_H + LIBNET_UDP_H + payload_size;
    udp_size = LIBNET_UDP_H + payload_size;

    //  Step 2: Memory Initialization (interchangable with step 1).

    if (libnet_init_packet(packet_size, &packet) == -1)
    {
        libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
    }

    //  Step 3: Packet construction (ethernet header).
    libnet_build_ethernet(
        enet_dst,
        enet_src,
        ETHERTYPE_IP,
        NULL,
        0,
        packet);
    printf("\n--- Injected packet on %s ---\n", dev2);

    //  Step 3: Packet construction (IP header).

    libnet_build_ip(
        LIBNET_UDP_H + payload_size,
        0,                 /* IP tos */
        id,                /* IP ID */
        0,                 /* Frag */
        ttl,               /* TTL */
        IPPROTO_UDP,       /* Transport protocol */
        inet_addr(saddr2), /* Source IP */
        inet_addr(daddr2), /* Destination IP */
        payload,           /* Pointer to payload (none) */
        0,
        packet + LIBNET_ETH_H); /* Packet header memory */

    //  Step 3: Packet construction (UDP header).

    libnet_build_udp(
        sport2,       /* source port */
        dport2,       /* dest. port */
        payload,      /* payload */
        payload_size, /* payload length */
        packet + LIBNET_ETH_H + LIBNET_IP_H);

    //  Step 4: Packet checksums (ICMP header *AND* IP header).

    if (libnet_do_checksum(packet + ETH_H, IPPROTO_UDP, LIBNET_UDP_H + payload_size) == -1)
    {
        libnet_error(LIBNET_ERR_FATAL, "libnet_do_checksum failed\n");
    }
    if (libnet_do_checksum(packet + ETH_H, IPPROTO_IP, LIBNET_IP_H) == -1)
    {
        libnet_error(LIBNET_ERR_FATAL, "libnet_do_checksum failed\n");
    }

    /* print packet info */
    if (!hide_header)
    {
        printf("IP header    Src Addr: %s", saddr2);
        printf("   Dst Addr: %s\n", daddr2);
        printf("             Len: %i   ID: %i   TTL: %i\n", ip_size, id, ttl);
        printf("UDP header   Src port: %i   Dst port: %i   Len: %i\n", sport2, dport2, udp_size);
    }
    if (!hide_payload)
    {
        printf("Payload (%d bytes)\n", payload_size);
        print_payload(payload, payload_size);
    }

    //  Step 5: Packet injection.

    c = libnet_write_link_layer(network, dev2, packet, packet_size);
    if (c < packet_size)
    {
        libnet_error(LN_ERR_WARNING, "libnet_write_link_layer only wrote %d bytes\n", c);
    }

    // Shut down the interface.

    if (libnet_close_link_interface(network) == -1)
    {
        libnet_error(LN_ERR_WARNING, "libnet_close_link_interface couldn't close the interface");
    }

    //Free packet memory.

    libnet_destroy_packet(&packet);
    printf("\n");
}

//copied from the serial.c file in lbard

int set_nonblock(int fd)
{
    int retVal = 0;

    do
    {
        if (fd == -1)
            break;

        int flags;
        if ((flags = fcntl(fd, F_GETFL, NULL)) == -1)
        {
            perror("fcntl");
            printf("set_nonblock: fcntl(%d,F_GETFL,NULL)", fd);
            retVal = -1;
            break;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            perror("fcntl");
            printf("set_nonblock: fcntl(%d,F_SETFL,n|O_NONBLOCK)", fd);
            return -1;
        }
    } while (0);
    return retVal;
}

int serial_setup_port_with_speed(int fd, int speed)
{
    struct termios t;

    tcgetattr(fd, &t);
    fprintf(stderr, "Serial port settings before tcsetaddr: c=%08x, i=%08x, o=%08x, l=%08x\n",
            (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
            (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

    speed_t baud_rate;
    switch (speed)
    {
    case 115200:
        baud_rate = B115200;
        break;
    case 230400:
        baud_rate = B230400;
        break;
    }

    // XXX Speed and options should be configurable
    if (cfsetospeed(&t, baud_rate))
        return -1;
    if (cfsetispeed(&t, baud_rate))
        return -1;

    // 8N1
    t.c_cflag &= ~PARENB;
    t.c_cflag &= ~CSTOPB;
    t.c_cflag &= ~CSIZE;
    t.c_cflag |= CS8;
    t.c_cflag |= CLOCAL;

    t.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO | ECHOE);
    /* Noncanonical mode, disable signals, extended
   input processing, and software flow control and echoing */

    t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR |
                   INPCK | ISTRIP | IXON | IXOFF | IXANY | PARMRK);
    /* Disable special handling of CR, NL, and BREAK.
   No 8th-bit stripping or parity error handling.
   Disable START/STOP output flow control. */

    // Disable CTS/RTS flow control
#ifndef CNEW_RTSCTS
    t.c_cflag &= ~CRTSCTS;
#else
    t.c_cflag &= ~CNEW_RTSCTS;
#endif

    // no output processing
    t.c_oflag &= ~OPOST;

    fprintf(stderr, "Serial port settings attempting ot be set: c=%08x, i=%08x, o=%08x, l=%08x\n",
            (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
            (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

    tcsetattr(fd, TCSANOW, &t);

    tcgetattr(fd, &t);
    fprintf(stderr, "Serial port settings after tcsetaddr: c=%08x, i=%08x, o=%08x, l=%08x\n",
            (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
            (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

    set_nonblock(fd);

    return 0;
}

int main(int argc, char **argv)
{
    int retVal = 0;

    do
    {
        //setup wireless capture settings
        char *dev = "mon0";
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        const u_char *packet;
        struct pcap_pkthdr header;
        int packcountlim = 1;
        int timeout = 10;                        //in miliseconds
        FILE *outFile = fopen("testFile", "ab"); // append only
        pcap_setdirection();
        time_t rawTime;
        struct tm *timeinfo;
        //packet container
        struct pktStruct
        {
            struct pcap_pkthdr pkt_header;
            const u_char *pkt_data;

            char timeInfo;
        };

        //setup serial ports
        char *port1 = "/dev/ttyUSB0";
        char *port2 = "/dev/ttyUSB1";
        char *port3 = "/dev/ttyUSB2";
        char *port4 = "/dev/ttyUSB3";

        printf("before open\n");
        //open serial ports
        int r1 = open(port1, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (r1 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port1);
            retVal = -1;
            break;
        }
        printf("after open %i\n", r1);
        int r2 = open(port2, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (r2 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port2);
            retVal = -1;
            break;
        }
        printf("after open %i\n", r2);
        int s1 = open(port3, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (s1 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port3);
            retVal = -1;
            break;
        }
        printf("after open %i\n", s1);
        int s2 = open(port4, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (s2 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port4);
            retVal = -1;
            break;
        }
        printf("after open %i\n", s2);

        //set non blocking for the serial ports
        set_nonblock(r1);
        set_nonblock(r2);
        set_nonblock(s1);
        set_nonblock(s2);

        //set serial port speeds
        serial_setup_port_with_speed(r1, 115200);
        serial_setup_port_with_speed(r2, 230400);
        serial_setup_port_with_speed(s1, 115200);
        serial_setup_port_with_speed(s2, 230400);
        printf("after serial setup\n");

        //open handle for wireless device
        handle = pcap_open_live(dev, BUFSIZ, packcountlim, timeout, errbuf);
        if (handle == NULL)
        {
            printf("Error starting pcap device: %s\n", errbuf);
        }

        //while loop that serialy searches for a packet to be captured by all devices (round robin)
        int bufferSize = 255;
        char readBuffer[bufferSize];
        char quitInputRead;
        int bytes_read;
        int packetID = 0;
        do
        {
            bytes_read = read(r1, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (r1): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                fflush(outFile);
            }

            bytes_read = read(s1, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (s1): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                fflush(outFile);
            }

            bytes_read = read(r2, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (r2): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                fflush(outFile);
            }

            bytes_read = read(s2, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (s2): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                fflush(outFile);
            }

            packet = pcap_next(handle, &header);
            if (header.len > 0)
            {
                printf("WIFI Packet total length %d\n", header.len);
                //send packet down the wire
                pcap_sendpacket(packet, ) if (pcap_sendpacket(packet, ) != 0)
                {
                    printf("Error sending packet. Length:  %d\n", header.len);
                    //send packet id++
                    //ttl = 60;
                    time(&rawtime);
                    timeinfo = localtime(&rawtime);
                    pktStruct.time = asctime(timeinfo);
                }
            }

        } while (1);

        //close opened serial ports
        close(r1);
        close(r2);
        close(s1);
        close(s2);
        printf("Serial ports closed: %s %s %s %s\n", port1, port2, port3, port4);
        //close opened file
        fclose(outFile);
    } while (0);

    return (retVal);
}
