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
#include <unistd.h>
#include <pcap.h>
#include <termios.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/*
 * 
 */
#define SVR_IP "192.168.2.2"
#define SVR_PORT 3940

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
    //Noncanonical mode, disable signals, extended
    //input processing, and software flow control and echoing

    t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR |
                   INPCK | ISTRIP | IXON | IXOFF | IXANY | PARMRK);
    //Disable special handling of CR, NL, and BREAK.
    //No 8th-bit stripping or parity error handling.
    //Disable START/STOP output flow control.

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
        printf("Before variable deration\n");
        //setup wireless capture settings
        char *dev = "mon0";
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        struct pcap_pkthdr header;
        int serverlen;
        int packcountlim = 1, timeout = 10, sockfd, n;
        FILE *outFile = fopen("testFile", "ab"); // append to file only

        printf("Before packet injection setup\n");
        //setup packet injection - source used: https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/udpclient.c
        u_char capPacket;
        struct sockaddr_in serv_addr;
        bzero((char *)&serv_addr, sizeof(serv_addr));        
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr(SVR_IP);
        struct hostent *server;
        int portno = SVR_PORT;
        serv_addr.sin_port = htons(portno);
        char hbuf[NI_MAXHOST];
        socklen_t len = sizeof(struct sockaddr_in);

        //setup sockets
        printf("Before socket setup\n");
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            perror("Error setting up socket\n");
            retVal = -2;
            return (retVal);
        }

        if (getnameinfo((struct sockaddr *)&serv_addr, len, hbuf, sizeof(hbuf), NULL, 0, 0))
        {
            printf("could not resolve IP\n");
            retVal = -1;
            return (retVal);
        }
        else
        {
            printf("host=%s\n", hbuf);
        }
        serverlen = sizeof(serv_addr);

        printf("Before serial port setup\n");
        //setup serial ports
        char *port1 = "/dev/ttyUSB0";
        char *port2 = "/dev/ttyUSB1";
        char *port3 = "/dev/ttyUSB2";
        char *port4 = "/dev/ttyUSB3";
        printf("before opening serial ports\n");
        //open serial ports
        int r1 = open(port1, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (r1 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port1);
            retVal = -3;
            break;
        }
        printf("after open %i\n", r1);
        int r2 = open(port2, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (r2 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port2);
            retVal = -4;
            break;
        }
        printf("after open %i\n", r2);
        int s1 = open(port3, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (s1 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port3);
            retVal = -5;
            break;
        }
        printf("after open %i\n", s1);
        int s2 = open(port4, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (s2 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", port4);
            retVal = -6;
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

        printf("Before pcap setup\n");
        //https://linux.die.net/man/3/pcap_setdirection
        pcap_setdirection(handle, PCAP_D_IN);

        //while loop that serialy searches for a packet to be captured by all devices (round robin)
        int bufferSize = 8192;
        char readBuffer[bufferSize];
        int bytes_read;

        do
        {
            /*bytes_read = read(r1, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (r1): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                //printf("Before trying to send serial captured packet\n");
                if (send(sockfd, readBuffer, sizeof(readBuffer), 0) == -1)
                {
                    perror("Error Sending");
                    retVal = -7;
                    break;
                }
                fflush(outFile);
            }

            bytes_read = read(s1, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (s1): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                //printf("Before trying to send serial captured packet\n");
                if (send(sockfd, readBuffer, sizeof(readBuffer), 0) == -1)
                {
                    perror("Error Sending");
                    retVal = -8;
                    break;
                }
                fflush(outFile);
            }

            bytes_read = read(r2, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (r2): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                //printf("Before trying to send serial captured packet\n");
                if (send(sockfd, readBuffer, sizeof(readBuffer), 0) == -1)
                {
                    perror("Error Sending");
                    retVal = -9;
                    break;
                }
                fflush(outFile);
            }

            bytes_read = read(s2, &readBuffer, bufferSize);
            if (bytes_read > 0)
            {
                readBuffer[bytes_read] = 0;
                printf("Read %d from (s2): %s\n", bytes_read, readBuffer);
                fprintf(outFile, "%X\n", *readBuffer);
                //printf("Before trying to send serial captured packet\n");
                if (send(sockfd, readBuffer, sizeof(readBuffer), 0) == -1)
                {
                    perror("Error Sending\n");
                    retVal = -10;
                    break;
                }
                fflush(outFile);
            }*/
            capPacket = pcap_next(handle, &header);
            if (header.len > 0)
            {
                printf("Captured WIFI packet total length %i\n", header.len);
                printf("Captured WIFI packet total length2 %i\n", header.caplen);
                printf("Before trying to send wifi captured packet\n");
                n = sendto(sockfd, &capPacket, header.caplen, 0, (struct sockaddr *)&serv_addr, serverlen);
                printf("Size Written %i\n", n);
                if (n < 0)
                {
                    perror("Error Sending\n");
                    retVal = -11;
                    break;
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
