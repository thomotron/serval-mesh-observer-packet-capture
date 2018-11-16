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

/*
 * 
 */
int main(int argc, char** argv) {

    //setup wireless capture settings
    char *dev = "mon0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    u_char packet;
    struct pcap_pkthdr header;
    int packcountlim = 1;
    int timeout = 10; //in miliseconds

    //setup serial ports
    char *port1 = "ttyUSB0";
    char *port2 = "ttyUSB1";
    char *port3 = "ttyUSB2";
    char *port4 = "ttyUSB3";
    int open1;
    int open2;
    int open3;
    int open4;

    printf("before open\n");
    //try to open serial portstderr(errno
    open1 = open(port1, O_RDONLY | O_NOCTTY);
    printf("after open %i\n", open1);
    if (open1 < 0)
    {
        printf("Could not open port %s: %s\n", port1, strerror(errno));
    }
    else
    {
        printf("Opened port %c fine", port1);
    }
    /*open2 = open(port2, 0_RDONLY | 0NOCTTY);
    if (open2 < 0)
    {
        printf("Could not open port %s: %s\n", port2, stderror(errno));
    }
    open3 = open(port3, 0_RDONLY | 0NOCTTY);
    if (open3 < 0)
    {
        printf("Could not open port %s: %s\n", port3, stderror(errno));
    }
    open4 = open(port4, 0_RDONLY | 0NOCTTY);
    if (open4 < 0)
    {
        printf("Could not open port %s: %s\n", port4, stderror(errno));
    }*/





    //set up wireless device
    /*dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("Error starting device: %s\n", errbuf);
    }

    //open handle for wireless device
    handle = pcap_open_live(dev, BUFSIZ, packcountlim, timeout, errbuf);

    //while loop that serialy searches for a packet to be captured by all devices (round robin)
    /*do
    {
        if (dev)
        {
            packet = *pcap_next(handle, &header);
        }
        /*if (s1)
        {

        }
        if (s2)
        {

        }
        if (s3)
        {

        }
        if (s4)
        {

        } 
       
        printf("Packet total length %d\n", header.len);
    } while (1);*/

    //close opened serial ports
    printf("before close %i\n", open1);
    close(open1);
    //close(open2);
    //close(open3);
    //close(open4);

    return (EXIT_SUCCESS);
}

