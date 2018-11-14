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

/*
 * 
 */
int main(int argc, char** argv) {
    char *dev = "mon0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    u_char *packet;
    struct pcap_pkhdr packet_header;
    int packcountlim = 1;
    int timeout = 10 //in miliseconds


    //set up wireless device
    device = pcap_lookupdev(errbuf);
    if (device == NULL)
    {
        printf("Error starting device: %s\n", errbuf);
    }

    //open handle for wireless device
    handle = pcap_open_live(dev, BUFSIZ, packcountlim, timeout, errbuf);

    //while loop that serialy searches for a packet to be captured by all devices (round robin)
    do
    {
        if (dev)
        {
            packet = pcap_next(handle, &packet_header);
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

        } */
    } while (1);

    return (EXIT_SUCCESS);
}

