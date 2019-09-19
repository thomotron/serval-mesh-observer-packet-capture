//
// A collection of functions to parse raw 802.11 packets
// captured by libpcap
//

#include <stdio.h>
#include <stdlib.h>
#include "packet_parser.h"
#include "radiotap_iter.h"

#define DEBUG

// Scrapes information from the given packet's 802.11 header
header_80211 get_header_80211(unsigned char* packet, int* offset)
{
    header_80211 header;

    // Frame control field is the first two octets
    // We only care about the first octet, so we'll grab and mask that
    header.frame_version = packet[*offset] & 0x03; // First bit pair, shifted down and masked
    header.frame_type = (packet[*offset] >> 2) & 0x03; // Second bit pair, shifted down and masked
    header.frame_subtype = (packet[*offset] >> 4) & 0x0F; // Last four bits, masked

    // Grab the source and dest MAC addresses
    for (int i = 0; i < 6; i++)
    {
        header.dest[i] = packet[*offset+4+i];
        header.source[i] = packet[*offset+10+i];
    }

#ifdef DEBUG
    printf("[DEBUG] 802.11 FRAME: VER %d, TYPE %d, SUBTYPE %d, SOURCE %02X:%02X:%02X:%02X:%02X:%02X, DEST %02X:%02X:%02X:%02X:%02X:%02X\n",
            header.frame_version,
            header.frame_type,
            header.frame_subtype,
            header.source[0], header.source[1], header.source[2], header.source[3], header.source[4], header.source[5],
            header.dest[0], header.dest[1], header.dest[2], header.dest[3], header.dest[4], header.dest[5]);
#endif

    // Skip the remainder of the frame header
    *offset += 36;

    return header;
}

// Scrapes information from the given packet's 802.11 LLC header
header_llc get_header_llc(unsigned char* packet, int* offset)
{
    header_llc header;
    *offset += 3; // Skip the first three octets (DSAP, SSAP, and control)

    // Grab the organisationally unique identifier and content type
    header.org_code = (packet[*offset+0] << 16) | (packet[*offset+1] << 8) | (packet[*offset+2]); // First three bytes
    header.type = (packet[*offset+3] << 8) | (packet[*offset+4]); // Remaining two bytes

#ifdef DEBUG
    printf("[DEBUG] LLC HEADER: OUI %06X, TYPE %04X\n", header.org_code, header.type);
#endif

    // Skip to the end of the LLC header
    *offset += 5;

    return header;
}

// Scraped information from the given packet's IPv4 header
header_ipv4 get_header_ipv4(unsigned char* packet, int* offset)
{
    header_ipv4 header;
    *offset += 9; // Skip to the 9th byte

    header.protocol = packet[*offset]; // Protocol byte

#ifdef DEBUG
    printf("[DEBUG] IPv4 HEADER: PROTO %02X\n", header.protocol);
#endif

    return header;
}

// Parses the given packet through as many parsing functions as possible
parsed_packet parse_packet(unsigned char* packet, int len)
{
    parsed_packet parsed;
    int offset = 0;

    // Set up a copious amount of structs to parse the RadioTap header
    struct ieee80211_radiotap_iterator radiotap_iterator;
    struct ieee80211_radiotap_header* radiotap_header = (struct ieee80211_radiotap_header*) packet;
    struct ieee80211_radiotap_vendor_namespaces radiotap_namespaces;
    ieee80211_radiotap_iterator_init(&radiotap_iterator, radiotap_header, len, &radiotap_namespaces);

    // Skip past the RadioTap header
    offset += radiotap_header->it_len;

#ifdef DEBUG
    printf("Starting packet parsing at offset %d\n", offset);
#endif

    // Enter a run-once loop so we can break execution neatly
    do
    {
        // Parse the 802.11 frame
        parsed.header_80211 = get_header_80211(packet, &offset);
        if (offset >= len) break;

        // Stop if the 802.11 header has a non-zero version (it hasn't been incremented as of Sep 2019)
        if (parsed.header_80211.frame_version != 0) break;

        // Parse the LLC header
        parsed.header_llc = get_header_llc(packet, &offset);
        if (offset >= len) break;

        // Stop if the LLC header has a non-empty org code, meaning we can't rely on an EtherType for L3 parsing
        if (parsed.header_llc.org_code) break;

        // Check what kind of header we should parse the L3 block as
        if (parsed.header_llc.type == 0x0800) parsed.header_ipv4 = get_header_ipv4(packet, &offset); // IPv4
        else if (parsed.header_llc.type == 0x86DD) {} // TODO: IPv6
        else break; // No other predefined parsing functions so we'll stop here
        if (offset >= len) break;

        // TODO: TCP/UDP, Rhizome
    } while (0);

    // Return the parsed packet
    return parsed;
}