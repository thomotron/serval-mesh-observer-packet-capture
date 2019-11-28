//
// A collection of functions to parse raw 802.11 packets
// captured by libpcap
//

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "packet_parser.h"
#include "radiotap_iter.h"

#define DEBUG

// Massive lookup array for 802.11 frame versions, types, and subtypes
// Plug values like this: wifi_frame_decription[version][type][subtype]
const char* wifi_frame_description[1][4][16] =
{
    { // Version 0
        { // Management
            "Association request",
            "Association response",
            "Reassociation request",
            "Reassociation response",
            "Probe request",
            "Probe response",
            "Timing advertisement",
            "Reserved",
            "Beacon",
            "Announcement traffic indication message",
            "Disassociation",
            "Authentication",
            "Deauthentication",
            "Action",
            "Action non-acknowledgement",
            "Reserved"
        },
        { // Control
            "Reserved",
            "Reserved",
            "Reserved",
            "Trigger",
            "Beamforming report poll",
            "802.11ac/ax null data packet announcement",
            "Control frame extension",
            "Control wrapper",
            "Block acknowledgement request",
            "Block acknowledgement",
            "Power-save poll",
            "Request-to-send",
            "Clear-to-send",
            "Acknowledgement",
            "Contention-free end",
            "Contention-free end, contention-free acknowledgement"
        },
        { // Data
            "Data",
            "Data, contention-free acknowledgement",
            "Data, contention-free poll",
            "Data, contention-free acknowledgement and poll",
            "No data",
            "Contention-free poll",
            "Contention-free acknowledgement",
            "Contention-free acknowledgement and poll",
            "QoS data",
            "QoS data, contention-free acknowledgement",
            "QoS data, contention-free poll",
            "QoS data, contention-free acknowledgement and poll",
            "QoS no data",
            "Reserved",
            "QoS no data, contention-free poll",
            "QoS no data, contention-free acknowledgement and poll"
        },
        { // Extension
            "Direction multi-gigabit beacon",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved",
            "Reserved"
        }
    }
};

// Scrapes information from the given packet's 802.11 header
header_80211 get_header_80211(unsigned char* packet, int* offset, int* trailer_len)
{
    header_80211 header = {0};

    // Frame control field is the first two octets
    // We (mostly) only care about the first octet, so we'll grab and mask that
    header.frame_version = packet[*offset] & 0x03; // First bit pair, shifted down and masked
    header.frame_type = (packet[*offset] >> 2) & 0x03; // Second bit pair, shifted down and masked
    header.frame_subtype = (packet[*offset] >> 4) & 0x0F; // Last four bits, masked

    // We need to grab two bits from the second octet to determine if this frame is
    // entering, exiting, or relaying through a wireless distribution system (or not at all)
    header.to_ds = packet[*offset+1] & 0x01; // Entering the distribution system
    header.from_ds = (packet[*offset+1] >> 1) & 0x01; // Exiting the distribution system

    // Grab the source and dest MAC addresses
    for (int i = 0; i < 6; i++)
    {
        header.dest[i] = packet[*offset+4+i];
        header.source[i] = packet[*offset+10+i];
    }

#ifdef DEBUG
    printf("[DEBUG] 802.11 FRAME: VER %d, TYPE %d, SUBTYPE %d, SOURCE %02X:%02X:%02X:%02X:%02X:%02X, DEST %02X:%02X:%02X:%02X:%02X:%02X, FROM DIST? %s, TO DIST? %s\n",
            header.frame_version,
            header.frame_type,
            header.frame_subtype,
            header.source[0], header.source[1], header.source[2], header.source[3], header.source[4], header.source[5],
            header.dest[0], header.dest[1], header.dest[2], header.dest[3], header.dest[4], header.dest[5],
            header.from_ds ? "YES" : "NO",
            header.to_ds ? "YES" : "NO");
#endif

    // Check if this is a relayed frame (4 addresses instead of 3, skip 6 extra bytes)
    if (header.from_ds && header.to_ds) *offset += 6;

    // Skip the remainder of the frame header
    *offset += 24;

    // Let the main parser know about the four-byte trailer
    *trailer_len += 4;

    return header;
}

// Scrapes information from the given packet's 802.11 LLC header
header_llc get_header_llc(unsigned char* packet, int* offset)
{
    header_llc header = {0};

    // Check if there is a SNAP header by checking DSAP and SSAP are 0xAA
    // If not, then this isn't a valid header and we should stop here
    if (packet[*offset] == 0xAA && packet[*offset+1] == 0xAA)
    {
        // Skip the DSAP, SSAP, and control fields
        *offset += 3;

        // Grab the organisationally unique identifier and content type
        header.org_code = (packet[*offset+0] << 16) | (packet[*offset+1] << 8) | (packet[*offset+2]); // First three bytes
        header.type = (packet[*offset+3] << 8) | (packet[*offset+4]); // Remaining two bytes

        // Skip to the end of the LLC header
        *offset += 5;
    }
    else
    {
        // Skip the DSAP, SSAP, and control fields
        *offset += 3;
    }

#ifdef DEBUG
    printf("[DEBUG] LLC HEADER: OUI %06X, TYPE %04X\n", header.org_code, header.type);
#endif

    return header;
}

// Scraped information from the given packet's IPv4 header
header_ipv4 get_header_ipv4(unsigned char* packet, int* offset)
{
    header_ipv4 header = {0};

    // Get the header length from the IHL field
    header.length = (packet[*offset] & 0x0F) * 4; // Mask the lower 4 bits and multiply into byte length

    // Get the protocol
    header.payload_proto = packet[*offset + 9];

    // Get the source and destination addresses
    header.source.s_addr = packet[*offset+12] | (packet[*offset+13] << 8) | (packet[*offset+14] << 16) | (packet[*offset+15] << 24);
    header.dest.s_addr = packet[*offset+16] | (packet[*offset+17] << 8) | (packet[*offset+18] << 16) | (packet[*offset+19] << 24);

#ifdef DEBUG
    printf("[DEBUG] IPv4 HEADER: SRC %s, DEST %s, LEN %d, PROTO %02X\n", inet_ntoa(header.source), inet_ntoa(header.dest), header.length, header.payload_proto);
#endif

    // Skip the remainder of the header
    *offset += header.length;

    return header;
}

header_ipv6 get_header_ipv6(unsigned char* packet, int* offset)
{
    header_ipv6 header = {0};

    // Get the Next Header field and treat it as the payload protocol
    header.payload_proto = packet[*offset+5];

    // Get the source and destination addresses
    for (int i = 0; i < 16; i++)
    {
        header.source.__in6_u.__u6_addr8[i] = packet[*offset+8+i];
        header.dest.__in6_u.__u6_addr8[i] = packet[*offset+24+i];
    }

#ifdef DEBUG
    // Parse the source and destination addresses
    char source_buffer[INET6_ADDRSTRLEN];
    char dest_buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &header.source, source_buffer, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &header.dest, dest_buffer, INET6_ADDRSTRLEN);

    printf("[DEBUG] IPv6 HEADER: SRC %s, DEST %s, PROTO %02x\n", source_buffer, dest_buffer, header.payload_proto);
#endif

    // Skip the remainder of the header
    *offset += 40;

    return header;
}

header_udp get_header_udp(unsigned char* packet, int* offset)
{
    header_udp header = {0};

    // Get the source and destination ports
    header.source_port = (packet[*offset] << 8) | packet[*offset+1];
    header.dest_port = (packet[*offset+2] << 8) | packet[*offset+3];

    // Get the packet and content length
    header.length = (packet[*offset+4] << 8) | packet[*offset+5];
    header.payload_length = header.length - 8;

#ifdef DEBUG
    printf("[DEBUG] UDP HEADER: SRC PORT %d, DEST PORT %d, LEN %d\n", header.source_port, header.dest_port, header.length);
#endif

    // Skip the remainder of the header
    *offset += 8;

    return header;
}

header_rhizome get_header_rhizome(unsigned char* packet, int* offset, int len)
{
    header_rhizome header = {0};

    // Get the packet type
    header.type = packet[*offset];

#ifdef DEBUG
    printf("[DEBUG] RHIZOME HEADER: TYPE %d\n", header.type);
#endif

    // Skip the remainder of the packet
    *offset += len;
}

header_bar get_header_bar(unsigned char* packet, int* offset)
{
    header_bar header = {0};

    // Copy over both of the char* fields
    strncpy(header.manifest_prefix, packet + *offset, 15);
    strncpy(header.lower_version, packet + *offset + 16, 7);

    // Get the remaining fields
    header.log_length = packet[*offset+15];
    header.lat_min = packet[*offset+23];
    header.lon_min = packet[*offset+24];
    header.lon_min = packet[*offset+25];
    header.lon_min = packet[*offset+26];
    header.ttl = packet[*offset+27];

#ifdef DEBUG
    printf("[DEBUG] RHIZOME BUNDLE ANNOUNCEMENT: MANIFEST PREFIX %s, LENGTH %d, LOW VERSION %s, BOUNDS (lat %d, lon %d) -> (lat %d, lon %d), TTL %d",
            header.manifest_prefix,
            header.log_length,
            header.lower_version,
            header.lat_min, header.lon_min, header.lat_max, header.lon_max,
            header.ttl);
#endif

    // Skip the remainder of the packet
    *offset += 32;

    return header;
}

// Parses the given packet through as many parsing functions as possible
parsed_packet parse_packet(unsigned char* packet, int len)
{
    parsed_packet parsed = {0};
    int offset = 0;
    int trailer_len = 0;

    // Set up a copious amount of structs to parse the RadioTap header
    struct ieee80211_radiotap_iterator radiotap_iterator;
    struct ieee80211_radiotap_header* radiotap_header = (struct ieee80211_radiotap_header*) packet;
    struct ieee80211_radiotap_vendor_namespaces radiotap_namespaces;
    ieee80211_radiotap_iterator_init(&radiotap_iterator, radiotap_header, len, &radiotap_namespaces);

    // Skip past the RadioTap header
    offset += radiotap_header->it_len;

#ifdef DEBUG
    printf("[DEBUG] Starting packet parsing at offset %d\n", offset);
#endif

    // Enter a run-once loop so we can break execution neatly
    do
    {
        // Parse the 802.11 frame
        parsed.header_80211 = get_header_80211(packet, &offset, &trailer_len);
        parsed.highest_header = MAC_80211;
        if (offset >= len - trailer_len) break;

        // Stop if the 802.11 header has a non-zero version (it hasn't been incremented as of Sep 2019)
        if (parsed.header_80211.frame_version != 0) break;

        // Stop if the 802.11 frame is not data or is QoS, as only data frames carry LLC
        if (parsed.header_80211.frame_type != 2 || parsed.header_80211.frame_subtype > 7) break;

        // Parse the LLC header
        parsed.header_llc = get_header_llc(packet, &offset);
        parsed.highest_header = LLC;
        if (offset >= len - trailer_len) break;

        // Stop if the LLC header has a non-empty org code, meaning we can't rely on an EtherType for L3 parsing
        if (parsed.header_llc.org_code) break;

        // Store our L4 protocol EtherType in a common place since IPv4 and IPv6 use the same protocol values
        unsigned char l4_proto = 0;

        // Check what kind of header we should parse the L3 block as
        switch (parsed.header_llc.type)
        {
            case 0x0800: // IPv4
                parsed.header_ipv4 = get_header_ipv4(packet, &offset);
                parsed.highest_header = IPv4;
                l4_proto = parsed.header_ipv4.payload_proto; // Inner protocol EtherType
                break;
            case 0x86DD: // IPv6
                parsed.header_ipv6 = get_header_ipv6(packet, &offset);
                parsed.highest_header = IPv6;
                l4_proto = parsed.header_ipv6.payload_proto; // Inner protocol EtherType
                break;
            default: // Unknown
                // No other predefined parsing functions so we'll stop here
                break;
        }
        if (offset >= len - trailer_len) break;

        // Store the L7 port/protocol number in a common spot as above for TCP/UDP
        unsigned short l7_source = 0;
        unsigned short l7_dest = 0;

        // Check what kind of EtherType we got from L3 and parse accordingly
        switch (l4_proto)
        {
            case 0x11: // UDP
                parsed.header_udp = get_header_udp(packet, &offset);
                parsed.highest_header = UDP;
                l7_source = parsed.header_udp.source_port;
                l7_dest = parsed.header_udp.dest_port;
                break;
            case 0x06: // TCP
                // TODO: TCP
                break;
            default:
                break;
        }

        // Try parse the L7 protocol from the L4 payload
        if (l7_source == 4110 || l7_dest == 4110) // Rhizome
        {
            parsed.header_rhizome = get_header_rhizome(packet, &offset, len);
            parsed.highest_header = Rhizome;
        }
    } while (0);

    // Return the parsed packet
    return parsed;
}