//
// A collection of functions to parse raw 802.11 packets
// captured by libpcap
//

#include "packet_parser.h"

// Scrapes information from the given packet's 802.11 header
header_80211 get_header_80211(unsigned char* packet, int* offset)
{
    header_80211 header;

    // Frame control field is the first two octets
    // We only care about the first octet, so we'll grab and mask that
    header.frame_version = (packet[*offset] >> 6) & 0x03; // First bit pair, shifted down and masked
    header.frame_type = (packet[*offset] >> 4) & 0x03; // Second bit pair, shifted down and masked
    header.frame_subtype = (packet[*offset]) & 0x0F; // Last four bits, masked

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

    return header;
}

// Parses the given packet through as many parsing functions as possible
parsed_packet parse_packet(unsigned char* packet, int len)
{
    parsed_packet parsed;
    int offset = 0;

    // Enter a run-once loop so we can break execution neatly
    do
    {
        parsed.header_80211 = get_header_80211(packet, &offset); // Parse the 802.11 frame
        if (offset >= len) break;
        parsed.header_llc = get_header_llc(packet, &offset); // Parse the LLC header
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