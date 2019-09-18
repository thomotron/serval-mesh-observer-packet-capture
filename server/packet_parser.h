//
// A collection of functions to parse raw 802.11 packets
// captured by libpcap
//

#ifndef MESHOBSERVER_PACKET_CAPTURE_PACKET_PARSER_H
#define MESHOBSERVER_PACKET_CAPTURE_PACKET_PARSER_H

// Represents an 802.11 frame header
// Trimmed down to the frame control field for our purposes
typedef struct header_80211
{
    unsigned char frame_type;
    unsigned char frame_version;
    unsigned char frame_subtype;

} header_80211;

// Represents an 802.11 LLC header
// Trimmed down to the OUI and type fields
typedef struct header_llc
{
    unsigned int   org_code;
    unsigned short type;
} header_llc;

typedef struct header_ipv4
{
    unsigned char protocol;
} header_ipv4;

// Represents a parsed 802.11 packet
// Consists of all parsable headers previously defined
typedef struct parsed_packet
{
    header_80211 header_80211;
    header_llc   header_llc;
    header_ipv4  header_ipv4;
} parsed_packet;

header_80211 get_header_80211(unsigned char* packet, int* offset);
header_llc get_header_llc(unsigned char* packet, int* offset);
header_ipv4 get_header_ipv4(unsigned char* packet, int* offset);
parsed_packet parse_packet(unsigned char* packet, int len);


#endif //MESHOBSERVER_PACKET_CAPTURE_PACKET_PARSER_H
