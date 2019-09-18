#ifndef MESHOBSERVER_PACKET_CAPTURE_MDP_TYPES_H
#define MESHOBSERVER_PACKET_CAPTURE_MDP_TYPES_H

// Simple structure for each well-known MDP port
typedef struct mdp_type
{
    long  portNo;
    char* description;

} mdp_type;

// All port numbers were collected from the following URL and are up-to-date as of 2019-09-17:
// http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp_port_number
struct mdp_type mdp_types[] =
{
    {1, "ID management"},
    {2, "Route state"},
    {4, "NAT traversal"},
    {5, "NAT traversal"},
    {6, "ECHO origination"},
    {7, "ECHO"},
    {8, "TRACE"},
    {10, "DNA"},
    {12, "VoMP"},
    {13, "Rhizome bundle transfer"},
    {14, "Rhizome bundle transfer"},
    {15, "Serval Directory Service"},
    {16, "Rhizome manifest request"},
    {17, "Rhizome sync"},
    {63, "No reply"},
    {0} // Null entry for iteration
};

#endif //MESHOBSERVER_PACKET_CAPTURE_MDP_TYPES_H
