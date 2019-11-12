#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <linux/limits.h>
#include <signal.h>
#include <argp.h>

#include "sync.h"
#include "lbard.h"
#include "message_handlers.h"
#include "packet_parser.h"

// Define some default argument values
#define DEFAULT_ADDRESS INADDR_ANY
#define DEFAULT_PORT 3940
#define DEFAULT_PACKET_CAPTURE_NUM -1
#define DEFAULT_PLANTUML_JAR_PATH "plantuml.jar"

// The number of mandatory arguments and a string containing them in the correct order delimited by spaces
#define NUM_MANDATORY_ARGS 0
static char argument_doc[] = "";

// List our arguments for argp
static struct argp_option options[] =
{
    {"port",    'p', "port",    0, "Port to listen on"},
    {"address", 'a', "address", 0, "Address to bind to"},
    {"jarpath", 'j', "path",    0, "PlantUML jarfile path"},
    {"packets", 'n', "packets", 0, "Number of packets to capture"},
    {0}
};

// Define a struct to hold our arg values
typedef struct arguments
{
    int            port;
    struct in_addr address;
    char*          jarpath;
    int            packets;
} arguments;

// Parse a single argument from argp
static error_t parse_arg(int key, char* arg, struct argp_state* state)
{
    // Get a pointer to the arguments struct
    arguments* arguments = state->input;

    // Parse the argument and store it in the struct
    switch (key)
    {
        case 'p':
            // Convert port number to int and assign it
            arguments->port = (int) strtol(arg, NULL, 10);;
            break;
        case 'a':
            // Convert & assign address, exiting on failure
            if (!inet_aton(arg, &arguments->address)) argp_usage(state);
            break;
        case 'j':
            arguments->jarpath = arg;
            break;
        case 'n':
            arguments->packets = (int) strtol(arg, NULL, 10);
            break;
        case ARGP_KEY_ARG:
            // Check if we have too many args
            if (state->arg_num >= NUM_MANDATORY_ARGS) argp_usage(state);

            // We would parse the args here, but we have none
        case ARGP_KEY_END:
            // Check if we have too few args
            if (state->arg_num < NUM_MANDATORY_ARGS) argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

// Define our argp parser which includes the argument structs and parser function we just defined
static struct argp argp_parser = {options, parse_arg, argument_doc, 0};

volatile sig_atomic_t sigint_flag = 0;
void sigint_handler(int signal)
{
    sigint_flag = 1;
}

long long start_time = 0;
long long gettime_ms()
{
    long long retVal = -1;

    do
    {
        struct timeval nowtv;

        // If gettimeofday() fails or returns an invalid value, all else is lost!
        if (gettimeofday(&nowtv, NULL) == -1)
        {
            perror("gettimeofday returned -1");
            break;
        }

        if (nowtv.tv_sec < 0 || nowtv.tv_usec < 0 || nowtv.tv_usec >= 1000000)
        {
            perror("gettimeofday returned invalid value");
            break;
        }

        retVal = nowtv.tv_sec * 1000LL + nowtv.tv_usec / 1000;
    } while (0);

    return retVal;
}

void dump_packet(char *msg, unsigned char *b, int n)
{
    printf("%s: Displaying %d bytes.\n", msg, n);
    for (int i = 0; i < n; i += 16)
    {
        int j;
        printf("%08X : ", i);
        for (j = 0; j < 16 && (i + j) < n; j++)
            printf("%02X ", b[i + j]);
        for (; j < 16; j++)
            printf("   ");
        for (j = 0; j < 16 && (i + j) < n; j++)
            if (b[i + j] >= ' ' && b[i + j] < 0x7f)
            {
                printf("%c", b[i + j]);
            }
            else
                printf(".");
        printf("\n");
    }
}

int parse_mac(unsigned char* mac, char* buffer)
{
    return sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void decode_wifi(unsigned char *packet, int len, FILE* output_file)
{
    printf("\n\n WIFI PACKET \n");

    // Dump the contents to the terminal
    dump_packet("Packet contents", packet, len);

    // Parse the packet headers
    parsed_packet headers = parse_packet(packet, len);

    // Parse the MAC addresses as neatly-formatted C strings
    char parsedSrcMac[18];
    char parsedDstMac[18];
    parse_mac(headers.header_80211.source, parsedSrcMac);
    parse_mac(headers.header_80211.dest, parsedDstMac);

    // Print out the source and destination
    printf("src MAC: %s\n", parsedSrcMac);
    printf("dst MAC: %s\n", parsedDstMac);

    // Parse the header on the highest level of the OSI stack
    char protocol[16];
    char message[64];
    switch (headers.highest_header)
    {
        case Rhizome:
            printf("This is a Rhizome packet\n");
            sprintf(protocol, "Rhizome");
            sprintf(message, "%s", headers.header_rhizome.type == 0 ? "BAR response" : "BAR request");
            break;
        case UDP:
            printf("This is a UDP packet\n");
            sprintf(protocol, "UDP");
            sprintf(message, "%d -> %d", headers.header_udp.source_port, headers.header_udp.dest_port);
            break;
        case TCP:
            // TODO: Parse TCP properly
            printf("This is a TCP packet\n");
            sprintf(protocol, "TCP");
            sprintf(message, "TCP parsing is not implemented yet");
            break;
        case IPv6:
            printf("This is an IPv6 packet\n");
            sprintf(protocol, "IPv6");
            switch (headers.header_ipv6.payload_proto)
            {
                case 0x06: // TCP
                    sprintf(message, "%s", "TCP");
                    break;
                case 0x11: // UDP
                    sprintf(message, "%s", "UDP");
                    break;
                default:
                    sprintf(message, "Unknown protocol (%02X)", headers.header_ipv6.payload_proto);
                    break;
            }
            break;
        case IPv4:
            printf("This is an IPv4 packet\n");
            sprintf(protocol, "IPv4");
            switch (headers.header_ipv4.payload_proto)
            {
                case 0x06: // TCP
                    sprintf(message, "%s", "TCP");
                    break;
                case 0x11: // UDP
                    sprintf(message, "%s", "UDP");
                    break;
                default:
                    sprintf(message, "Unknown protocol (%02X)", headers.header_ipv4.payload_proto);
                    break;
            }
            break;
        case LLC:
            printf("This is an 802.11 data frame with an LLC header\n");
            sprintf(protocol, "LLC");
            switch (headers.header_llc.type)
            {
                case 0x0800: // IPv4
                    sprintf(message, "%s", "IPv4");
                    break;
                case 0x0806: // ARP
                    sprintf(message, "%s", "ARP");
                    break;
                case 0x86DD: // IPv6
                    sprintf(message, "%s", "IPv6");
                    break;
                default:
                    sprintf(message, "Unknown protocol (%04X)", headers.header_llc.type);
                    break;
            }
            break;
        case MAC_80211:
            printf("This is an 802.11 frame\n");
            sprintf(protocol, "802.11");
            sprintf(message, "%s", wifi_frame_description[headers.header_80211.frame_version][headers.header_80211.frame_type][headers.header_80211.frame_subtype]);
            break;
        default:
            printf("This is an unknown packet type\n");
            sprintf(protocol, "???");
            sprintf(message, "%s", "");
            break;
    }

    // Write to the diagram
    fprintf(output_file, "\"%s\" -> \"%s\": T+%lldms - %s: %s\n", parsedSrcMac, parsedDstMac, gettime_ms() - start_time, protocol, message);
}

int decode_lbard(unsigned char *msg, int len, FILE *output_file)
{
    int areWeSending = 1; // Use this to see if we are sending or receiving
    int offset = 8;
    int peer_index = -1;

    // Iterate over the message buffer
    while (offset < len)
    {
        // All valid messages must be at least 8 bytes long.
        if (len < 8)
            return -1;

        char peer_prefix[6 * 2 + 1];
        snprintf(peer_prefix, 6 * 2 + 1, "%02x%02x%02x%02x%02x%02x",
                 msg[0], msg[1], msg[2], msg[3], msg[4], msg[5]);
        int msg_number = msg[6] + 256 * (msg[7] & 0x7f);
        int is_retransmission = msg[7] & 0x80;

        // Try find an existing struct for this peer
        struct peer_state *p = NULL;
        for (int i = 0; i < peer_count; i++)
        {
            // Check if the struct's prefix matches this one
            if (!strcasecmp(peer_records[i]->sid_prefix, peer_prefix))
            {
                // Set this as our peer struct
                p = peer_records[i];
                peer_index = i;
                break;
            }
        }

        // If we didn't find an existing peer struct, make one
        if (!p)
        {
            p = calloc(1, sizeof(struct peer_state));
            for (int i = 0; i < 4; i++)
                p->sid_prefix_bin[i] = msg[i];
            p->sid_prefix = strdup(peer_prefix);
            p->last_message_number = -1;
            p->tx_bundle = -1;
            p->request_bitmap_bundle = -1;

            // Store it in the peer_records array
            peer_records[peer_count++] = p;
        }

        // Update time stamp and most recent message from peer
        if (msg_number > p->last_message_number)
        {
            // We probably have missed packets.
            // But only count if gap is <256, since more than that probably means
            // something more profound has happened.
            p->missed_packet_count += msg_number - p->last_message_number - 1;
        }
        p->last_message_time = time(0);

        // Update the last message number, given this isn't a retransmission
        if (!is_retransmission)
            p->last_message_number = msg_number;

        int message_length;
        while (offset < len)
        {
            // Dump the packet to STDOUT
            printf("Offset: %i, len %i\n", offset, len);
            dump_packet("Packet offset", msg, len);
            printf("Message Type: %c - 0x%02X\n", msg[offset], msg[offset]);

            // Check if there's a handler for this message type
            if (message_handlers[msg[offset]])
            {
                // Call the handler and get the message description
                char message_description[8192];
                printf("Calling message handler for type 0x%02x @ offset 0x%x\n", msg[offset], offset);
                message_length = message_handlers[msg[offset]](p, peer_prefix, NULL, NULL, &msg[offset], len - offset, message_description);
                printf("Message description: %s\n", message_description);

                // Get the current time for the diagram
                long long relative_time_ms;
                relative_time_ms = gettime_ms() - start_time;

                // Check if this is an outgoing transmission from our Mesh Extender
                if (strncasecmp(msg, "LBARD:RFD900:TX:", 16))
                {
                    // Write as an outgoing transmission to the diagram
                    fprintf(output_file, "%s -> BROADCAST: T+%lldms %c - %s\n", peer_prefix,
                            relative_time_ms, msg[offset], message_description);
                }
                else
                {
                    // Write as an incoming transmission to the diagram
                    fprintf(output_file, "BROADCAST -> %s: T+%lldms %c - %s\n", peer_prefix,
                            relative_time_ms, msg[offset], message_description);
                }

                // Report an error if the packet length is less than 1 byte
                if (message_length < 1)
                {
                    fprintf(stderr,
                            "At packet offset 0x%x, message parser 0x%02x returned zero or negative message length (=%d).\n"
                            "  Assuming packet is corrupt.\n",
                            offset, msg[offset], message_length);
                    return -1;
                }
                printf("### %s : Handler consumed %d packet bytes.\n", timestamp_str(), message_length);
                offset += message_length;
            }
            else
            {
                // No parser for this message type (i.e. invalid message field)
                char sender_prefix[128];
                sprintf(sender_prefix, "%s*", p->sid_prefix);

                return -1;
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    // Register signal handlers
    signal(SIGINT, sigint_handler);

    int retVal;

    // Define args struct and populate simple defaults
    arguments args;
    args.port = DEFAULT_PORT;
    args.packets = DEFAULT_PACKET_CAPTURE_NUM;
    args.jarpath = DEFAULT_PLANTUML_JAR_PATH;

    // Populate complex defaults
    if (DEFAULT_ADDRESS == NULL)
    {
        args.address.s_addr = DEFAULT_ADDRESS;
    }
    else if (!inet_aton(DEFAULT_ADDRESS, &args.address))
    {
        perror("Failed to parse and set default address");
        exit(1);
    };

    // Parse command line args
    argp_parse(&argp_parser, argc, argv, 0, 0, &args);

    do
    {
        // Get the time to write as the file name
        time_t rawTime;
        int bufferSize = 100;
        struct tm *timeInfo;
        time(&rawTime);
        timeInfo = localtime(&rawTime);
        char timingDiagramFileName[bufferSize];
        char *time = asctime(timeInfo);
        time[strlen(time) - 1] = 0; //remove the new line at end of time
        snprintf(timingDiagramFileName, bufferSize, "timingDiagram_%s.txt", time);

        // Open the file and add the PlantUML prefix
        FILE *outFile;
        outFile = fopen(timingDiagramFileName, "w"); //open file to write to
        fprintf(outFile, "@startuml\n");			 //write first line of uml file

        // Initialise socket variables
        int sockfd;
        struct sockaddr_in serv_addr, client_addr;
        memset(&serv_addr, 0, sizeof(serv_addr)); //clear struct before setting up
        memset(&client_addr, 0, sizeof(client_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr = args.address; //any source address
        serv_addr.sin_port = htons(args.port);

        // Try opening the socket
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            perror("ERROR opening socket");
            exit(-1);
        }

        // Bind the listen address to the socket
        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("ERROR on binding");
            exit(-1);
        }
        else
        {
            printf("Listening at %s:%i\n", inet_ntoa(serv_addr.sin_addr), args.port);
        }

        // Set the start time
        start_time = gettime_ms();

        // Print out a helpful reminder that this will run until you tell it to stop
        if (args.packets > 0)
        {
            printf("Will capture %d packet%c\n", args.packets, args.packets > 1 ? 's' : '\0');
        }
        else
        {
            printf("Will capture forever until stopped\n");
        }
        printf("Press Ctrl+C to stop capturing\n");
        fflush(stdout);

        // Accept and process incoming packets, will iterate until desired number of packets reached or stopped manually
        u_char packet[8192];
        for (int i = 0; args.packets > 0 ? i < args.packets && !sigint_flag : !sigint_flag; i++)
        {
            int bytesReceived = 0;
            unsigned int addressLength;

            // Accept incoming message
            while (!bytesReceived && !sigint_flag)
            {
                // Null-terminate the packet buffer
                packet[0] = 0;

                // Receive packets (non-blocking)
                bytesReceived = recvfrom(
                        sockfd, // Socket
                        packet, // Packet buffer
                        8192, // Packet length
                        MSG_DONTWAIT, // Don't block and wait
                        (struct sockaddr *) &client_addr, // Source address
                        &addressLength // Address length
                );

                // Check if we haven't received anything
                if (!bytesReceived)
                {
                    usleep(100000); // Sleep for 100ms before we try again
                    printf(".");
                    fflush(stdout);
                }

                // Handle errors
                switch (errno)
                {
                    case 0: // No error
                        break;
                    case EAGAIN: // Receive timed out
                        bytesReceived = 0;
                        break;
                    default:
                        perror("Unhandled error from recvfrom()");
                        break;
                }

                // Reset errno
                errno = 0;
            }

            // Kill the packet loop if we broke out with a SIGINT
            if (sigint_flag) break;

            printf("Received %d bytes\n", bytesReceived);

            // Check for receive errors and break
            if (bytesReceived < 0)
            {
                perror("ERROR in recieving packet\n");
                retVal = 1;
                break;
            }

            // Is this an LBARD packet?
            if (packet[0] == 'L' &&
                packet[1] == 'B' &&
                packet[2] == 'A' &&
                packet[3] == 'R' &&
                packet[4] == 'D')
            {
                // Check if the packet is not just a header
                if (sizeof(packet) > 5)
                {
                    printf("About to call decode_lbard()\n");

                    // Initialise a buffer to store our decoded LBARD packet in
                    char lbardResult[8192];

                    // Decode the LABRD packet
                    // 16 byte offset before analysis to remove packet header
                    // 32 bytes of Reed-Solomon error correction trimmed from the end
                    // 1 byte of new line character that is an artifact of data collection removed from the end also
                    decode_lbard(&packet[16], bytesReceived - 16 - 32 - 1, outFile);

                    // Null-terminate the decoded packet buffer
                    lbardResult[0] = '\0';
                }
            }
            else // Not an LBARD packet, must be from WiFi
            {
                // Decode wifi packet and put returned string into NTD text file
                decode_wifi(&packet, bytesReceived, outFile);
            }

            // Null-terminate the packet buffer
            packet[0] = '\0';
        }

        // Append the PlantUML suffix to the fille
        fprintf(outFile, "@enduml");

        // Get current working directory as this is where the generated text file is saved
        char cwd[PATH_MAX];
        char command[256];
        getcwd(cwd, sizeof(cwd));

        // Wait until the file is written and close it
        printf("Writing diagram template file...\n");
        fclose(outFile);

        // Run PlantUML on the text file we just generated
        printf("Making diagram in '%s'. This may take a while.\n", cwd);
        snprintf(command, 256, "java -jar \'%s\' \'%s/%s\'", args.jarpath, cwd, timingDiagramFileName);
        system(command);

        // Clear out allocated memory blocks
        for (int i = 0; i < peer_count; i++)
        {
            free(peer_records[i]->sid_prefix); // strdup'd string
            free(peer_records[i]); // calloc'd struct
        }
    } while (0);

    return retVal;
}
