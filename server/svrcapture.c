/* A simple server in the internet domain using TCP
   The port number is passed as an argument 
   This version runs forever, forking off a separate 
   process for each connection
   gcc server2.c -lsocket
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netdb.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <linux/limits.h>
#include <assert.h>
#include <signal.h>
#include <argp.h>

#include "sync.h"
#include "lbard.h"
#include "message_handlers.h"
#include "packet_parser.h"

#define MAX_PACKET_SIZE 255
#define RADIO_RXBUFFER_SIZE 64 + MAX_PACKET_SIZE

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

	// Work our way down the OSI stack and find the highest parsed header
	char protocol[16];
	char message[64];
	if (headers.header_udp.length) // We've gotten the UDP header
    {
	    printf("This is a UDP packet\n");
        sprintf(protocol, "UDP");
	    sprintf(message, "%d -> %d", headers.header_udp.source_port, headers.header_udp.dest_port);
    }
	else if (headers.header_ipv6.payload_proto || headers.header_ipv4.payload_proto) // We've gotten an IP header
    {
	    // Get the IP version and protocol
	    char version;
	    unsigned char payload_proto;
	    if (headers.header_ipv6.payload_proto)
        {
	        version = '6';
            payload_proto = headers.header_ipv6.payload_proto;
        }
	    else
        {
	        version = '4';
            payload_proto = headers.header_ipv4.payload_proto;
        }

	    printf("This is an IPv%c packet\n", version);
	    sprintf(protocol, "IPv%c", version);
        switch (payload_proto)
        {
            case 0x06: // TCP
                sprintf(message, "%s", "TCP");
                break;
            case 0x11: // UDP
                sprintf(message, "%s", "UDP");
                break;
            default:
                sprintf(message, "Unknown protocol (%02X)", payload_proto);
                break;
        }
    }
	else if (headers.header_llc.type) // We've gotten the 802.11 LLC header
    {
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
    }
	else // We've gotten the 802.11 frame header
    {
	    printf("This is an 802.11 frame\n");
        sprintf(protocol, "802.11");
        sprintf(message, "%s", wifi_frame_description[headers.header_80211.frame_version][headers.header_80211.frame_type][headers.header_80211.frame_subtype]);
    }

	// Write to the diagram
	fprintf(output_file, "\"%s\" -> \"%s\": T+%lldms - %s: %s\n", parsedSrcMac, parsedDstMac, gettime_ms() - start_time, protocol, message);
}

int decode_lbard(unsigned char *msg, int len, FILE *output_file, char *myAttachedMeshExtender)
{
	int areWeSending=1; //use this to see if we are sending or recieving
	int iterationTest = 1;
	int offset = 8;
	int peer_index = -1;
	while (offset < len)
	{
		/*
    Parse message and act on it.    
    */

		// All valid messages must be at least 8 bytes long.
		if (len < 8)
			return -1;
		char peer_prefix[6 * 2 + 1];
		snprintf(peer_prefix, 6 * 2 + 1, "%02x%02x%02x%02x%02x%02x",
				 msg[0], msg[1], msg[2], msg[3], msg[4], msg[5]);
		int msg_number = msg[6] + 256 * (msg[7] & 0x7f);
		int is_retransmission = msg[7] & 0x80;

		// Find or create peer structure for this.
		struct peer_state *p = NULL;
		for (int i = 0; i < peer_count; i++)
		{
			if (!strcasecmp(peer_records[i]->sid_prefix, peer_prefix))
			{
				p = peer_records[i];
				peer_index = i;
				break;
			}
		}


		if (!p)
		{
			p = calloc(1, sizeof(struct peer_state));
			for (int i = 0; i < 4; i++)
				p->sid_prefix_bin[i] = msg[i];
			p->sid_prefix = strdup(peer_prefix);
			p->last_message_number = -1;
			p->tx_bundle = -1;
			p->request_bitmap_bundle = -1;
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

		if (!is_retransmission)
			p->last_message_number = msg_number;
		int advance;
		while (offset < len)
		{
			printf("Offset: %i, len %i\n", offset, len);
			dump_packet("Packet offset", msg, len);

			iterationTest ++;
			printf("Message Type: %c - 0x%02X\n", msg[offset], msg[offset]);

			if (message_handlers[msg[offset]])
			{
				char message_description[8192];
				printf("Calling message handler for type 0x%02x @ offset 0x%x\n",
					   msg[offset], offset);
				advance = message_handlers[msg[offset]](p, peer_prefix, NULL, NULL,
														&msg[offset], len - offset, message_description);
				printf("Message description: %s\n", message_description);

				long long relative_time_ms;
				relative_time_ms = gettime_ms() - start_time;

				if (strncasecmp(msg, "LBARD:RFD900:TX:", 16))
				{
					fprintf(output_file, "%s -> BROADCAST: T+%lldms %c - %s\n", peer_prefix,
							 relative_time_ms, msg[offset], message_description);
				} else 
				{
					fprintf(output_file, "BROADCAST -> %s: T+%lldms %c - %s\n", peer_prefix,
							 relative_time_ms, msg[offset], message_description);
				}
				

				if (advance < 1)
				{
					fprintf(stderr,
							"At packet offset 0x%x, message parser 0x%02x returned zero or negative message length (=%d).\n"
							"  Assuming packet is corrupt.\n",
							offset, msg[offset], advance);
					return -1;
				}
				printf("### %s : Handler consumed %d packet bytes.\n", timestamp_str(), advance);
				offset += advance;
			}
			else
			{
				// No parser for this message type
				// invalid message field.

				char sender_prefix[128];
				char monitor_log_buf[1024];
				sprintf(sender_prefix, "%s*", p->sid_prefix);

				/*snprintf(monitor_log_buf, sizeof(monitor_log_buf),
						 "Illegal message field 0x%02X at radio packet offset %d",
						 msg[offset], offset);
				fprintf(stderr, "Illegal message type 0x%02x at offset %d\n", msg[offset], offset);*/

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
	//int fd = fileno(stdin);

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
		//get time to write to file name
		time_t rawTime;
		int bufferSize = 100;
		struct tm *timeInfo;
		time(&rawTime);
		timeInfo = localtime(&rawTime);
		char timingDiagramFileName[bufferSize];
		char *time = asctime(timeInfo);
		time[strlen(time) - 1] = 0; //remove the new line at end of time
		snprintf(timingDiagramFileName, bufferSize, "timingDiagram_%s.txt", time);
		char myAttachedMeshExtender = argv[1];

		FILE *outFile;
		outFile = fopen(timingDiagramFileName, "w"); //open file to write to
		fprintf(outFile, "@startuml\n");			 //write first line of uml file

		//init socket variables
		int sockfd, portno = args.port;

		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sockfd < 0)
		{
			perror("ERROR opening socket");
			exit(-1);
		}

		//build server's internet address
		struct sockaddr_in serv_addr, client_addr;
		memset(&serv_addr, 0, sizeof(serv_addr)); //clear struct before setting up
		memset(&client_addr, 0, sizeof(client_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr = args.address; //any source address
		serv_addr.sin_port = htons(args.port);

		//bind sockets
		if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		{
			perror("ERROR on binding");
			exit(-1);
		}

		printf("Listening at %s:%i\n", inet_ntoa(serv_addr.sin_addr), args.port);

		//make variables for reading in packets
		u_char packet[8192];

		//main while loop to accept packet
		//set starting time
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
					decode_lbard(&packet[16], bytesReceived - 16 - 32 - 1, outFile, myAttachedMeshExtender);

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

		//add final line to file
		fprintf(outFile, "@enduml");

		//run the program to create the graph
		//change the arguments to where file location is ect
		char *location = args.jarpath;
		//get current working directory as this is where the generated textural file will be saved
		char cwd[PATH_MAX];
		char command[256];
		getcwd(cwd, sizeof(cwd));

		//wait to finish writing file
		printf("writing diagram text file\n");
		fclose(outFile);

		//call program to make graph
		printf("Making diagram in: %s\n", cwd);
		snprintf(command, 256, "java -jar \'%s\' \'%s/%s\'", location, cwd, timingDiagramFileName);
		//printf("Running following command to make graph\n %s\nPlease wait - Program will finish when diagram is made\n\n", command);
		system(command);

	} while (0);

	return retVal;
}
