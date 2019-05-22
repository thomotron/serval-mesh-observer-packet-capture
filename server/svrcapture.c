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

#include "sync.h"
#include "lbard.h"
#include "message_handlers.h"

#define MAX_PACKET_SIZE 255
#define RADIO_RXBUFFER_SIZE 64 + MAX_PACKET_SIZE

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

char decode_wifi(unsigned char *packet, int len)
{
	char decodedString[15];
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t srcMac[6];
	uint8_t dstMac[6];
	uint16_t seq_ctrl;

	printf("\n\n WIFI PACKET \n");
	//check if big or little endin

	printf("Before bit shift\n");
	frame_control = (packet[0] >> 4) & 0x03; //bit shift to get the bits we want

	//copy in mac addresses
	for (int i = 0; i < 6; i++)
	{
		srcMac[i] = packet[i + 4];
		dstMac[i] = packet[i + 10];
	}

	dump_packet("Packet contents", packet, len);

	printf("src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
	printf("dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5]);

	printf("Before making string\n");
	//snprintf(decodedString, sizeof(decodedString), "Src MAC:%s Dst MAC:%s", packetHeader.addr1, packetHeader.addr2);

	//ARP has mac address destination of 00:00:00:00:00:00

	char test[] = "this is a test";
	printf("%s", test);
	return decodedString;
}

int decode_lbard(unsigned char *msg, int len, char *returnString)
{
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

		strcat(returnString, peer_prefix);
		printf("\nBuilt String: %s\n", returnString);

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
			printf("Message Type: %c - 0x%02X\n", msg[offset], msg[offset]);

			if (message_handlers[msg[offset]])
			{
				char message_description[8192];
				printf("Calling message handler for type 0x%02x @ offset 0x%x\n",
					   msg[offset], offset);
				advance = message_handlers[msg[offset]](p, peer_prefix, NULL, NULL,
														&msg[offset], len - offset, message_description);
				printf("Message description: %s\n", message_description);
				/*if (strstr(message_description, "Illegal message") != NULL)
				{
					snprintf(returnString, 8000, "%s -> BROADCAST: %c : %s\n", peer_prefix,
							 msg[offset], "Error parsing rest of message");
				}
				else*/
				{
					long long relative_time_ms;
					relative_time_ms = gettime_ms() - start_time;

					snprintf(returnString, 8190, "%s -> BROADCAST: T+%lldms %c - %s\n", peer_prefix,
							relative_time_ms, msg[offset], message_description);
				}
				printf("CURRENT STRING: %s", returnString);
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
	int retVal;
	//int fd = fileno(stdin);

	do
	{
		//set up file for writing captured packet info

		//get time to write to file name
		time_t rawTime;
		int bufferSize = 100;
		struct tm *timeInfo;
		time(&rawTime);
		timeInfo = localtime(&rawTime);
		char timingDiagramFileName[bufferSize];
		char *time = asctime(timeInfo);
		time[strlen(time) - 1] = 0; //remove the new line at end of time
		snprintf(timingDiagramFileName, bufferSize, "timingDiagram: %s.txt", time);

		FILE *outFile;
		outFile = fopen(timingDiagramFileName, "w"); //open file to write to
		fprintf(outFile, "@startuml\n");			 //write first line of uml file

		//init socket variables
		int sockfd, portno = 3940;

		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sockfd < 0)
		{
			perror("ERROR opening socket");
			exit(-1);
		}

		//build server's internet address
		struct sockaddr_in serv_addr, cliaddr;
		memset(&serv_addr, 0, sizeof(serv_addr)); //clear struct before setting up
		memset(&cliaddr, 0, sizeof(cliaddr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = INADDR_ANY; //any source address
		serv_addr.sin_port = htons(portno);

		//bind sockets
		if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		{
			perror("ERROR on binding");
			exit(-1);
		}

		//make variables for reading in packets
		u_char packet[8192];

		//main while loop to accept packet
		int i;
		char wifiPacketInfo;

		for (i = 0; i < 10; i++)
		{
			//memset(&buffer, 0, 500);
			//printf("Waiting for packet to read\n");
			int n;
			unsigned int len;
			n = 0;
			while (!n)
			{
				n = recvfrom(sockfd, packet, 8192, MSG_DONTWAIT, (struct sockaddr *)&cliaddr, &len);
				if (!n)
				{
					usleep(100000);
					printf(".");
					fflush(stdout);
				}
				if (errno == EAGAIN)
					n = 0;
				if (errno)
				{
					if (errno != EAGAIN)
					{
						perror("recvfrom() says");
					}
					errno = 0;
				}
			}
			if (n < 0)
			{
				perror("ERROR in recieving packet\n");
				retVal = 1;
				break;
			}
			//decide if Wi-Fi packet or LABRD packet
			if (packet[0] == 'L' &&
				packet[1] == 'B' &&
				packet[2] == 'A' &&
				packet[3] == 'R' &&
				packet[4] == 'D')
			{
				if (sizeof(packet) > 5)
				{
					char lbardResult[8192];
					decode_lbard(&packet[16], n - 16, lbardResult); //16 byte offset before analysis to remove packet header
					printf("\n%s\n", lbardResult);
					fprintf(outFile, "%s", lbardResult);
					//break;
					lbardResult[0] = '\0';
				}
			}
			else //if not lbard packet, is wifi packet
			{
				//decode wifi packet and put returned string into NTD text file
				wifiPacketInfo = decode_wifi(&packet, n);
				fprintf(outFile, wifiPacketInfo);
				wifiPacketInfo = '\0';
			}
			packet[0] = '\0'; // set the string to a zero length
		}

		//add final line to file
		fprintf(outFile, "@enduml");

		//run the program to create the graph
		//change the arguments to where file location is ect
		char *location = "/home/honours/Desktop/MeshObserver-Packet-Capture/server/plantuml.jar";
		//get current working directory as this is where the generated textural file will be saved
		char cwd[PATH_MAX];
		char command[256];
		getcwd(cwd, sizeof(cwd));

		//wait to finish writing file
		printf("writing diagram text file\n");
		fclose(outFile);

		//call program to make graph
		printf("Making diagram in: %s", cwd);
		snprintf(command, 256, "java -jar \'%s\' \'%s/%s\'", location, cwd, timingDiagramFileName);
		printf("Running following command to make graph\n %s\nPlease wait - Program will finish when diagram is made\n\n", command);
		system(command);

	} while (0);

	return retVal;
}
