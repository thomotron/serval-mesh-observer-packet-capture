#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <termios.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <argp.h>

#define DEFAULT_SERVER_PORT 3940
#define DEFAULT_PCAP_DEV "mon0"
#define DEFAULT_PCAP_FILTER ""
#define PCAP_FILE "testFile"

// The number of mandatory arguments and a string containing them in the correct order delimited by spaces
#define NUM_MANDATORY_ARGS 1
static char argument_doc[] = "ADDRESS";

// List our arguments for argp
static struct argp_option options[] =
{
        {"port",    'p', "port",    0,                   "Server port"},
        {"wifidev", 'd', "wifidev", 0,                   "Wi-Fi capture device"},
        {"filter",  'f', "filter",  0,                   "Pcap filter for Wi-Fi packets"},
        {"nouhf",    1,  "nouhf",   OPTION_ARG_OPTIONAL, "Disables UHF LBARD capture"},
        {"nowifi",   2,  "nowifi",  OPTION_ARG_OPTIONAL, "Disables Wi-Fi packet capture"},
        {0}
};

// Define a struct to hold our arg values
typedef struct arguments
{
    struct in_addr address;
    int            port;
    char*          wifidev;
    char*          filter;
    unsigned char  uhfCapture;
    unsigned char  wifiCapture;
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
            arguments->port = (int) strtol(arg, NULL, 10);
            break;
        case 'd':
            // Set the Wi-Fi device name
            arguments->wifidev = arg;
            break;
        case 'f':
            // Set the pcap filter string
            arguments->filter = arg;
            break;
        case 1:
            // Check if Wi-Fi capture is already disabled and print an error
            if (!arguments->wifiCapture)
            {
                printf("Cannot disable both UHF and Wi-Fi capture at the same time\n");
                argp_usage(state);
            }

            // Disable UHF capture
            arguments->uhfCapture = 0;
            break;
        case 2:
            // Check if Wi-Fi capture is already disabled and print an error
            if (!arguments->uhfCapture)
            {
                printf("Cannot disable both UHF and Wi-Fi capture at the same time\n");
                argp_usage(state);
            }

            // Disable Wi-Fi capture
            arguments->wifiCapture = 0;
            break;
        case ARGP_KEY_ARG:
            // Check if we have too many args
            if (state->arg_num >= NUM_MANDATORY_ARGS) argp_usage(state);

            // Parse and set the server address, printing usage on failure
            if (state->arg_num == 0 && !inet_aton(arg, &arguments->address)) argp_usage(state);
            break;
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

struct sockaddr_in serv_addr;
int server_socket = -1;

void dump_packet(char *msg, unsigned char *buffer, int n);

struct serial_port
{
    int fd;
    int rfd900_tx_count;
    int rfd900_rx_count;

    char *port;
    int id;

    // For !! tx mode, here is the accumulated transmitted packet
    unsigned char tx_buff[1024];
    int tx_bytes;
    int tx_state;

    // For RX mode, we look for the envelope our RFD900 firmware puts following a received packet
    unsigned char rx_buff[1024];
    int rx_bytes;
};

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

#define MAX_PORTS 16
struct serial_port serial_ports[MAX_PORTS];
int serial_port_count = 0;

int set_nonblock(int fd)
{
    int retVal = 0;

    do
    {
        if (fd == -1)
            break;

        int flags;
        if ((flags = fcntl(fd, F_GETFL, NULL)) == -1)
        {
            perror("fcntl");
            printf("set_nonblock: fcntl(%d,F_GETFL,NULL)", fd);
            retVal = -1;
            break;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            perror("fcntl");
            printf("set_nonblock: fcntl(%d,F_SETFL,n|O_NONBLOCK)", fd);
            return -1;
        }
    } while (0);
    return retVal;
}

int serial_setup_port_with_speed(int fd, int speed)
{
    struct termios t;

    tcgetattr(fd, &t);
    //fprintf(stderr, "Serial port settings before tcsetaddr: c=%08x, i=%08x, o=%08x, l=%08x\n",
    //        (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
    //        (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

    speed_t baud_rate;
    switch (speed)
    {
        case 115200:
            baud_rate = B115200;
            break;
        case 230400:
            baud_rate = B230400;
            break;
    }

    // XXX Speed and options should be configurable
    if (cfsetospeed(&t, baud_rate))
        return -1;
    if (cfsetispeed(&t, baud_rate))
        return -1;

    // 8N1
    t.c_cflag &= ~PARENB;
    t.c_cflag &= ~CSTOPB;
    t.c_cflag &= ~CSIZE;
    t.c_cflag |= CS8;
    t.c_cflag |= CLOCAL;

    t.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO | ECHOE);
    //Noncanonical mode, disable signals, extended
    //input processing, and software flow control and echoing

    t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR |
                   INPCK | ISTRIP | IXON | IXOFF | IXANY | PARMRK);
    //Disable special handling of CR, NL, and BREAK.
    //No 8th-bit stripping or parity error handling.
    //Disable START/STOP output flow control.

    // Disable CTS/RTS flow control
#ifndef CNEW_RTSCTS
    t.c_cflag &= ~CRTSCTS;
#else
    t.c_cflag &= ~CNEW_RTSCTS;
#endif

    // no output processing
    t.c_oflag &= ~OPOST;

    //fprintf(stderr, "Serial port settings attempting to be set: c=%08x, i=%08x, o=%08x, l=%08x\n",
    //        (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
    //        (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

    tcsetattr(fd, TCSANOW, &t);

    tcgetattr(fd, &t);
    //fprintf(stderr, "Serial port settings after tcsetaddr: c=%08x, i=%08x, o=%08x, l=%08x\n",
    //        (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
    //        (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

    set_nonblock(fd);

    return 0;
}

int record_rfd900_event(struct serial_port *sp, unsigned char *packet, int len, char* type)
{
    int retVal = 0;

    do
    {
        char message[1024 + 16 + 2]; // 1024-byte max packet length + 16-byte header + 2-byte newline & null-terminator

        // Write the header to the message buffer
        sprintf(message, "LBARD:RFD900:%s:", type);

        // Write the packet contents to the message buffer and terminate it
        int offset = strlen(message);
        memcpy(&message[offset], packet, len);
        offset += len;
        message[offset++] = '\n';
        message[offset++] = 0;

        // Set up the start time if it hasn't been already
        if (!start_time)
            start_time = gettime_ms();

        // Try writing the message to the server socket
        errno = 0;
        printf("T+%lldms: Writing %i bytes to the server socket from serial port %p\n", gettime_ms() - start_time, offset, sp);
        if (sendto(server_socket, message, offset, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("Error sending");
            retVal = -7;
            break;
        }
        else
        {
            printf("Sent successfully\n\n");
        }
    } while (0);

    return retVal;
}

int setup_monitor_port(char *path, int speed)
{
    int retVal = 0;

    do
    {
        // Make sure we're not registering more ports than we're designed to
        if (serial_port_count >= MAX_PORTS)
        {
            fprintf(stderr, "Too many serial ports. (Increase MAX_PORTS?)\n");
            retVal = -3;
            break;
        }

        // Open the serial port
        int r1 = open(path, O_RDONLY | O_NOCTTY | O_NDELAY);
        if (r1 == -1)
        {
            fprintf(stderr, "Failed to open serial port '%s'\n", path);
            retVal = -3;
            break;
        }

        // Set up a new struct for the this serial port
        serial_ports[serial_port_count].fd = r1;
        serial_ports[serial_port_count].port = strdup(path);
        serial_ports[serial_port_count].id = serial_port_count;
        serial_ports[serial_port_count].rfd900_tx_count = 0;
        serial_ports[serial_port_count].rfd900_rx_count = 0;
        serial_ports[serial_port_count].tx_state = 0;
        serial_ports[serial_port_count].tx_bytes = 0;

        // Set this serial port to non-blocking mode to make reading easier
        set_nonblock(r1);

        // Set the serial port speed
        serial_setup_port_with_speed(r1, speed);

        printf("Initialised '%s' as serial port %d\n", path, serial_port_count);

        // Increment the number of serial ports we have configured
        serial_port_count++;
    } while (0);

    return retVal;
}

int process_serial_char(struct serial_port *sp, unsigned char c)
{
    int retVal = 0;

    do
    {
        // Check if the buffer is full
        if (sp->rx_bytes >= 1024)
        {
            // Shift bytes left by one
            memmove(&sp->rx_buff[0],&sp->rx_buff[1],1023);

            // Decrement the number of bytes in the buffer
            sp->rx_bytes--;
        }

        // Place the character at the end of the buffer and increment the byte count
        sp->rx_buff[sp->rx_bytes++] = c;

        // Check if the buffer ends with an RFD900 envelope
        if ((sp->rx_buff[sp->rx_bytes - 1] == 0x55) &&
            (sp->rx_buff[sp->rx_bytes - 8] == 0x55) &&
            (sp->rx_buff[sp->rx_bytes - 9] == 0xaa))
        {
            // Get the packet length from the envelope
            int packet_bytes = sp->rx_buff[sp->rx_bytes - 4];

            // Get the offset for the start of the packet
            int offset = sp->rx_bytes - 9 - packet_bytes;
            if (offset >= 0) {
                printf("Got RFD900 RX envelope for %d byte packet at offset %d.\n", packet_bytes, offset);

                // Send the packet to the server
                record_rfd900_event(sp, &sp->rx_buff[offset], packet_bytes, "RX");

                // Increment the number of RX packets we've seen
                sp->rfd900_rx_count++;
            }
        }

        // Check the escape character flag to see if the last character was a '!'
        if (sp->tx_state == 0)
        {
            // Is this a possible TX escape character?
            if (c == '!')
            {
                // Set the escape character flag so we can interpret the sequence on the next pass
                sp->tx_state = 1;
            }
            else
            {
                // If the TX buffer is not full yet, append the character to the end of the TX buffer
                if (sp->tx_bytes < 1024) sp->tx_buff[sp->tx_bytes++] = c;
            }
        }
        else
        {
            // Check what character is being escaped
            switch (c)
            {
                case '!': // '!!' = TX packet
                    printf("Recognised TX of %d byte packet.\n", sp->tx_bytes);
                    dump_packet("Outgoing packet dump", sp->tx_buff, sp->tx_bytes);

                    // Send the packet to the server
                    record_rfd900_event(sp, sp->tx_buff, sp->tx_bytes, "TX");

                    // Increment the number of TX packets we have seen and reset the buffer offset
                    sp->rfd900_tx_count++;
                    sp->tx_bytes = 0;
                    break;
                case '.': // '!.' = Escaped '!'
                    // If the TX buffer is not full yet, append the character to the end of the TX buffer
                    if (sp->tx_bytes < 1024) sp->tx_buff[sp->tx_bytes++] = '!';
                    break;
                case 'c':
                case 'C': // '!c' or '!C' = Flush TX buffer
                    sp->tx_bytes = 0;
                    break;
                default: // Some other character we don't know what to do with
                    break;
            }

            // Reset the escape character flag
            sp->tx_state = 0;
        }
    } while (0);

    return retVal;
}

int process_serial_port(struct serial_port *sp)
{
    int retVal = 0;

    do
    {
        unsigned char buffer[128]; // Use a small buffer so we round-robin among the ports more often
        int bytes_read = read(sp->fd, buffer, sizeof(buffer)); // Read bytes from the serial port into the buffer

        if (bytes_read > 0)
        {
            // Dump the packet
            dump_packet("Incoming packet dump", buffer, bytes_read);

            // Process each character sequentially
            for (int i = 0; i < bytes_read; i++)
                process_serial_char(sp, buffer[i]);
        }
    } while (0);

    return retVal;
}

void dump_packet(char *msg, unsigned char *buffer, int n)
{
    printf("%s: Displaying %d bytes.\n", msg, n);
    for (int offset = 0; offset < n; offset += 16)
    {
        // Print the offset
        printf("%08X : ", offset);

        // Print a line of 16 bytes
        int j;
        for (j = 0; j < 16; j++)
        {
            // Check if there are more bytes available
            if ((offset + j) < n)
                // Print the next byte
                printf("%02X ", buffer[offset + j]);
            else
                // Pad the missing byte
                printf("   ");
        }

        // Print an ASCII representation of the line
        for (j = 0; j < 16 && (offset + j) < n; j++)
            if (buffer[offset + j] >= ' ' && buffer[offset + j] < 0x7f)
                printf("%c", buffer[offset + j]);
            else
                printf(".");
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    int retVal = 0;

    // Define args struct and populate simple defaults
    arguments args;
    args.port = DEFAULT_SERVER_PORT;
    args.wifidev = DEFAULT_PCAP_DEV;
    args.filter = DEFAULT_PCAP_FILTER;
    args.uhfCapture = 1;
    args.wifiCapture = 1;

    // Parse command line args
    argp_parse(&argp_parser, argc, argv, 0, 0, &args);

    do
    {
        FILE *outFile = fopen(PCAP_FILE, "ab"); // Open file in append-only mode

        // Define up wireless capture variables
        char *wifi_dev = args.wifidev;
        char pcap_errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program pcap_filter; // Compiled libpcap filter program
        pcap_t *pcap_handle;
        struct pcap_pkthdr pcap_packet_header;
        int timeout = 10, n;
        bpf_u_int32 maskp; // Subnet mask
        bpf_u_int32 ip; // IP address

        // Set up UDP socket variables
        // (derived from https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/udpclient.c)
        // Clear out the server address struct and populate it from config
        u_char *capPacket; // Outgoing UDP packet buffer
        bzero((char *)&serv_addr, sizeof(serv_addr)); // Clear out the server address struct
        serv_addr.sin_family = AF_INET; // Address family (IPv4)
        serv_addr.sin_addr = args.address; // Server IP address
        serv_addr.sin_port = htons(args.port); // Server port

        // Set up the UDP socket
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            perror("Error setting up socket\n");
            retVal = -2;
            return (retVal);
        }
        else
        {
            printf("Will send data to %s:%i\n", inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));
        }
        server_socket = sockfd;

        if (args.uhfCapture)
        {
            // Set up serial ports
            // Start with them all on same speed, so that we can figure out
            // which pairs of ports that are connected to the same wire.
            setup_monitor_port("/dev/ttyUSB0", 230400);
            setup_monitor_port("/dev/ttyUSB1", 230400);
            setup_monitor_port("/dev/ttyUSB2", 230400);
            setup_monitor_port("/dev/ttyUSB3", 230400);

            // Wait for input on one and see if the same character appears on another very soon there after
            // This assumes that there is traffic on at least one of the ports. If not, then there is
            // nothing to collect anyway.
            int links_setup = 0;
            while (links_setup == 0)
            {
                char buff[1024];
                int i = 0;
                for (; i < 4; i++)
                {
                    int n = read(serial_ports[i].fd, buff, 1024);
                    if (n > 0)
                    {
                        // We have some input, so now let's look for it on the other ports.
                        // But give the USB serial adapters time to catch up, as they frequently
                        // have 16ms of latency. We allow 50ms here to be safe.
                        usleep(50000);
                        char buff2[1024];
                        int j = 0;
                        for (; j < 4; j++)
                        {
                            // Don't look for the data on ourselves
                            if (i == j)
                                continue;

                            int n2 = read(serial_ports[j].fd, buff2, 1024);
                            if (n2 >= n && !bcmp(buff, buff2, n))
                            {
                                printf("Serial ports %d and %d seem to be linked.\n", i, j);

                                // Set one of those to 115200, and then one of the other two ports to 115200,
                                // and then we should have both speeds on both ports available
                                serial_setup_port_with_speed(serial_ports[i].fd, 115200);
                                int k = 0;
                                for (; k < 4; k++)
                                {
                                    if (k == i)
                                        continue;
                                    if (k == j)
                                        continue;
                                    serial_setup_port_with_speed(serial_ports[k].fd, 115200);
                                    links_setup = 1;
                                    break;
                                }
                            }
                        }
                    }
                }

                // Wait a little while before trying again
                usleep(50000);
            }
        }

        if (args.wifiCapture)
        {
            // Lookup the IP address and netmask for the Wi-Fi device
            pcap_lookupnet(wifi_dev, &ip, &maskp, pcap_errbuf);

            // Open the Wi-Fi interface
            pcap_handle = pcap_open_live(wifi_dev, BUFSIZ, 1, timeout, pcap_errbuf);
            if (pcap_handle == NULL)
            {
                printf("Error starting pcap device: %s\n", pcap_errbuf);
            }

            // Set non-blocking mode
            if (pcap_setnonblock(pcap_handle, 1, pcap_errbuf))
            {
                printf("Error setting pcap device to non-blocking: %s\n", pcap_errbuf);
            }

            // Compile the filter
            if (pcap_compile(pcap_handle, &pcap_filter, args.filter, 0, ip) == -1)
            {
                printf("Bad filter - %s\n", pcap_geterr(pcap_handle));
                printf("For more information on pcap filters, see 'man pcap-filter' or https://www.tcpdump.org/manpages/pcap-filter.7.html\n");
                retVal = -8;
                break;
            }

            // Apply the filter
            if (pcap_setfilter(pcap_handle, &pcap_filter) == -1)
            {
                fprintf(stderr, "Error setting filter\n");
                retVal = -8;
                break;
            }
        }

        // Search for packets on each serial device in a round-robin manner (and also Wi-Fi if enabled)
        do
        {
            if (args.uhfCapture)
            {
                // Iterate over each serial device and read from them
                for (int i = 0; i < serial_port_count; i++)
                {
                    process_serial_port(&serial_ports[i]);
                }
            }

            if (args.wifiCapture)
            {
                // Try capturing Wi-Fi traffic
                pcap_packet_header.len = 0;
                pcap_packet_header.caplen = 0;
                capPacket = pcap_next(pcap_handle, &pcap_packet_header);
                if (capPacket && pcap_packet_header.len > 0)
                {
                    printf("Captured WIFI packet total length %i\n", pcap_packet_header.len);
                    n = sendto(sockfd, capPacket, pcap_packet_header.len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
                    //dump_packet("Captured Packet", capPacket, n);
                    printf("Size Written %i\n", n);
                    if (n < 0)
                    {
                        perror("Error Sending\n");
                        retVal = -11;
                        perror("Sendto: ");
                        break;
                    }
                }
            }
        } while (1);

        // Close the output file
        fclose(outFile);
    } while (0);

    return (retVal);
}
