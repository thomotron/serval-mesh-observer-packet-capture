/*
 * File:   captureme.c
 * Author: honours
 *
 * Created on November 13, 2018, 5:53 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <termios.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

//#define test 1
#define DEFAULT_SERVER_PORT 3940

struct sockaddr_in serv_addr;
int serversock = -1;
char *myMeshExtenderID;

void dump_packet(char *msg, unsigned char *b, int n);

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
  fprintf(stderr, "Serial port settings before tcsetaddr: c=%08x, i=%08x, o=%08x, l=%08x\n",
          (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
          (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

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

  fprintf(stderr, "Serial port settings attempting to be set: c=%08x, i=%08x, o=%08x, l=%08x\n",
          (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
          (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

  tcsetattr(fd, TCSANOW, &t);

  tcgetattr(fd, &t);
  fprintf(stderr, "Serial port settings after tcsetaddr: c=%08x, i=%08x, o=%08x, l=%08x\n",
          (unsigned int)t.c_cflag, (unsigned int)t.c_iflag,
          (unsigned int)t.c_oflag, (unsigned int)t.c_lflag);

  set_nonblock(fd);

  return 0;
}

int record_rfd900_rx_event(struct serial_port *sp, unsigned char *packet, int len)
{
  int retVal = 0;

  do
  {
    char message[1024] = "LBARD:RFD900:RX:";
    char first_bytes_hex[16];

    printf("Current string: %s", message);

    int offset = strlen(message);
    memcpy(&message[offset], packet, len);
    offset += len;
    message[offset++] = '\n';
    message[offset++]=0;

    if (!start_time)
      start_time = gettime_ms();
    printf("T+%lldms: Before sendto of RFD900 packet\n", gettime_ms() - start_time);

    /*//used to see if the Mesh Extender has sent or recieved a packet
    char peer_prefix[6 * 2 + 1];
    snprintf(peer_prefix, 6 * 2 + 1, "%02x%02x%02x%02x%02x%02x",
             msg[0], msg[1], msg[2], msg[3], msg[4], msg[5]);*/

    errno = 0;
    int n = sendto(serversock, message, offset, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    printf("Size Written %i using %p\n", offset, sp);
    if (n < 0)
    {
      perror("Error Sending");
      retVal = -7;
      break;
    }
    //fflush(outFile);
    printf("Send to server socket\n\n");
    message[0] = '\0'; // set the string to a zero length
  } while (0);

  return retVal;
}

int record_rfd900_tx_event(struct serial_port *sp)
{
  int retVal = 0;

  do
  {
    char message[1024] = "LBARD:RFD900:TX:";
    char first_bytes_hex[16];

    snprintf(first_bytes_hex, 16, "%02X%02X%02X%02X%02X%02X",
             sp->tx_buff[0], sp->tx_buff[1],
             sp->tx_buff[2], sp->tx_buff[3],
             sp->tx_buff[4], sp->tx_buff[5]);


    printf("Current string: %s", message);

    int offset = strlen(message);
    memcpy(&message[offset], sp->tx_buff, sp->tx_bytes);
    offset += sp->tx_bytes;
    message[offset++] = '\n';

    if (!start_time)
      start_time = gettime_ms();
    printf("T+%lldms: Before sendto of RFD900 packet\n", gettime_ms() - start_time);

    /*//used to see if the Mesh Extender has sent or recieved a packet
    char peer_prefix[6 * 2 + 1];
    snprintf(peer_prefix, 6 * 2 + 1, "%02x%02x%02x%02x%02x%02x",
             msg[0], msg[1], msg[2], msg[3], msg[4], msg[5]);*/

    errno = 0;
    int n = sendto(serversock, message, offset, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    printf("Size Written %i using %p\n", offset, sp);
    if (n < 0)
    {
      perror("Error Sending");
      retVal = -7;
      break;
    }
    //fflush(outFile);
    printf("Send to server socket\n\n");
    message[0] = '\0'; // set the string to a zero length
  } while (0);

  return retVal;
}

int setup_monitor_port(char *path, int speed)
{
  int retVal = 0;

  do
  {
    if (serial_port_count >= MAX_PORTS)
    {
      fprintf(stderr, "Too many serial ports. (Increase MAX_PORTS?)\n");
      retVal = -3;
      break;
    }

    //open serial port
    int r1 = open(path, O_RDONLY | O_NOCTTY | O_NDELAY);
    if (r1 == -1)
    {
      fprintf(stderr, "Failed to open serial port '%s'\n", path);
      retVal = -3;
      break;
    }

    serial_ports[serial_port_count].fd = r1;
    serial_ports[serial_port_count].port = strdup(path);
    serial_ports[serial_port_count].id = serial_port_count;
    serial_ports[serial_port_count].rfd900_tx_count = 0;
    serial_ports[serial_port_count].rfd900_rx_count = 0;
    serial_ports[serial_port_count].tx_state = 0;
    serial_ports[serial_port_count].tx_bytes = 0;

    //set non blocking for the serial ports for continous loop
    set_nonblock(r1);

    //set serial port speeds
    serial_setup_port_with_speed(r1, speed);

    printf("Initialised '%s' as serial port %d\n", path, serial_port_count);

    serial_port_count++;

  } while (0);
  return retVal;
}

int process_serial_char(struct serial_port *sp, unsigned char c)
{
  int retVal = 0;

  do
  {

    if (sp->rx_bytes >= 1024 )
    {
      // shift RX bytes down
      memmove(&sp->rx_buff[0],&sp->rx_buff[1],1023);
      
      sp->rx_bytes--;
    }
    sp->rx_buff[sp->rx_bytes++]=c;
    
    if ((sp->rx_buff[sp->rx_bytes-1]==0x55)
	&&(sp->rx_buff[sp->rx_bytes-8]==0x55)
	&&(sp->rx_buff[sp->rx_bytes-9]==0xaa))
    {
       int packet_bytes=sp->rx_buff[sp->rx_bytes-4];
       int offset=sp->rx_bytes-9-packet_bytes;
       if (offset>=0) {
       unsigned char *packet=&sp->rx_buff[offset];
       printf("Saw RFD900 RX envelope for %d byte packet @ offset %d.\n",
              packet_bytes,offset);
       record_rfd900_rx_event(sp,packet,packet_bytes);
       sp->rfd900_rx_count++;
       }
    }
    
    if (sp->tx_state == 0)
    {
      // Not in ! escape mode
      if (c == '!')
        sp->tx_state = 1;
      else
      {
        if (sp->tx_bytes < 1024)
          sp->tx_buff[sp->tx_bytes++] = c;
      }
    }
    else
    {
      switch (c)
      {
      case '!':
        // Double ! = TX packet
        printf("Recognised TX of %d byte packet.\n", sp->tx_bytes);
        dump_packet("sent packet", sp->tx_buff, sp->tx_bytes);

        record_rfd900_tx_event(sp);

        sp->rfd900_tx_count++;
        sp->tx_bytes = 0;
        break;
      case '.':
        // Escaped !
        if (sp->tx_bytes < 1024)
          sp->tx_buff[sp->tx_bytes++] = '!';
        break;
      case 'c':
      case 'C':
        // Flush TX buffer
        sp->tx_bytes = 0;
        break;
      default:
        // Some other character we don't know what to do with
        break;
      }
      sp->tx_state = 0;
    }
  } while (0);

  return retVal;
}

int process_serial_port(struct serial_port *sp)
{
  int i;
  int retVal = 0;
  int bytes_read;
  unsigned char buffer[128]; // small buffer, so we round-robin among the ports more often
  do
  {
    bytes_read = read(sp->fd, buffer, sizeof(buffer));

    if (bytes_read > 0)
    {
      dump_packet("read", buffer, bytes_read);
      printf("Read Size: %i\n", bytes_read);
      for (i = 0; i < bytes_read; i++)
        process_serial_char(sp, buffer[i]);
    }
  } while (0);

  return retVal;
}

void dump_packet(char *msg, unsigned char *b, int n)
{
  printf("%s: Displaying %d bytes.\n", msg, n);
  int i;
  for (i = 0; i < n; i += 16)
  {
    int j;
    printf("%08X : ", i);
    for (j = 0; j < 16 && (i + j) < n; j++)
      printf("%02X ", b[i + j]);
    for (; j < 16; j++)
      printf("   ");
    for (j = 0; j < 16 && (i + j) < n; j++)
      if (b[i + j] >= ' ' && b[i + j] < 0x7f)
        printf("%c", b[i + j]);
      else
        printf(".");
    printf("\n");
  }
}

int main(int argc, char **argv)
{
  int retVal = 0;

  // Check arg count and print usage
  if (argc < 3)
  {
      printf("Usage: %s <sid> <address> [port]\n", argv[0]);
      exit(1);
  }

  // Get our SID
  myMeshExtenderID = argv[1];

  // Parse address
  struct in_addr address;
  if (!inet_aton(argv[2], &address))
  {
      fprintf(stderr, "Invalid address \"%s\"\n", argv[2]);
      exit(1);
  }

  // Parse optional port
  int port = argc >= 4 ? *argv[3] : DEFAULT_SERVER_PORT;

  do
  {
    printf("Before variable deration\n");
    //setup wireless capture settings
    char *dev = "mon0";
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // hold compiled libpcap filter program
    pcap_t *handle;
    struct pcap_pkthdr header;
    int serverlen;
    int timeout = 10, sockfd, n;
    FILE *outFile = fopen("testFile", "ab"); // append to file only
    bpf_u_int32 maskp;                       // subnet mask
    bpf_u_int32 ip;                          //ip
    printf("My Mesh Extender ID is: %s\n", myMeshExtenderID);

    char pcapFilterString[] = "ether host E2:95:6E:4C:A8:D7";

    printf("Before packet injection setup\n");
    //setup packet injection - source used: https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/udpclient.c
    u_char *capPacket;
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = address;
    serv_addr.sin_port = htons(port);
    char hbuf[NI_MAXHOST];
    socklen_t len = sizeof(struct sockaddr_in);

    //setup sockets
    printf("Before socket setup\n");
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
      perror("Error setting up socket\n");
      retVal = -2;
      return (retVal);
    }
    else
    {
        printf("Will send data to %s:%i\n", inet_ntoa(serv_addr.sin_addr), port);
    }

    serversock = sockfd;

#ifdef test
    if (getnameinfo((struct sockaddr *)&serv_addr, len, hbuf, sizeof(hbuf), NULL, 0, 0))
    {
      printf("could not resolve IP\n");
      retVal = -1;
      return (retVal);
    }
    else
    {
      printf("host=%s\n", hbuf);
    }
    serverlen = sizeof(serv_addr);
#endif

    printf("Before serial port setup\n");

    // Setup radio serial port
    if (setup_monitor_port("/dev/ttyATH0", 230400) < 0)
    {
        // Exit if we don't have a serial port to read from
        exit(1);
    }

#ifdef WITH_PCAP
    printf("Before pcap setup\n");

    pcap_lookupnet(dev, &ip, &maskp, errbuf);

    //open handle for wireless device
    handle = pcap_open_live(dev, BUFSIZ, 1, timeout, errbuf);
    if (handle == NULL)
    {
      printf("Error starting pcap device: %s\n", errbuf);
    }

    if (pcap_compile(handle, &fp, pcapFilterString, 0, ip) == -1)
    {
      printf("Bad filter - %s\n", pcap_geterr(handle));
      retVal = -8;
      break;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
      fprintf(stderr, "Error setting filter\n");
      retVal = -8;
      break;
    }
#endif
    // While loop that serially searches for a packet to be captured by all devices (round robin)

    printf("Before loop\n");
    do
    {
      int i;
      for (i = 0; i < serial_port_count; i++)
        process_serial_port(&serial_ports[i]);

      /*header.len = 0;
            header.caplen = 0;
            capPacket = pcap_next(handle, &header);
            if (header.len > 0)
            {
                printf("Captured WIFI packet total length %i\n", header.len);
                n = sendto(sockfd, capPacket, header.len, 0, (struct sockaddr *)&serv_addr, serverlen);
                //dump_packet("Captured Packet", capPacket, n);
                printf("Size Written %i\n", n);
                if (n < 0)
                {
                    perror("Error Sending\n");
                    retVal = -11;
                    perror("Sendto: ");
                    break;
                }
            }*/
    } while (1);

    printf("Closing output file.\n");
    //close opened file
    fclose(outFile);

  } while (0);

  return (retVal);
}
