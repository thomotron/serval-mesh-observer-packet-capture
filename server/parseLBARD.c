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

#define MAX_PEERS 1024
#define MAX_BUNDLES 10000
#define FLAG_NO_RANDOMIZE_REDIRECT_OFFSET 1
#define FLAG_NO_HARD_LOWER 8
#define BAR_LENGTH (8 + 8 + 4 + 1)

int peer_count = 0;
extern unsigned char my_sid[32];
int debug_bitmap = 0;
int cached_body_len = 0;
int cached_manifest_encoded_len = 0;
unsigned char my_sid[32];
int bundle_count;
unsigned int option_flags = 0;
int debug_ack = 0;
unsigned char *cached_manifest = NULL;
int cached_manifest_len = 0;
unsigned char *cached_body = NULL;
long long cached_version = 0;
char *bid_of_cached_bundle = NULL;
unsigned char *cached_manifest_encoded = NULL;
char *my_sid_hex;
char timestamp_str_out[1024];

void error(char *msg)
{
    perror(msg);
    exit(1);
}

struct peer_state
{
    char *sid_prefix;
    unsigned char sid_prefix_bin[4];

    // random 32 bit instance ID, used to work out when LBARD has died and restarted
    // on a peer, so that we can restart the sync process.
    unsigned int instance_id;

    unsigned char *last_message;
    time_t last_message_time;
    // if last_message_time is more than this many seconds ago, then they aren't
    // considered an active peer, and are excluded from rhizome rank calculations
    // and various other things.
    int last_message_number;

    time_t last_timestamp_received;

    // Used to log RSSI of receipts from this sender, so that we can show in the stats display
    int rssi_accumulator;
    int rssi_counter;
    // Used to show number of missed packets in the stats display
    int missed_packet_count;

    // Enough for 2 packets per second for a full minute
#define RSSI_LOG_SIZE 120
    int rssi_log_count;
    int recent_rssis[RSSI_LOG_SIZE];
    long long recent_rssi_times[RSSI_LOG_SIZE];

#ifdef SYNC_BY_BAR
    // BARs we have seen from them.
    int bundle_count;
#define MAX_PEER_BUNDLES 100000
    int bundle_count_alloc;
    char **bid_prefixes;
    long long *versions;
    unsigned char *size_bytes;
    unsigned char *insert_failures;
#else

    // Bundle we are currently transfering to this peer
    int tx_bundle;
    int tx_bundle_priority;
    int tx_bundle_manifest_offset;
    int tx_bundle_body_offset;

    // These get set to offsets provided in an ACK('A') packet,
    // so that we avoid resending stuff that has been definitively acknowledged by
    // the recipient.  The values from the ACK are written directly in here, so that
    // if a problem does arise, the recipient can move the ACK point backwards if
    // required
    int tx_bundle_manifest_offset_hard_lower_bound;
    int tx_bundle_body_offset_hard_lower_bound;

    // number of http fetch errors for a manifest/payload we tolerate, before
    // discarding this bundle and trying to send the next.
#define MAX_CACHE_ERRORS 5
    int tx_cache_errors;

    /* Bundles we want to send to this peer
     In theory, we can have a relatively short queue, since we intend to rebuild the
     tree periodically. Thus any bundles received will cause the new sync process to
     not insert those in the TX queue, and thus allow the transfer of the next 
     MAX_TXQUEUE_LEN highest priority bundles. */
#define MAX_TXQUEUE_LEN 10
    int tx_queue_len;
    int tx_queue_bundles[MAX_TXQUEUE_LEN];
    unsigned int tx_queue_priorities[MAX_TXQUEUE_LEN];
    int tx_queue_overflow;
#endif

    /* Bitmaps that we use to keep track of progress of sending a bundle.
     We mark off blocks as we send them, or as we see them TXd by others,
     or as we get an explicit bitmap state sent by the receiver.
     
     A set bit means that we have received that 64 byte piece. */
    int request_bitmap_bundle;
    int request_bitmap_offset;
    unsigned char request_bitmap[32];
    unsigned char request_manifest_bitmap[2];
};

struct peer_state *peer_records[MAX_PEERS];

struct bundle_record
{
    int index; // position in array of bundles

    char *service;
    char *bid_hex;
    unsigned char bid_bin[32];
    long long version;
    char *author;
    int originated_here_p;
#ifdef SYNC_BY_BAR
#define TRANSMIT_NOW_TIMEOUT 2
    time_t transmit_now;
    int announce_bar_now;
#else
    //sync_key_t sync_key;
#endif
    long long length;
    char *filehash;
    char *sender;
    char *recipient;

    // The last time we announced this bundle in full.
    time_t last_announced_time;
    // The last version of the bundle that we announced.
    long long last_version_of_manifest_announced;
    // The furthest through the file that we have announced during the current
    // attempt at announcing it (which may be interrupted by the presence of bundles
    // with a higher priority).
    long long last_offset_announced;
    // Similarly for the manifest
    long long last_manifest_offset_announced;

    long long last_priority;
    int num_peers_that_dont_have_it;
};
struct bundle_record bundles[MAX_BUNDLES];

int free_peer(struct peer_state *p)
{
    if (p->sid_prefix)
    {
        free(p->sid_prefix);
    }
    p->sid_prefix = NULL;
    for (int i = 0; i < 4; i++)
        p->sid_prefix_bin[i] = 0;
#ifdef SYNC_BY_BAR
    for (int i = 0; i < p->bundle_count; i++)
    {
        if (p->bid_prefixes[i])
            free(p->bid_prefixes[i]);
    }
    free(p->bid_prefixes);
    p->bid_prefixes = NULL;
    free(p->versions);
    p->versions = NULL;
    free(p->size_bytes);
    p->size_bytes = NULL;
    free(p->insert_failures);
    p->insert_failures = NULL;
#endif
    // sync_free_peer_state(sync_state, p);
    free(p);
    return 0;
}

char *timestamp_str(void)
{

    struct tm tm;
    time_t now = time(0);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    localtime_r(&now, &tm);
    snprintf(timestamp_str_out, 1024, "[%02d:%02d.%02d.%03d]",
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec / 1000);

    return timestamp_str_out;
}

int prime_bundle_cache(int bundle_number, char *sid_prefix_hex,
                       char *servald_server, char *credential)
{
    if (bundle_number < 0)
        return -1;

    for (int i = 0; i < 6; i++)
    {
        if (sid_prefix_hex[i] < '0' || sid_prefix_hex[i] > 'f')
        {
            fprintf(stderr, "Saw illegal character 0x%02x in sid_prefix_hex[%d]\n",
                    (unsigned char)sid_prefix_hex[i], i);
            exit(-1);
        }
    }

    if ((!bid_of_cached_bundle) || strcasecmp(bundles[bundle_number].bid_hex, bid_of_cached_bundle) || (cached_version != bundles[bundle_number].version))
    {
        // Cache is invalid - release
        if (bid_of_cached_bundle)
        {
            free(bid_of_cached_bundle);
            bid_of_cached_bundle = NULL;
            free(cached_manifest);
            cached_manifest = NULL;
            free(cached_manifest_encoded);
            cached_manifest_encoded = NULL;
            free(cached_body);
            cached_body = NULL;
        }

        // Load bundle into cache
        char path[8192];
        char filename[1024];

        snprintf(path, 8192, "/restful/rhizome/%s.rhm",
                 bundles[bundle_number].bid_hex);


        char pathbuf[1024];
        snprintf(filename, 1024, "%s/%d.%s.manifest", getcwd(pathbuf, 1024), getpid(),
                 sid_prefix_hex);

        unlink(filename);
        FILE *f = fopen(filename, "w");
        if (!f)
        {
            fprintf(stderr, "could not open output file '%s'.\n", filename);
            perror("fopen");
            return -1;
        }

        fclose(f);
        f = fopen(filename, "r");
        if (!f)
        {
            fprintf(stderr, "ERROR: Could not open '%s' to read bundle manifest in prime_bundle_cache() call for bundle #%d\n",
                    filename, bundle_number);
            perror("fopen");
            return -1;
        }
        if (cached_manifest)
            free(cached_manifest);
        cached_manifest = malloc(8192);
        assert(cached_manifest);
        cached_manifest_len = fread(cached_manifest, 1, 8192, f);
        cached_manifest = realloc(cached_manifest, cached_manifest_len);
        assert(cached_manifest);
        fclose(f);
        unlink(filename);
        if (0)
            fprintf(stderr, "  manifest is %d bytes long.\n", cached_manifest_len);

        // Reject over-length manifests
        if (cached_manifest_len > 1024)
            return -1;

        // Generate binary encoded manifest from plain text version
        if (cached_manifest_encoded)
            free(cached_manifest_encoded);
        cached_manifest_encoded = malloc(1024);
        assert(cached_manifest_encoded);
        cached_manifest_encoded_len = 0;

        snprintf(path, 8192, "/restful/rhizome/%s/raw.bin",
                 bundles[bundle_number].bid_hex);
        snprintf(filename, 1024, "%d.%s.raw", getpid(), sid_prefix_hex);
        unlink(filename);
        f = fopen(filename, "w");
        if (!f)
        {
            fprintf(stderr, "could not open output file '%s'.\n", filename);
            perror("fopen");
            return -1;
        }
        fclose(f);
        f = NULL;

        // XXX - This transport only allows bundles upto 5MB!
        // (and that is probably pushing it a bit for a mesh extender with only 32MB RAM
        // for everything!)
        f = fopen(filename, "r");
        if (!f)
        {
            fprintf(stderr, "could read file '%s'.\n", filename);
            perror("fopen");
            return -1;
        }
        if (cached_body)
            free(cached_body);
        cached_body = malloc(5 * 1024 * 1024);
        assert(cached_body);
        // XXX - Should check that we read all the bytes
        cached_body_len = fread(cached_body, 1, 5 * 1024 * 1024, f);
        cached_body = realloc(cached_body, cached_body_len);
        if (cached_body_len)
            assert(cached_body);
        else
            fprintf(stderr, "WARNING:Body len = 0 bytes!\n");
        fclose(f);
        unlink(filename);
        if (1)

            bid_of_cached_bundle = strdup(bundles[bundle_number].bid_hex);

        cached_version = bundles[bundle_number].version;

        if (0)
            fprintf(stderr, "Cached manifest and body for %s\n",
                    bundles[bundle_number].bid_hex);
    }

    return 0;
}

int progress_bitmap_translate(struct peer_state *p, int new_body_offset)
{

    // First, check if the translation requires us to discard our bitmap,
    // or whether we can keep all or part of it.

    // Start with an empty bitmap
    unsigned char new_request_bitmap[32];
    bzero(new_request_bitmap, 32);

    int bit_delta = (new_body_offset - p->request_bitmap_offset) / 64;

    // Copy in any bits from the pre-translation bitmap
    // We start at bit 1, not bit 0, since we assume that the reason we
    // are advancing to this point, is that the piece at this position
    // requires retransmission.
    for (int bit = 1; bit < 256; bit++)
    {
        int the_bit = 0;
        int old_bit = bit + bit_delta;
        if (old_bit >= 0 && old_bit < 256)
            the_bit = p->request_bitmap[old_bit >> 3] & (1 << (old_bit & 7));
        if (the_bit)
            new_request_bitmap[bit >> 3] |= (1 << (bit & 7));
    }

    p->request_bitmap_offset = new_body_offset;
    memcpy(p->request_bitmap, new_request_bitmap, 32);

    return 0;
}

long long size_byte_to_length(unsigned char size_byte)
{
    return 1 << size_byte;
}

int bytes_to_prefix(unsigned char *bytes_in, char *prefix_out)
{

    sprintf(prefix_out, "%02X%02X%02X%02X%02X%02X*",
            bytes_in[0], bytes_in[1], bytes_in[2],
            bytes_in[3], bytes_in[4], bytes_in[5]);
    return 0;
}

int dump_bytes(FILE *f, char *msg, unsigned char *bytes, int length)
{
    int retVal = -1;

    do
    {
#if COMPILE_TEST_LEVEL >= TEST_LEVEL_LIGHT
        if (!msg)
        {
            perror("msg is null");
            break;
        }
        if (!bytes)
        {
            perror("bytes is null");
            break;
        }
#endif
        fprintf(f, "%s:\n", msg);
        for (int i = 0; i < length; i += 16)
        {
            fprintf(f, "%04X: ", i);
            for (int j = 0; j < 16; j++)
                if (i + j < length)
                    fprintf(f, " %02X", bytes[i + j]);
            fprintf(f, "  ");
            for (int j = 0; j < 16; j++)
            {
                int c;
                if (i + j < length)
                    c = bytes[i + j];
                else
                    c = ' ';
                if (c < ' ')
                    c = '.';
                if (c > 0x7d)
                    c = '.';
                fprintf(f, "%c", c);
            }
            fprintf(f, "\n");
        }
        retVal = 0;
    } while (0);

    return retVal;
}

int dump_progress_bitmap(FILE *f, unsigned char *b, int blocks)
{
    for (int i = 0; i < (32 * 8) && (i < blocks); i++)
    {
        if (b[i >> 3] & (1 << (i & 7)))
            fprintf(f, ".");
        else
            fprintf(f, "Y");
        //    if (((i&63)==63)&&(i!=255)) fprintf(f,"\n    ");
    }
    fprintf(f, "\n");
    return 0;
}

int lookup_bundle_by_prefix(const unsigned char *prefix, int len)
{
    if (len > 8)
        len = 8;

    int best_bundle = -1;
    int bundle;
    int i;
    for (bundle = 0; bundle < bundle_count; bundle++)
    {
        for (i = 0; i < len; i++)
        {
            if (prefix[i] != bundles[bundle].bid_bin[i])
                break;
        }
        if (i == len)
        {
            if ((best_bundle == -1) || (bundles[bundle].version > bundles[best_bundle].version))
                best_bundle = bundle;
        }
    }
    if (0)
        printf("  %02X%02X%02X%02x* is bundle #%d of %d\n",
               prefix[0], prefix[1], prefix[2], prefix[3],
               best_bundle, bundle_count);
    return best_bundle;
}

int message_parser_42(struct peer_state *sender, char *prefix,
                      char *servald_server, char *credential,
                      unsigned char *msg, int length, char *message_description)
{
    int offset = 0;
    if (length - offset < BAR_LENGTH)
    {
        fprintf(stderr, "Ignoring runt BAR (len=%d instead of %d)\n",
                length - offset, BAR_LENGTH);
        return -2;
    }
    offset++;
    // BAR announcement
    char bid_prefix[8 * 2 + 1 + 1];
    snprintf(bid_prefix, 8 * 2 + 1, "%02X%02X%02X%02X%02X%02X%02X%02X",
             msg[offset + 0], msg[offset + 1], msg[offset + 2], msg[offset + 3],
             msg[offset + 4], msg[offset + 5], msg[offset + 6], msg[offset + 7]);
    offset += 8;
    long long version = 0;
    for (int i = 0; i < 8; i++)
        version |= ((long long)msg[offset + i]) << (i * 8LL);
    offset += 8;
    char recipient_prefix[4 * 2 + 1 + 1];
    snprintf(recipient_prefix, 4 * 2 + 1, "%02x%02x%02x%02x",
             msg[offset + 0], msg[offset + 1], msg[offset + 2], msg[offset + 3]);
    offset += 4;
    unsigned char size_byte = msg[offset];
    offset += 1;
#ifdef SYNC_BY_BAR
    if (debug_pieces)
        printf(
            "Saw a BAR from %s*: %s* version %lld size byte 0x%02x"
            " (we know of %d bundles held by that peer)\n",
            sender->sid_prefix, bid_prefix, version, size_byte, sender->bundle_count);
#endif
    {
        char sender_prefix[128];
        char monitor_log_buf[1024];
        sprintf(sender_prefix, "%s*", sender->sid_prefix);
        snprintf(monitor_log_buf, sizeof(monitor_log_buf),
                 "BAR: BID=%s*, version 0x%010llx,"
                 " %smeshms payload has %lld--%lld bytes,"
#ifdef SYNC_BY_BAR
                 " (%d unique)"
#endif
                 ,
                 bid_prefix, version,
                 (size_byte & 0x80) ? "non-" : "",
                 (size_byte & 0x7f) ? (size_byte_to_length((size_byte & 0x7f) - 1)) : 0,
                 size_byte_to_length((size_byte & 0x7f)) - 1
#ifdef SYNC_BY_BAR
                 ,
                 sender->bundle_count
#endif
        );

        //      monitor_log(sender_prefix,NULL,monitor_log_buf);
    }

#ifdef SYNC_BY_BAR
    peer_note_bar(sender, bid_prefix, version, recipient_prefix, size_byte);
#else
    printf("TSYNC FIN: %s* has finished receiving"
           " %s version %lld \n",
           sender ? sender->sid_prefix : "<null>", bid_prefix,
           version);

#endif

    return offset;
}

int message_parser_47(struct peer_state *sender, char *sender_prefix,
                      char *servald_server, char *credential,
                      unsigned char *msg, int length, char *message_description)
{
    // Get instance ID of peer. We use this to note if a peer's lbard has restarted
    int offset = 0;
    offset++;
    {
        unsigned int peer_instance_id = 0;
        for (int i = 0; i < 4; i++)
            peer_instance_id |= (msg[offset++] << (i * 8));
        if (!sender->instance_id)
            sender->instance_id = peer_instance_id;
        if (sender->instance_id != peer_instance_id)
        {
            // Peer's instance ID has changed: Forget all knowledge of the peer and
            // return (ignoring the rest of the packet).
#ifndef SYNC_BY_BAR
            int peer_index = -1;
            for (int i = 0; i < peer_count; i++)
                if (sender == peer_records[i])
                {
                    peer_index = i;
                    break;
                }
            if (peer_index == -1)
            {
                // Could not find peer structure. This should not happen.
                return 0;
            }

            free_peer(peer_records[peer_index]);
            sender = calloc(1, sizeof(struct peer_state));
            for (int i = 0; i < 4; i++)
                sender->sid_prefix_bin[i] = msg[i];
            sender->sid_prefix = strdup(sender_prefix);
            sender->last_message_number = -1;
            sender->tx_bundle = -1;
            sender->instance_id = peer_instance_id;
            printf("Peer %s* has restarted -- discarding stale knowledge of its state.\n", sender->sid_prefix);
            peer_records[peer_index] = sender;
#endif
        }
    }

    return offset;
}

int message_parser_4C(struct peer_state *sender, char *sender_prefix,
                      char *servald_server, char *credential,
                      unsigned char *msg, int length, char *message_description)
{
    // Get instance ID of peer. We use this to note if a peer's lbard has restarted
    int offset = 0;

    if ((length - offset) < (1 + 8 + 8 + 4))
    {
        fprintf(stderr, "Error parsing message type 0x4C at offset 0x%x: length-offset=%d-%d=%d, but expected at least 1+8+8+4=21 bytes.\n",
                offset, length, offset, length - offset);
        dump_bytes(stderr, "complete packet", msg, length);
        return -3;
    }

    offset++;

    int bid_prefix_offset = offset;
    char bid_prefix[2 * 8 + 1 + 1];
    snprintf(bid_prefix, 8 * 2 + 1, "%02x%02x%02x%02x%02x%02x%02x%02x",
             msg[offset + 0], msg[offset + 1], msg[offset + 2], msg[offset + 3],
             msg[offset + 4], msg[offset + 5], msg[offset + 6], msg[offset + 7]);
    offset += 8;
    long long version = 0;
    for (int i = 0; i < 8; i++)
        version |= ((long long)msg[offset + i]) << (i * 8LL);
    offset += 8;
    long long offset_compound = 0;
    for (int i = 0; i < 4; i++)
        offset_compound |= ((long long)msg[offset + i]) << (i * 8LL);
    offset += 4;

    {
        char sender_prefix[128];
        char monitor_log_buf[1024];
        sprintf(sender_prefix, "%s*", sender->sid_prefix);
        char bid_prefix[128];
        bytes_to_prefix(&msg[bid_prefix_offset], bid_prefix);
        snprintf(monitor_log_buf, sizeof(monitor_log_buf),
                 "Payload length: BID=%s*, version 0x%010llx, length = %lld bytes",
                 bid_prefix, version, offset_compound);
        //assign to message description
        message_description = monitor_log_buf;

        //    monitor_log(sender_prefix,NULL,monitor_log_buf);
    }

    //  saw_length(sender_prefix,bid_prefix,version,offset_compound);

    return offset;
}

int message_parser_4D(struct peer_state *p, char *sender_prefix,
                      char *servald_server, char *credential,
                      unsigned char *msg_in, int length, char *message_description)
{
    int offset = 0;
    // XXX copy in or replace body of this function with this one

    unsigned char *msg = &msg_in[offset];
    (offset) += 1;  // Skip 'M'
    (offset) += 8;  // Skip BID prefix
    (offset) += 2;  // Skip manifest bitmap
    (offset) += 4;  // Skip start of region of interest
    (offset) += 32; // Skip progress bitmap

    // Get fields
    unsigned char *bid_prefix = &msg[1];
    unsigned char *manifest_bitmap = &msg[9];
    int body_offset = msg[11] | (msg[12] << 8) | (msg[13] << 16) | (msg[14] << 24);
    unsigned char *bitmap = &msg[15];
    int bundle = lookup_bundle_by_prefix(bid_prefix, 8);
    int manifest_offset = 1024;

    if (p->tx_bundle == bundle)
    {
        // We are sending this bundle to them, so update our info

        // XXX - We should also remember these as the last verified progress,
        // so that when we fill the bitmap, we can resend all not yet-acknowledged content

        p->request_bitmap_bundle = bundle;
        p->request_bitmap_offset = body_offset;
        memcpy(p->request_bitmap, bitmap, 32);

        // Update manifest bitmap ...
        memcpy(p->request_manifest_bitmap, manifest_bitmap, 2);
        // ... and quickly recalculate first useful TX point
        for (int i = 0; i < 16; i++)
            if (!(manifest_bitmap[i >> 3] & (1 << (i & 7))))
            {
                manifest_offset = i * 64;
                break;
            }
        p->tx_bundle_manifest_offset = manifest_offset;
    }

    if (debug_bitmap)
        printf(">>> BITMAP ACK: %s* is informing everyone to send from m=%d (%02x%02x), p=%d of"
               " %02x%02x%02x%02x%02x%02x%02x%02x:  ",
               p ? p->sid_prefix : "<null>",
               manifest_offset,
               p->request_manifest_bitmap[0], p->request_manifest_bitmap[1],
               body_offset,
               msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8]);
    //assign message description
    snprintf(message_description, 8000, ">>> BITMAP ACK: %s* is informing everyone to send from m=%d (%02x%02x), p=%d of"
                                        " %02x%02x%02x%02x%02x%02x%02x%02x:  ",
             p ? p->sid_prefix : "<null>",
             manifest_offset,
             p->request_manifest_bitmap[0], p->request_manifest_bitmap[1],
             body_offset,
             msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8]);

    int max_block = 256;
    if (bundle > -1)
    {
        max_block = (bundles[bundle].length - p->request_bitmap_offset);
        if (max_block & 0x3f)
            max_block = 1 + max_block / 64;
        else
            max_block = 0 + max_block / 64;
    }
    if (max_block > 256)
        max_block = 256;
    if (debug_bitmap)
        dump_progress_bitmap(stdout, bitmap, max_block);
    return offset;
}

int message_parser_52(struct peer_state *sender, char *sender_prefix,
                      char *servald_server, char *credential,
                      unsigned char *msg, int length, char *message_description)
{
    int offset = 0;
    // Request for a segment
    {
        char target_sid[4 + 1 + 1];
        char bid_prefix[8 * 2 + 1 + 1];
        int bundle_offset = 0;
        int is_manifest = 0;
        offset++;
        snprintf(target_sid, 5, "%02x%02x", msg[offset], msg[offset + 1]);
        offset += 2;
        snprintf(bid_prefix, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
                 msg[offset + 0], msg[offset + 1], msg[offset + 2], msg[offset + 3],
                 msg[offset + 4], msg[offset + 5], msg[offset + 6], msg[offset + 7]);
        offset += 8;
        bundle_offset |= msg[offset++];
        bundle_offset |= msg[offset++] << 8;
        bundle_offset |= msg[offset++] << 16;
        // We can only request segments upto 8MB point in a bundle via this transport!
        // XXX here be dragons
        if (bundle_offset & 0x800000)
            is_manifest = 1;
        bundle_offset &= 0x7fffff;

        {
            printf("Saw request from SID=%s* BID=%s @ %c%d addressed to SID=%s*\n",
                   sender_prefix, bid_prefix, is_manifest ? 'M' : 'B', bundle_offset,
                   target_sid);
            snprintf(message_description, 8000, "Saw request from SID=%s* BID=%s @ %c%d addressed to SID=%s*\n",
                     sender_prefix, bid_prefix, is_manifest ? 'M' : 'B', bundle_offset,
                     target_sid);
        }
        {
            char status_msg[1024];
            snprintf(status_msg, 1024, "Saw request from SID=%s* BID=%s @ %c%d addressed to SID=%s*\n",
                     sender_prefix, bid_prefix, is_manifest ? 'M' : 'B', bundle_offset,
                     target_sid);
            message_description = status_msg;
            //     status_log(status_msg);
        }

        {
            char sender_prefix[128];
            char monitor_log_buf[1024];
            sprintf(sender_prefix, "%s*", sender->sid_prefix);
            snprintf(monitor_log_buf, sizeof(monitor_log_buf),
                     "Request for BID=%s*, beginning at offset %d of %s.",
                     bid_prefix, bundle_offset, is_manifest ? "manifest" : "payload");
            message_description = monitor_log_buf;

            // monitor_log(sender_prefix,NULL,monitor_log_buf);
        }

#ifdef SYNC_BY_BAR
        // Are we the target SID?
        if (!strncasecmp(my_sid, target_sid, 4))
        {
            if (debug_pull)
                printf("  -> request is for us.\n");
            // Yes, it is addressed to us.
            // See if we have this bundle, and if so, set the appropriate stream offset
            // and mark the bundle as requested
            // XXX linear search!
            for (int i = 0; i < bundle_count; i++)
            {
                if (!strncasecmp(bid_prefix, bundles[i].bid, 16))
                {
                    if (debug_pull)
                        printf("  -> found the bundle.\n");
                    bundles[i].transmit_now = time(0) + TRANSMIT_NOW_TIMEOUT;
                    if (debug_announce)
                    {
                        printf("*** Setting transmit_now flag on %s*\n",
                               bundles[i].bid);
                    }

                    // When adjusting the offset, don't adjust it if we are going to reach
                    // that point within a few hundred bytes, as it won't save any time, and
                    // it might just cause confusion and delay because of the latency of us
                    // receiving the message and responding to it.
                    if (is_manifest)
                    {
                        if ((bundle_offset < bundles[i].last_manifest_offset_announced) || ((bundle_offset - bundles[i].last_manifest_offset_announced) > 500))
                        {
                            bundles[i].last_manifest_offset_announced = bundle_offset;
                            if (debug_pull)
                                printf("  -> setting manifest announcement offset to %d.\n", bundle_offset);
                        }
                    }
                    else
                    {
                        if ((bundle_offset < bundles[i].last_offset_announced) || ((bundle_offset - bundles[i].last_offset_announced) > 500))
                        {
                            bundles[i].last_offset_announced = bundle_offset;
                            if (debug_pull)
                                printf("  -> setting body announcement offset to %d.\n", bundle_offset);
                        }
                    }
                }
            }
        }
#endif
    }

    return offset;
}

int message_parser_53(struct peer_state *sender, char *sender_prefix,
                      char *ignore1, char *ignore2,
                      unsigned char *msg, int length, char *message_description)
{
    int offset = 0;
    // Sync-tree synchronisation message

    // process the message
    // sync_tree_receive_message(sender,&msg[offset]);

    // Skip over the message
    if (msg[offset + 1])
        offset += msg[offset + 1];
    // Zero field length is clearly an error, so abort
    else
    {
        {
            char sender_prefix[128];
            char monitor_log_buf[1024];
            sprintf(sender_prefix, "%s*", sender->sid_prefix);

            snprintf(monitor_log_buf, sizeof(monitor_log_buf),
                     "S field with zero length at radio packet offset %d",
                     offset);
            sprintf(message_description, "%s", message_description);

            //	monitor_log(sender_prefix,NULL,monitor_log_buf);
        }
        return -1;
    }
    
    sprintf(message_description, "SYNC Message");
        printf("Before return message description:%s\n", message_description);

    return offset;
}

int message_parser_54(struct peer_state *sender, char *sender_prefix,
                      char *servald_server, char *credential,
                      unsigned char *msg, int length, char *message_description)
{
    int offset = 0;
    {
        offset++;
        //int stratum=msg[offset++];
        struct timeval tv;
        bzero(&tv, sizeof(struct timeval));
        for (int i = 0; i < 8; i++)
            tv.tv_sec |= msg[offset++] << (i * 8);
        for (int i = 0; i < 3; i++)
            tv.tv_usec |= msg[offset++] << (i * 8);
        /* XXX - We don't do any clever NTP-style time correction here.
       The result will be only approximate, probably accurate to only
       ~10ms - 100ms per stratum, and always running earlier and earlier
       with each stratum, as we fail to correct the received time for 
       transmission duration.
       We can at least try to fix this a little:
       1. UHF radio serial speed = 230400bps = 23040cps.
       2. Packets are typically ~250 bytes long.
       3. Serial TX speed to radio is thus ~10.8ms
       4. UHF Radio air speed is 128000bps.
       5. Radio TX time is thus 250*8/128000= ~15.6ms
       6. Total minimum delay is thus ~26.4ms
       
       Thus we will make this simple correction of adding 26.4ms.
       
       The next challenge is if we have multiple sources with the same stratum
       giving us the time.  In that case, we need a way to choose a winner, since
       we are not implementing fancy NTP-style time integration algorithms. The
       trick is to get something simple, that stops clocks jumping backwards and
       forwards allover the shop.  A really simple approach is to have a timeout
       when updating the time, and ignore updates from the same time stratum for
       the next several minutes.  We should also decay our stratum if we have not
       heard from an up-stream clock lately, so that we always converge on the
       freshest clock.  In fact, we can use the slow decay to implement this
       quasi-stability that we seek.
    */
        tv.tv_usec += 26400;

        char sender_prefix[128];
        sprintf(sender_prefix, "%s*", sender->sid_prefix);

        //   saw_timestamp(sender_prefix,stratum,&tv);

        // Also record time delta between us and this peer in the relevant peer structure.
        // The purpose is to that the bundle/activity log can be more easily reconciled with that
        // of other mesh extenders.  By being able to relate the claimed time of each mesh extender
        // against each other, we can hopefully quite accurately piece together the timing of bundle
        // transfers via UHF, for example.
        time_t now = time(0);
        long long delta = (long long)now - (long long)sender->last_timestamp_received;
        // fprintf(stderr,"Logging timestamp message from %s (delta=%lld).\n",sender_prefix,delta);
        if (delta < 0)
        {
            fprintf(stderr, "Correcting last timestamp report time to be in the past, not future.\n");
            sender->last_timestamp_received = 0;
        }
        if (delta > 60)
        {
            // fprintf(stderr,"Logging timestamp message, since >60 seconds since last seen from this peer.\n");
            sender->last_timestamp_received = now;
        }
    }
    message_description = "Time correction";

    return offset;
}

int message_parser_41(struct peer_state *sender, char *sid_prefix_hex,
                      char *servald_server, char *credential,
                      unsigned char *msg, int length, char *message_description)
{
    // Get fields

    // Manifest progress is now exclusively sent as a bitmap, not an offset.
    // Compute first useful offset for legacy purposes.
    int manifest_offset = 1024;
    for (int i = 0; i < 16; i++)
        if (!(msg[9 + (i >> 3)] & (1 << (i & 7))))
        {
            manifest_offset = i * 64;
            break;
        }

    int body_offset = msg[11] | (msg[12] << 8) | (msg[13] << 16) | (msg[14] << 24);
    int for_me = 0;

    if ((msg[15] == my_sid[0]) && (msg[16] == my_sid[1]))
        for_me = 1;

    // Does the ACK tell us to jump exactly here, or to a random place somewhere
    // after it?  If it indicates a random jump, only do the jump 1/2 the time.
    int randomJump = 0;
    if (msg[0] == 'a' || msg[0] == 'f')
        randomJump = random() & 1;

    unsigned char *bid_prefix = &msg[1];

    int bundle = lookup_bundle_by_prefix(bid_prefix, 8);

    fprintf(stderr, "SYNC ACK: '%c' %s* is asking for %s (%02X%02X) to send from m=%d, p=%d of"
                    " %02x%02x%02x%02x%02x%02x%02x%02x (bundle #%d/%d)\n",
            msg[0],
            sender ? sender->sid_prefix : "<null>",
            for_me ? "us" : "someone else",
            msg[15], msg[16],
            manifest_offset, body_offset,
            msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8],
            bundle, bundle_count);

    snprintf(message_description, 8000, "SYNC ACK: '%c' %s* is asking for %s (%02X%02X) to send from m=%d, p=%d of"
                                        " %02x%02x%02x%02x%02x%02x%02x%02x (bundle #%d/%d)\n",
             msg[0],
             sender ? sender->sid_prefix : "<null>",
             for_me ? "us" : "someone else",
             msg[15], msg[16],
             manifest_offset, body_offset,
             msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8],
             bundle, bundle_count);

    if (!for_me)
        return 17;

    // Sanity check inputs, so that we don't mishandle memory.
    if (manifest_offset < 0)
        manifest_offset = 0;
    if (body_offset < 0)
        body_offset = 0;

    if (bundle < 0)
        return 17;
    //return correct length so handler knows how far to advance in packet

    if (bundle == sender->request_bitmap_bundle)
    {

        // For manifest progress, simply copy in the manifest progress bitmap
        sender->request_manifest_bitmap[0] = msg[9];
        sender->request_manifest_bitmap[0] = msg[10];

        // Reset (or translate) TX bitmap, since we are being asked to send from here.
        if (msg[0] == 'F' && msg[0] == 'f')
        {
            // Message types  F and f indicate that this really is the first byte we
            // could ever need, so translate the progress bitmap to the new offset
            progress_bitmap_translate(sender, body_offset);
        }
        else
        {
            // Message types A and a indicate that there are lowered number byte(s) we
            // still need, so we should only conservatively advance the bitmap, so as
            // to keep as much of the state that we have that might tell us which those
            // missing bytes might be.
            int body_offset_conservative = sender->request_bitmap_offset;
            // First, always go backwards if we need to
            if (body_offset < body_offset_conservative)
                body_offset_conservative = body_offset;
            // And advance only if the new offset would be <4KB from the end of the window
            // (and only then if we aren't sure that the bundle is <= 16KB)
            if (bundles[bundle].length > (16 * 1024))
            {
                if (body_offset > (body_offset_conservative + (12 * 1024)))
                    body_offset_conservative = body_offset;
            }
        }
    }

    if (bundle == sender->tx_bundle)
    {

        if (!(option_flags & FLAG_NO_HARD_LOWER))
        {
            sender->tx_bundle_manifest_offset_hard_lower_bound = manifest_offset;
            sender->tx_bundle_body_offset_hard_lower_bound = body_offset;
            if (debug_ack)
                fprintf(stderr, "HARDLOWER: Setting hard lower limit to M/B = %d/%d due to ACK packet\n",
                        manifest_offset, body_offset);
        }
        if (randomJump)
        {

            fprintf(stderr, "SYNC ACK: %s* is asking for us to send from m=%d, p=%d\n",
                    sender->sid_prefix, manifest_offset, body_offset);

            snprintf(message_description, 8000, "SYNC ACK: %s* is asking for us to send from m=%d, p=%d\n",
                     sender->sid_prefix, manifest_offset, body_offset);
            sender->tx_bundle_manifest_offset = manifest_offset;
            sender->tx_bundle_body_offset = body_offset;
        }
        else
        {
            fprintf(stderr, "SYNC ACK: Ignoring, because we are sending bundle #%d, and request is for bundle #%d\n", sender->tx_bundle, bundle);
            fprintf(stderr, "          Requested BID/version = %s/%lld\n",
                    bundles[bundle].bid_hex, bundles[bundle].version);
            snprintf(message_description, 8000, "SYNC ACK: Ignoring, because we are sending bundle #%d, and request is for bundle #%d\n", sender->tx_bundle, bundle);
            fprintf(stderr, "                 TX BID/version = %s/%lld\n",
                    bundles[sender->tx_bundle].bid_hex, bundles[sender->tx_bundle].version);
        }
    }

    return 17;
}

int message_parser_50(struct peer_state *sender, char *sender_prefix,
                      char *servald_server, char *credential,
                      unsigned char *msg, int length, char *message_description)
{
    int offset = 0;

    char bid_prefix[8 * 2 + 1];
    long long version;
    unsigned int offset_compound;
    long long piece_offset;
    int piece_bytes;
    int piece_is_manifest;
    int above_1mb = 0;
    int is_end_piece = 0;

    // Skip header character
    if (!(msg[offset] & 0x20))
        above_1mb = 1;
    if (!(msg[offset] & 0x01))
        is_end_piece = 1;
    offset++;

    offset += 2;

    if (length - offset < (1 + 8 + 8 + 4 + 1))
        return -3;
    snprintf(bid_prefix, 8 * 2 + 1, "%02x%02x%02x%02x%02x%02x%02x%02x",
             msg[offset + 0], msg[offset + 1], msg[offset + 2], msg[offset + 3],
             msg[offset + 4], msg[offset + 5], msg[offset + 6], msg[offset + 7]);
    offset += 8;
    version = 0;
    for (int i = 0; i < 8; i++)
        version |= ((long long)msg[offset + i]) << (i * 8LL);
    offset += 8;
    offset_compound = 0;
    for (int i = 0; i < 6; i++)
        offset_compound |= ((long long)msg[offset + i]) << (i * 8LL);
    offset += 4;
    if (above_1mb)
        offset += 2;
    else
        offset_compound &= 0xffffffff;
    piece_offset = (offset_compound & 0xfffff) | ((offset_compound >> 12LL) & 0xfff00000LL);
    piece_bytes = (offset_compound >> 20) & 0x7ff;
    piece_is_manifest = offset_compound & 0x80000000;

    {
        char sender_prefix[128];
        char monitor_log_buf[1024];
        sprintf(sender_prefix, "%s*", sender->sid_prefix);
        snprintf(monitor_log_buf, sizeof(monitor_log_buf),
                 "Piece of bundle: BID=%s*, [%lld--%lld) of %s.%s",
                 bid_prefix,
                 piece_offset, piece_offset + piece_bytes - 1,
                 piece_is_manifest ? "manifest" : "payload",
                 is_end_piece ? " This is the last piece of that." : "");
        message_description = monitor_log_buf;

        //    monitor_log(sender_prefix,NULL,monitor_log_buf);
    }

    if (piece_bytes > 0)
        offset += piece_bytes;

    return offset;
}
