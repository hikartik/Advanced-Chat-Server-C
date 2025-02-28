#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <omp.h>
#include "config.h"
#include "ssl_helper.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
    char name[64];
    int client_fd;
    SSL *ssl;
    int active;
} ClientInfo;

ClientInfo client_list[MAX_CLIENTS];

// Initialize client list slots to inactive
void init_client_list() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_list[i].active = 0;
    }
}

// Add a client to the global list (protected by OpenMP critical section)
void add_client(const char *name, int client_fd, SSL *ssl) {
    #pragma omp critical(client_list)
    {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!client_list[i].active) {
                strncpy(client_list[i].name, name, sizeof(client_list[i].name) - 1);
                client_list[i].name[sizeof(client_list[i].name) - 1] = '\0';
                client_list[i].client_fd = client_fd;
                client_list[i].ssl = ssl;
                client_list[i].active = 1;
                break;
            }
        }
    }
}

// Remove a client from the list when disconnected
void remove_client(int client_fd) {
    #pragma omp critical(client_list)
    {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_list[i].active && client_list[i].client_fd == client_fd) {
                client_list[i].active = 0;
                break;
            }
        }
    }
}

// Find a client by name
ClientInfo *find_client_by_name(const char *name) {
    ClientInfo *found = NULL;
    #pragma omp critical(client_list)
    {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_list[i].active && strcmp(client_list[i].name, name) == 0) {
                found = &client_list[i];
                break;
            }
        }
    }
    return found;
}

// Broadcast a message to all connected clients
void broadcast_message(const char *sender, const char *msg) {
    char full_msg[BUFFER_SIZE];
    snprintf(full_msg, sizeof(full_msg), "[%s]: %s", sender, msg);
    #pragma omp critical(client_list)
    {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_list[i].active) {
                SSL_write(client_list[i].ssl, full_msg, strlen(full_msg));
            }
        }
    }
}

// Send a private message to a specific client
void send_private_message(const char *sender, const char *recipient, const char *msg) {
    char full_msg[BUFFER_SIZE];
    snprintf(full_msg, sizeof(full_msg), "[%s -> %s]: %s", sender, recipient, msg);
    ClientInfo *client = find_client_by_name(recipient);
    if (client != NULL) {
        SSL_write(client->ssl, full_msg, strlen(full_msg));
    }
}

// Logging function to log events with timestamps
void log_event(const char *format, ...) {
    va_list args;
    va_start(args, format);
    FILE *log_file_ptr = fopen(LOG_FILE, "a");
    if (log_file_ptr) {
        time_t now = time(NULL);
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file_ptr, "[%s] ", time_str);
        vfprintf(log_file_ptr, format, args);
        fprintf(log_file_ptr, "\n");
        fclose(log_file_ptr);
    }
    va_end(args);
}

int server_fd = -1;
SSL_CTX *ssl_ctx = NULL;
volatile int keep_running = 1;

void handle_signal(int sig) {
    keep_running = 0;
    log_event("Received signal %d, shutting down server.", sig);
    if (server_fd != -1) {
        close(server_fd);
    }
}

// Handles each client: registration and then processing messages persistently.
void handle_client(int client_fd, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);
    log_event("Accepted connection from %s:%d", client_ip, client_port);

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        log_event("SSL_new failed for %s:%d", client_ip, client_port);
        close(client_fd);
        return;
    }
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
        log_event("SSL_accept failed for %s:%d", client_ip, client_port);
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        log_event("Failed to read registration from %s:%d", client_ip, client_port);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return;
    }
    buffer[bytes] = '\0';
    // Expect a registration message: "REGISTER:username"
    if (strncmp(buffer, "REGISTER:", 9) == 0) {
        char username[64];
        strncpy(username, buffer + 9, sizeof(username) - 1);
        username[sizeof(username) - 1] = '\0';
        add_client(username, client_fd, ssl);
        char ack[128];
        snprintf(ack, sizeof(ack), "Welcome %s! You are registered.\n", username);
        SSL_write(ssl, ack, strlen(ack));
        log_event("Client %s registered from %s:%d", username, client_ip, client_port);
    } else {
        SSL_write(ssl, "Invalid registration. Use REGISTER:<username>\n", 46);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    // Main persistent communication loop
    while (1) {
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            log_event("Client disconnected from %s:%d", client_ip, client_port);
            break;
        }
        buffer[bytes] = '\0';
        log_event("Received from %s:%d: %s", client_ip, client_port, buffer);

        // If the client sends "EXIT", close the connection.
        if (strncmp(buffer, "EXIT", 4) == 0) {
            SSL_write(ssl, "Goodbye!\n", 9);
            break;
        }
        // If the message starts with "SEND:", then process as private message.
        else if (strncmp(buffer, "SEND:", 5) == 0) {
            // Expected format: "SEND:recipient:message"
            char *token = strtok(buffer + 5, ":");
            if (token == NULL) continue;
            char recipient[64];
            strncpy(recipient, token, sizeof(recipient) - 1);
            recipient[sizeof(recipient) - 1] = '\0';
            token = strtok(NULL, "");
            if (token == NULL) continue;
            char *msg = token;
            char sender[64] = "Unknown";
            // Look up sender from global list using client_fd
            #pragma omp critical(client_list)
            {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_list[i].active && client_list[i].client_fd == client_fd) {
                        strncpy(sender, client_list[i].name, sizeof(sender) - 1);
                        sender[sizeof(sender) - 1] = '\0';
                        break;
                    }
                }
            }
            send_private_message(sender, recipient, msg);
        }
        // If the message starts with "BROADCAST:", then send to all clients.
        else if (strncmp(buffer, "BROADCAST:", 10) == 0) {
            char *msg = buffer + 10;
            char sender[64] = "Unknown";
            #pragma omp critical(client_list)
            {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_list[i].active && client_list[i].client_fd == client_fd) {
                        strncpy(sender, client_list[i].name, sizeof(sender) - 1);
                        sender[sizeof(sender) - 1] = '\0';
                        break;
                    }
                }
            }
            broadcast_message(sender, msg);
        }
        else {
            SSL_write(ssl, "Unknown command\n", 16);
        }
    }

    remove_client(client_fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    log_event("Closed connection for client from %s:%d", client_ip, client_port);
}

int main() {
    struct sockaddr_in addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    system("mkdir -p logs");
    init_client_list();

    ssl_ctx = init_ssl_context("certs/server.crt", "certs/server.key");

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    log_event("Server started on port %d", SERVER_PORT);
    printf("Server listening on port %d...\n", SERVER_PORT);

    #pragma omp parallel num_threads(MAX_THREADS)
    {
        #pragma omp single nowait
        {
            while (keep_running) {
                int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
                if (client_fd < 0) {
                    if (errno == EINTR)
                        break;
                    log_event("accept failed: %s", strerror(errno));
                    continue;
                }
                #pragma omp task firstprivate(client_fd, client_addr)
                {
                    handle_client(client_fd, client_addr);
                }
            }
        }
    }

    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    log_event("Server shut down gracefully.");
    return 0;
}

