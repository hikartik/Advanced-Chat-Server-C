#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "config.h"  // Ensure this file defines BUFFER_SIZE and SERVER_PORT

// Global flag to indicate if the client should keep running
volatile int keep_running = 1;

// Thread function for continuously receiving messages
void *receive_thread(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE];
    while (keep_running) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("\n[Incoming] %s\n", buffer);
            fflush(stdout);
        } else {
            // Error or connection closed
            keep_running = 0;
            break;
        }
    }
    return NULL;
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    SSL *ssl;
    SSL_CTX *ctx;
    char username[64];

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create an SSL context for the client using TLS
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Create a TCP socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Setup the server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Create a new SSL structure for the connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new failed\n");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    SSL_set_fd(ssl, sock);

    // Perform TLS/SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Connected securely to the server.\n");

    // *** Registration Step *** 
    // Prompt the user to enter a username and send a registration message
    printf("Enter your username: ");
    fflush(stdout);
    if (fgets(username, sizeof(username), stdin) == NULL) {
        perror("fgets failed");
        exit(EXIT_FAILURE);
    }
    // Remove trailing newline
    username[strcspn(username, "\n")] = '\0';
    
    // Build and send the registration command (e.g., "REGISTER:Alice")
    char reg_msg[128];
    snprintf(reg_msg, sizeof(reg_msg), "REGISTER:%s", username);
    if (SSL_write(ssl, reg_msg, strlen(reg_msg)) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Wait for registration acknowledgment from the server
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("%s\n", buffer);
    } else {
        ERR_print_errors_fp(stderr);
    }

    // Create a separate thread for receiving messages
    pthread_t recv_tid;
    if (pthread_create(&recv_tid, NULL, receive_thread, ssl) != 0) {
        perror("pthread_create failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Main thread: handle sending messages/commands to the server
    while (keep_running) {
        printf("Enter command (SEND:recipient:message, BROADCAST: message, EXIT to quit): ");
        fflush(stdout);
        if (fgets(buffer, sizeof(buffer), stdin) == NULL)
            break;
        // Remove trailing newline
        buffer[strcspn(buffer, "\n")] = '\0';
        if (strlen(buffer) == 0)
            continue;
        if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        if (strncmp(buffer, "EXIT", 4) == 0) {
            keep_running = 0;
            break;
        }
    }
    
    // Wait for the receiving thread to finish, then clean up
    pthread_join(recv_tid, NULL);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

