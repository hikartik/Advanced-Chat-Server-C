#include "ssl_helper.h"
#include <stdio.h>
#include <stdlib.h>

SSL_CTX *init_ssl_context(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create a new TLS server context
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the certificate and key for the context
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading certificate from %s\n", cert_file);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading private key from %s\n", key_file);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

