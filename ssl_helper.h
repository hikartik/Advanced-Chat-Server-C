#ifndef SSL_HELPER_H
#define SSL_HELPER_H

#include <openssl/ssl.h>
#include <openssl/err.h>

// Initializes and returns an SSL context for the server using the given certificate and key files.
SSL_CTX *init_ssl_context(const char *cert_file, const char *key_file);

#endif // SSL_HELPER_H

