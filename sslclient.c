/*
 ============================================================================
 Name        : TLS_Programming.c
 Author      : Julius Eerola
 Version     : 02.11.2015
 Copyright   :
 Description : Verbose TLS client.
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* OpenSSL libraries */
#include <ssl.h>
#include <bio.h>
#include <err.h>

#define BUFFER_SIZE 1000

void print_certificate_subject(X509 *certificate) {
	char *common_name = calloc(BUFFER_SIZE, 1);
	char *organization_name = calloc(BUFFER_SIZE, 1);

	X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_commonName, common_name, BUFFER_SIZE);
	X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_organizationName, organization_name, BUFFER_SIZE);
	printf("Certificate subject:\n");
	printf(" - Common name: %s\n", common_name);
	printf(" - Organization name: %s\n", organization_name);

	free(common_name);
	free(organization_name);
}

void print_certificate_root(X509 *certificate) {
	char *organization_name = calloc(BUFFER_SIZE, 1);
	char *organization_unit = calloc(BUFFER_SIZE, 1);

	X509_NAME_get_text_by_NID(X509_get_issuer_name(certificate), NID_organizationName, organization_name, BUFFER_SIZE);
	X509_NAME_get_text_by_NID(X509_get_issuer_name(certificate), NID_organizationalUnitName, organization_unit, BUFFER_SIZE);

	printf("Certificate issuer:\n");
	printf(" - Organization name: %s\n", organization_name);
	printf(" - Organization unit: %s\n", organization_unit);

	free(organization_name);
	free(organization_unit);

	print_certificate_subject(certificate);
}

void print_certificate_issuer(X509 *certificate) {
	char *common_name = calloc(BUFFER_SIZE, 1);
	char *organization_name = calloc(BUFFER_SIZE, 1);

	X509_NAME_get_text_by_NID(X509_get_issuer_name(certificate), NID_commonName, common_name, BUFFER_SIZE);
	X509_NAME_get_text_by_NID(X509_get_issuer_name(certificate), NID_organizationName, organization_name, BUFFER_SIZE);
	printf("Certificate issuer:\n");
	printf(" - Common name: %s\n", common_name);
	printf(" - Organization name: %s\n", organization_name);

	free(common_name);
	free(organization_name);
}

void print_certificate(X509 *certificate) {
	printf("===\n");
	print_certificate_issuer(certificate);
	print_certificate_subject(certificate);
	printf("\n");
}

void verify_certificates(SSL **ssl, char *domain_name) {
	long result = SSL_get_verify_result(*ssl);
	if (result != X509_V_OK) {
		printf("Exiting due to error: %s\n", X509_verify_cert_error_string(result));
		exit(1);
	}

	STACK_OF(X509) *certificate_chain = SSL_get_peer_cert_chain(*ssl);
	unsigned amount = sk_X509_num(certificate_chain);

	print_certificate_root(sk_X509_value(certificate_chain, amount - 1));
	printf("\n");
	for (int i = 1; i < amount; i++) {
		print_certificate(sk_X509_value(certificate_chain, amount - i - 1));
	}

	/* Check manually that subject name and domain name matches in the peer certificate. */
	char *peer_CN = calloc(BUFFER_SIZE, 1);
	X509 *peer = SSL_get_peer_certificate(*ssl);
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

	if (strcmp(peer_CN, domain_name)) {
		printf("Exiting due to error: certificate subject and domain name do not match\n");
		exit(1);
	}

	printf("Certificates verified.\n");
}

SSL_CTX *initialize_ctx(void) {
    /* Algorithms and error messages retrieved. */
    SSL_library_init();
    SSL_load_error_strings();

    /* Create a new context. */
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method()); //SSLv23 == SSLv2, SSLv3, TLSv1 OK
    if (ctx == NULL) {
        printf("Exiting due to error: could not create a context object\n");
        exit(1);
    }

    return ctx;
}

BIO *initialize_SSL(SSL_CTX *ctx, SSL **ssl, char *domain_name, char *port, char *path) {
    /* CA certificate path is set. */
    if (!SSL_CTX_load_verify_locations(ctx, NULL, path)) {
        printf("Exiting due to error: could not load trusted CA certificates\n");
        exit(1);
    }

    /* Create BIO abstraction based on the context object. */
    BIO *bio = BIO_new_ssl_connect(ctx);

    /* Detach SSL from BIO. */
    BIO_get_ssl(bio, ssl);
    if (!(*ssl)) {
        printf("Exiting due to error: problems with SSL pointer\n");
        exit(1);
    }

    /* BIO variables (host and port) are set. */
    BIO_set_conn_hostname(bio, domain_name);
    BIO_set_conn_port(bio, port);

    /* Connect to host. */
    if (BIO_do_connect(bio) < 1) {
        printf("Exiting due to error: could not create a connection to the given host\n");
        exit(1);
    }

    /* Check and print certificates. */
    verify_certificates(ssl, domain_name);

    return bio;
}

char *get_message(BIO *bio) {
    char *message = calloc(BUFFER_SIZE, 1);

    if (BIO_read(bio, message, BUFFER_SIZE) < 0) {
        printf("Exiting due to error: could not receive the message\n");
        exit(1);
    }

    return message;
}

void send_message(BIO *bio, char *message) {
    if (BIO_write(bio, message, strlen(message)) < 0) {
        printf("Exiting due to error: could not send the message\n");
        exit(1);
    }
}

int main(int argc, char **argv) {
    /* Store given parameters. */
    char *domain_name = argv[1];
    char *port = argv[2];

    if (argc != 3) {
        printf("Exiting due to error: usage: ./sslclient <address> <port>\n");
        return 1;
    }

    /* Create a context object. */
    SSL_CTX *ctx = initialize_ctx();
    SSL *ssl = NULL;

    char *trusted_path = "/etc/ssl/certs";
    BIO *bio = initialize_SSL(ctx, &ssl, domain_name, port, trusted_path);

    char *message = "GET / HTTP/1.1\n\nConnection: close";
    send_message(bio, message);

    char *received_message = get_message(bio);
    printf("%s\n", received_message);
    free(received_message);

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    ERR_free_strings();

    return 0;
}
