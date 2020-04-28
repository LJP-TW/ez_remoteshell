#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>

#include "shared/general_ssl.h"
#include "ez_client.h"

#define BUF_MAX_LEN 0x1000

static
void client_handle_parameters(int argc, char **argv, client_parameters *cp)
{
    int cmd_opt = 0;
    int tmp;

    while (1) {
        cmd_opt = getopt(argc, argv, "i:p:f:h");

        if (cmd_opt == -1) {
            break;
        }

        switch (cmd_opt) {
            case 'i':
                tmp = strlen(optarg) + 1;
                cp->ip = malloc(tmp);
                memset(cp->ip, 0, tmp);
                strcat(cp->ip, optarg);
                break;
            case 'p':
                cp->port = atoi(optarg);
                break;
            case 'f':
                tmp = strlen(optarg) + 1;
                cp->config_file = malloc(tmp);
                memset(cp->config_file, 0, tmp);
                strcat(cp->config_file, optarg);
                break;
            case 'h':
                printf("Usage: " CLIENT_BIN_NAME " [OPTION]...\n");
                printf("\n");
                printf("  -i\tserver ip\n");
                printf("  -p\tserver port\n");
                printf("  -f\tconfig file\n");
                printf("  -h\thelp\n");
                exit(EXIT_SUCCESS);
                break;

            case '?':
            default:
                fprintf(stderr, "Try '" CLIENT_BIN_NAME " -h' for more information.\n");
                exit(EXIT_FAILURE);
        }
    }

    if (cp->ip == NULL) {
        fprintf(stderr, CLIENT_BIN_NAME ": need to set parameter -i\n");
        exit(EXIT_FAILURE);
    } else if (cp->port == 0) {
        fprintf(stderr, CLIENT_BIN_NAME ": need to set parameter -p\n");
        exit(EXIT_FAILURE);
    } else if (cp->config_file == NULL) {
        fprintf(stderr, CLIENT_BIN_NAME ": need to set parameter -f\n");
        exit(EXIT_FAILURE);
    }
}

static
void client_parse_config_file(client_parameters *cp, client_config_rec *cc)
{
    FILE *fp;
    char name[0x80];
    char val[0x80];

    if ((fp = fopen(cp->config_file, "r")) == NULL) {
        fprintf(stderr, CLIENT_BIN_NAME ": cannot read cc file\n");
        exit(EXIT_FAILURE);
    }

    while (fscanf(fp, "%127[^=]=%127[^\n]%*c", name, val) == 2) {
        if (strncmp("CA_CERT", name, 7) == 0) {
            cc->CA_cert_file = malloc(0x80);
            memset(cc->CA_cert_file, 0, 0x80);
            strcat(cc->CA_cert_file, val);
        } else if (strncmp("CLIENT_CERT", name, 11) == 0) {
            cc->client_cert_file = malloc(0x80);
            memset(cc->client_cert_file, 0, 0x80);
            strcat(cc->client_cert_file, val);
        } else if (strncmp("CLIENT_PKEY", name, 11) == 0) {
            cc->client_pkey_file = malloc(0x80);
            memset(cc->client_pkey_file, 0, 0x80);
            strcat(cc->client_pkey_file, val);
        }
    }
}

static
SSL_CTX *client_create_context(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}

inline static
void client_set_cert_pkey(SSL_CTX *ctx, client_config_rec *cc)
{
    set_cert_pkey(ctx, (config_rec *)cc);
}

inline static
void client_set_ca_cert(SSL_CTX *ctx, client_config_rec *cc)
{
    set_ca_cert(ctx, (config_rec *)cc);
}

static
int client_create_socket(void)
{
    int s;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
        fprintf(stderr, "socket error");
        exit(EXIT_FAILURE);
    }

    return s;
}

inline static
void client_init(int argc,
                 char **argv,
                 client_parameters **cp,
                 client_config_rec **cc,
                 SSL_CTX **ctx)
{
    *cp = malloc(sizeof(client_parameters));
    *cc = malloc(sizeof(client_config_rec));

    client_handle_parameters(argc, argv, *cp);
    client_parse_config_file(*cp, *cc);

    init_openssl();

    *ctx = client_create_context();
    client_set_cert_pkey(*ctx, *cc);
    client_set_ca_cert(*ctx, *cc);
}

inline static
SSL *client_create_ssl_connect(int sock, SSL_CTX *ctx)
{
    return create_ssl_connect(sock, ctx, 0);
}

static
void client_tcp_connect(client_parameters *cp, int sock)
{
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cp->port);
    addr.sin_addr.s_addr = inet_addr(cp->ip); 

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "connect error");
        exit(EXIT_FAILURE);
    }
}

static
void client_application(SSL *ssl)
{
    char *out_p, *in_p;
    int outgoing = 0;
    int incoming = 0;
    int rc;
    struct pollfd pfd[2];
    char buf_stdin[BUF_MAX_LEN];
    char buf_socket[BUF_MAX_LEN];

    /* setup socket input fd */
    pfd[0].fd = SSL_get_fd(ssl);
    pfd[0].events = POLLIN;

    /* setup stdin fd */
    pfd[1].fd = STDIN_FILENO;
    pfd[1].events = POLLIN;

    while (1) {
        out_p = buf_stdin;
        in_p = buf_socket;

        pfd[0].revents = 0;
        pfd[1].revents = 0;

        /* waiting for (without timeout) 
         * - network input
         * - shell output */
        rc = poll(pfd, 2, -1);

#ifdef DEBUG
        printf("[c] poll over\n");
        printf("[c] rc: %d\n", rc);
        printf("[c] pfd[0].revents: %d\n", pfd[0].revents);
        printf("[c] pfd[1].revents: %d\n", pfd[1].revents);
#endif

        /* check for error */
        if (rc <= 0) {
            fprintf(stderr, "poll error\n");
            return;
        }

        if (!outgoing && pfd[1].revents & POLLIN) {
#ifdef DEBUG
            printf("[#] get some data from stdin\n");
#endif

            /* There's something to read from stdin */
            outgoing = read(pfd[1].fd, out_p, buf_stdin + BUF_MAX_LEN - out_p);
            if (outgoing == -1) {
                fprintf(stderr, "error occured when read from stdin");
                return;
            }
        }

        if (!incoming && pfd[0].revents & POLLIN) {
#ifdef DEBUG
            printf("[#] get some data from socket\n");
#endif

            /* There's something to read from socket */
            incoming = SSL_read(ssl, in_p, buf_socket + BUF_MAX_LEN - in_p);
            if (incoming == -1) {
                fprintf(stderr, "error occured when read from socket");
                return;
            }
        }

        /* If POLLIN set but read return 0 */
        if ((!incoming && pfd[0].revents & POLLIN) ||
            (pfd[0].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            fprintf(stderr, "connect close\n");
            return;
        }

        /* deliver data */
        do {
            rc = incoming ? write(STDOUT_FILENO, in_p, incoming) : 0;

            /* check for error */
            if (rc < 0) {
                fprintf(stderr, "error occured when write to stdout\n");
                return;
            }

            if (rc > 0) {
                in_p += rc;
                incoming -= rc;
            }

            rc = outgoing ? SSL_write(ssl, out_p, outgoing) : 0;

            /* check for error */
            if (rc < 0) {
                fprintf(stderr, "error occured when write to server\n");
                return;
            }

            if (rc > 0) {
                out_p += rc;
                outgoing -= rc;
            }
        } while (incoming || outgoing);
    }
}

static
void client_request(int sock, SSL_CTX *ctx)
{
    SSL *ssl;
    char buf[2];

    ssl = client_create_ssl_connect(sock, ctx);

    /* Print information */
    printf("[>] SSL connection using %s\n", SSL_get_cipher(ssl));

    /* verify server certificate */
    printf("[>] Server Certificate:\n");
    switch (check_cert(ssl)) {
    case -1:
        fprintf(stderr, "no certificate\n");
        goto SSL_SHUTDOWN;
    case -2:
        fprintf(stderr, "certificate no subject or no issuer\n");
        goto SSL_SHUTDOWN;
    case -3:
        fprintf(stderr, "certificate is invalid\n");
        goto SSL_SHUTDOWN;
    default:
        break;
    }

    /* ok */
    SSL_read(ssl, buf, 2);

    /* run application */
    client_application(ssl);

SSL_SHUTDOWN:
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    client_parameters *cp;
    client_config_rec *cc;
    int sock;

    client_init(argc, argv, &cp, &cc, &ctx);

    sock = client_create_socket();

    client_tcp_connect(cp, sock);

    /* send request to server, including TLS handshake */
    client_request(sock, ctx);

    SSL_CTX_free(ctx);
    close(sock);

    return 0;
}
