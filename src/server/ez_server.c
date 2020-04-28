#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <unistd.h>
#include <ctype.h>

#include <signal.h>
#include <sys/prctl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>

#include "shared/general_ssl.h"
#include "ez_server.h"

#define BUF_MAX_LEN 0x1000

static
void server_handle_parameters(int argc, char **argv, server_parameters *sp)
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
                sp->ip = malloc(tmp);
                memset(sp->ip, 0, tmp);
                strcat(sp->ip, optarg);
                break;
            case 'p':
                sp->port = atoi(optarg);
                break;
            case 'f':
                tmp = strlen(optarg) + 1;
                sp->config_file = malloc(tmp);
                memset(sp->config_file, 0, tmp);
                strcat(sp->config_file, optarg);
                break;
            case 'h':
                printf("Usage: " SERVER_BIN_NAME " [OPTION]...\n");
                printf("\n");
                printf("  -i\tip\n");
                printf("  -p\tport\n");
                printf("  -f\tconfig file\n");
                printf("  -h\thelp\n");
                exit(EXIT_SUCCESS);
                break;

            case '?':
            default:
                fprintf(stderr, "Try '" SERVER_BIN_NAME " -h' for more information.\n");
                exit(EXIT_FAILURE);
        }
    }

    if (sp->ip == NULL) {
        fprintf(stderr, SERVER_BIN_NAME ": need to set parameter -i\n");
        exit(EXIT_FAILURE);
    } else if (sp->port == 0) {
        fprintf(stderr, SERVER_BIN_NAME ": need to set parameter -p\n");
        exit(EXIT_FAILURE);
    } else if (sp->config_file == NULL) {
        fprintf(stderr, SERVER_BIN_NAME ": need to set parameter -f\n");
        exit(EXIT_FAILURE);
    }
}

static
void server_parse_config_file(server_parameters *sp, server_config_rec *sc)
{
    FILE *fp;
    char name[0x80];
    char val[0x80];

    if ((fp = fopen(sp->config_file, "r")) == NULL) {
        fprintf(stderr, SERVER_BIN_NAME ": cannot read sc file\n");
        exit(EXIT_FAILURE);
    }

    while (fscanf(fp, "%127[^=]=%127[^\n]%*c", name, val) == 2) {
        if (strncmp("CA_CERT", name, 7) == 0) {
            sc->CA_cert_file = malloc(0x80);
            memset(sc->CA_cert_file, 0, 0x80);
            strcat(sc->CA_cert_file, val);
        } else if (strncmp("SERVER_CERT", name, 11) == 0) {
            sc->server_cert_file = malloc(0x80);
            memset(sc->server_cert_file, 0, 0x80);
            strcat(sc->server_cert_file, val);
        } else if (strncmp("SERVER_PKEY", name, 11) == 0) {
            sc->server_pkey_file = malloc(0x80);
            memset(sc->server_pkey_file, 0, 0x80);
            strcat(sc->server_pkey_file, val);
        }
    }
}

static
SSL_CTX *server_create_context(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}

inline static
void server_set_cert_pkey(SSL_CTX *ctx, server_config_rec *sc)
{
    set_cert_pkey(ctx, (config_rec *)sc);
}

inline static
void server_set_ca_cert(SSL_CTX *ctx, server_config_rec *sc)
{
    set_ca_cert(ctx, (config_rec *)sc);
}

static
int server_create_socket(server_parameters *sp)
{
    int s;
    int TRUE = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(sp->port);
    addr.sin_addr.s_addr = inet_addr(sp->ip); 

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        fprintf(stderr, "socket error");
        exit(EXIT_FAILURE);
    }

    /* set SO_REUSEADDR, check out this link for detail:
     *   https://stackoverflow.com/questions/10619952/how-to-completely-destroy-a-socket-connection-in-c 
     */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &TRUE, sizeof(TRUE)) == -1) {
        fprintf(stderr, "setsockopt error\n");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind error");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 100) < 0) {
        fprintf(stderr, "listen error");
        exit(EXIT_FAILURE);
    }

    return s;
}

inline static
void server_init(int argc, 
                 char **argv, 
                 server_parameters **sp, 
                 server_config_rec **sc,
                 SSL_CTX **ctx)
{
    *sp = malloc(sizeof(server_parameters));
    *sc = malloc(sizeof(server_config_rec));

    server_handle_parameters(argc, argv, *sp);
    server_parse_config_file(*sp, *sc);

    init_openssl();

    *ctx = server_create_context();
    server_set_cert_pkey(*ctx, *sc);
    server_set_ca_cert(*ctx, *sc);
}

inline static
SSL *server_create_ssl_connect(int sock, SSL_CTX *ctx)
{
    return create_ssl_connect(sock, ctx, 1);
}

static
int server_create_shell(int *shell_in, int *shell_out) 
{
    int pipe_in[2];
    int pipe_out[2];
    int pid;

    if (pipe(pipe_in) == -1 || pipe(pipe_out) == -1) {
        return -1;
    }

    if ((pid = fork()) < 0) {
        return -1;
    } else if (pid == 0) {
        char *run_cmd = "/bin/sh";
        char **run_argv = malloc(sizeof(char *) * 2);
        char **run_envp = malloc(sizeof(char *) * 1);
        
        run_argv[0] = run_cmd;
        run_argv[1] = NULL;

        run_envp[0] = NULL;

        // close unused fd
        close(pipe_in[1]);
        close(pipe_out[0]);

        // redirect fd
        dup2(pipe_in[0], STDIN_FILENO);
        dup2(pipe_out[1], STDOUT_FILENO);

        // close unused fd
        close(pipe_in[0]);
        close(pipe_out[1]);

        // execute shell
        execve(run_cmd, run_argv, run_envp);

        // never reached
        exit(EXIT_FAILURE);
    }
    
    // close unsed fd
    close(pipe_in[0]);
    close(pipe_out[1]);

    *shell_in = pipe_in[1];
    *shell_out = pipe_out[0];

    return 0;
}

static
void server_application(SSL *ssl)
{
    char *out_p, *in_p;
    int outgoing = 0;
    int incoming = 0;
    int rc;
    int shell_in_fd, shell_out_fd;
    struct pollfd pfd[2];
    char buf_shell[BUF_MAX_LEN];
    char buf_socket[BUF_MAX_LEN];

    /* create shell */
    if (server_create_shell(&shell_in_fd, &shell_out_fd) != 0) {
        fprintf(stderr, "create shell error\n");
        return;
    }

    /* setup socket input fd */
    pfd[0].fd = SSL_get_fd(ssl);
    pfd[0].events = POLLIN;

    /* setup shell output fd */
    pfd[1].fd = shell_out_fd;
    pfd[1].events = POLLIN;

    while (1) {
        out_p = buf_shell;
        in_p = buf_socket;

        pfd[0].revents = 0;
        pfd[1].revents = 0;

        /* waiting for (without timeout) 
         * - network input
         * - shell output */
        rc = poll(pfd, 2, -1);

        /* check for error */
        if (rc <= 0) {
            fprintf(stderr, "poll error\n");
            return;
        }

        if (!outgoing && pfd[1].revents & POLLIN) {
#ifdef DEBUG
            printf("[#] get some data from shell\n");
#endif

            /* There's something to read from shell */
            outgoing = read(pfd[1].fd, out_p, buf_shell + BUF_MAX_LEN - out_p);
            if (outgoing == -1) {
                fprintf(stderr, "error occured when read from shell");
                return;
            }
        }

        /* If POLLIN set but read return 0 */
        if ((!outgoing && pfd[1].revents & POLLIN) ||
            (pfd[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            fprintf(stderr, "shell close\n");
            return;
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
            fprintf(stderr, "client close\n");
            return;
        }

        /* deliver data */
        do {
            rc = incoming ? write(shell_in_fd, in_p, incoming) : 0;

            /* check for error */
            if (rc < 0) {
                fprintf(stderr, "error occured when write to shell\n");
                return;
            }

            if (rc > 0) {
                in_p += rc;
                incoming -= rc;
            }

            rc = outgoing ? SSL_write(ssl, out_p, outgoing) : 0;

            /* check for error */
            if (rc < 0) {
                fprintf(stderr, "error occured when write to client\n");
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
void server_respond(int client, SSL_CTX *ctx)
{
    SSL *ssl;

    ssl = server_create_ssl_connect(client, ctx);

#ifdef DEBUG
    /* Print information */
    printf("[m] SSL connection using %s\n", SSL_get_cipher(ssl));
#endif

    /* verify client certificate */
    printf("[>] Client Certificate:\n");
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
    SSL_write(ssl, "hi", 2);

    /* run application */
    server_application(ssl);

SSL_SHUTDOWN:
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx = NULL;
    server_parameters *sp = NULL;
    server_config_rec *sc = NULL;
    int sock;

    server_init(argc, argv, &sp, &sc, &ctx);

#ifdef DEBUG
    printf("[m] Session cache mode: %ld\n", SSL_CTX_get_session_cache_mode(ctx));
#endif

    sock = server_create_socket(sp);

    /* when child process exit, just let it be deleted,
     * preventing zombie process */
    signal(SIGCHLD, SIG_IGN);

    /* Handle connections */
    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        int pid;

#ifdef DEBUG
        printf("[m] start to accept client\n");
#endif

        /* TCP handshake */
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            fprintf(stderr, "accept error");
            exit(EXIT_FAILURE);
        }

        if ((pid = fork()) < 0) {
            fprintf(stderr, "fork error\n");
        } else if (pid == 0) {
            /* when parent exit, childs also exit */
            prctl(PR_SET_PDEATHSIG, SIGHUP);
            close(sock);

            /* respond to client, including TLS handshake */
            server_respond(client, ctx);
            exit(EXIT_SUCCESS);
        }

        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}
