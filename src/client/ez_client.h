#ifndef EZ_CLIENT_C
#define EZ_CLIENT_C

#define CLIENT_BIN_NAME "ez_rsclient"

struct _client_parameters {
    char *ip;
    char *config_file;
    unsigned int port;
};

typedef struct _client_parameters client_parameters;

/* The config variables at config file */
struct _client_config_rec {
    char *CA_cert_file;
    char *client_cert_file;
    char *client_pkey_file;
    /* DON'T CHANGE order of above config */
};

typedef struct _client_config_rec client_config_rec;

#endif
