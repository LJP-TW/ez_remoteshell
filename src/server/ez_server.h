#ifndef EZ_SERVER_C
#define EZ_SERVER_C

#define SERVER_BIN_NAME "ez_rsserver"

struct _server_parameters {
    char *ip;
    char *config_file;
    unsigned int port;
};

typedef struct _server_parameters server_parameters;

/* The config variables at config file */
struct _server_config_rec {
    char *CA_cert_file;
    char *server_cert_file;
    char *server_pkey_file;
    /* DON'T CHANGE order of above config */
};

typedef struct _server_config_rec server_config_rec;

#endif
