/*
 * Defaults Settings
 */

/* Turn this on to show debug info */
//#define DEBUG_NSOPENSSL                1

#define MODULE                         "nsopenssl"
#define MODULE_SHORT                   "ssl"
#define SERVER_ROLE                    1
#define CLIENT_ROLE                    0
#define DEFAULT_PROTOCOLS              "All"
#define DEFAULT_CIPHER_LIST            SSL_DEFAULT_CIPHER_LIST
#define DEFAULT_CERT_FILE              "certificate.pem"
#define DEFAULT_KEY_FILE               "key.pem"
#define DEFAULT_CA_FILE                "ca.pem"
#define DEFAULT_CA_DIR                 "ca"
#define DEFAULT_PEER_VERIFY            NS_FALSE
#define DEFAULT_PEER_VERIFY_DEPTH      3
#define DEFAULT_SESSION_CACHE          NS_TRUE
#define DEFAULT_SESSION_CACHE_SIZE     128
#define DEFAULT_SESSION_CACHE_TIMEOUT  300
#define DEFAULT_TRACE                  NS_FALSE
#define DEFAULT_TIMEOUT                30
#define DEFAULT_BUFFER_SIZE            16384
#define DEFAULT_SEEDBYTES              1024
#define DEFAULT_MAXBYTES               1024000
#define DEFAULT_SENDWAIT               60
#define DEFAULT_RECVWAIT               60
#define CONFIG_MODULE_DIR              "ModuleDir"
#define CONFIG_RANDOM_FILE             "RandomFile"
#define CONFIG_SEEDBYTES               "SeedBytes"

