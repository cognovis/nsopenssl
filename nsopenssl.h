/*
 * The contents of this file are subject to the AOLserver Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://aolserver.com.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License (the "GPL"), in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * Copyright (C) 2000-2003 Scott S. Goodwin
 * 
 * Module originally written by Stefan Arentz. Early contributions made by
 * Freddie Mendoze and Rob Mayoff.
 *
 * $Header$
 */

#include <ns.h>

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _WIN32
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#define SockError(i)    Tcl_PosixError((i))

#ifdef __sun
#include <sys/filio.h>
#endif

/* openssl and nsd both define closesocket */
#ifdef closesocket
#undef closesocket
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>


/*
 * Defaults
 */

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
#define CONFIG_MODULE_DIR              "ModuleDir"
#define CONFIG_RANDOM_FILE             "RandomFile"
#define CONFIG_SEEDBYTES               "SeedBytes"
#define DEFAULT_SEEDBYTES              1024
#define DEFAULT_MAXBYTES               1024000


/*
 * Hold SSL Context information. If refcnt is 0, then struct can be disposed
 * of or initialized.  If refcnt is 1 and NsOpenSSLContextFree is called, the
 * data pointed to in the structure that needs to be freed will be freed. If
 * refcnt is > 1, a call to NsOpenSSLContextFree simply decrements refcnt. If
 * refcnt > 0 and NsOpenSSLContextInit is called, nothing happens.
 */

typedef struct NsOpenSSLContext {
    char              *server; 
    char              *name;                /* Name of this SSL context */
    char              *desc;
    int                role;                /* 0 = client, 1 = server */
    int                initialized;         /* 1 = already initialized */
    int                refcnt;              /* How many active conns I'm tied to */
    char              *moduleDir;
    char              *certFile;             /* PEM formatted certificate file */
    char              *keyFile;              /* PEM formatted key file */
    char              *protocols;            /* Allowed SSL protocols */
    char              *cipherSuite;          /* OpenSSL-formatted cipher string */
    char              *caFile;               /* PEM format CA file(s) concatenated */
    char              *caDir;                /* CA directory */
    int                peerVerify;           /* 0 = off; 1 = on */
    int                peerVerifyDepth;      /* How deep verification path can be */
    int                sessionCache;         /* 0 = off; 1 = on */
    char              *sessionCacheId;       /* XXX needs to be free'd */
    int                sessionCacheSize;     /* In bytes */
    int                sessionCacheTimeout;  /* Flush session cache in seconds */
    int                trace;                /* 0 = off; 1 = on */
    int                bufsize;
    int                timeout;
    Ns_Mutex           lock;
    SSL_CTX           *sslctx;
    struct NsOpenSSLContext *next;
    struct Server     *serverPtr;            /* virtual server-specific data */ 
} NsOpenSSLContext;

/*
 * Used to manage SSL drivers on top of the AOLserver comm driver.
 */

typedef struct NsOpenSSLDriver {
    Ns_Mutex                  lock;
    char                     *server;      
    char                     *name;          /* Name of this SSL driver */      
    char                     *path;
    char                     *dir;
    SOCKET                    lsock;
    int                       port;          /* Port the core driver is listening on */
    int                       refcnt;        /* Number of conns tied to this driver */
    struct NsOpenSSLContext  *sslcontext;    /* SSL context assoc with this driver */ 
} NsOpenSSLDriver;

/*
 * Used for both core-driven and C/Tcl API-driven conns
 */

typedef struct NsOpenSSLConn {
    Ns_Mutex                  lock;
    char                     *server;
    int                       peerport;  /* port this connection came in or went out on */
    int                       peeraddr;  /* IP address of remote side */
    char                      peer[16];  /* peer's name */
    struct NsOpenSSLContext  *sslcontext;
    SSL_CTX                  *sslctx;
    SSL                      *ssl;       /* initialized SSL instance itself */
    BIO                      *bio;        /* block i/o */
    SOCKET                    socket;
    SOCKET                    wsock;
    int                       refcnt;    /* don't ns_free() unless this is 0 */
    int                       timeout;
    struct NsOpenSSLDriver   *ssldriver; /* the driver this conn belongs to */
} NsOpenSSLConn;

/*
 * Manages each virtual server's specific SSL information.
 */

typedef struct Server {
    Ns_Mutex           lock;
    char              *server;
    Tcl_HashTable      sslcontexts;
    Tcl_HashTable      ssldrivers;
    char              *defaultclientcontext;
    char              *defaultservercontext;
    int                nextSessionCacheId;
} Server;

/*
 * sslconn.c
 */

#if 0
extern void
NsOpenSSLErrorDump(NsOpenSSLConn *sslconn, int code);
#endif

extern NsOpenSSLConn *
NsOpenSSLConnCreate(SOCKET socket, NsOpenSSLContext *sslcontext);

extern void 
NsOpenSSLConnDestroy(NsOpenSSLConn *sslconn);

extern int 
NsOpenSSLConnFlush(NsOpenSSLConn *sslconn);

extern int 
NsOpenSSLConnRecv(SSL *ssl, void *buffer, int toread);

// XXX const or CONST???
extern int 
NsOpenSSLConnSend(SSL *ssl, const void *buffer, int towrite);

extern int
NsOpenSSLConnHandshake(NsOpenSSLConn *sslconn);

/*
 * ssl.c
 */

extern NsOpenSSLConn *
Ns_OpenSSLSockConnect(char *server, char *host, int port, int async,
        int timeout, NsOpenSSLContext *sslcontext);

extern NsOpenSSLConn *
Ns_OpenSSLSockAccept(SOCKET sock, NsOpenSSLContext *sslcontext);

extern SOCKET
Ns_OpenSSLSockListen(char *addr, int port);

extern int
Ns_OpenSSLSockListenCallback(char *addr, int port, Ns_SockProc *proc, void *arg);

extern int
Ns_OpenSSLFetchUrl(char *server, Ns_DString *dsPtr, char *url, 
        Ns_Set *headers, NsOpenSSLContext *sslcontext);

/*
 * tclcmds.c
 */

extern void 
NsOpenSSLTclInit(char *server);

/*
 * nsopenssl.c
 */

extern Server *
NsOpenSSLServerGet(char *server);

extern void
NsOpenSSLContextAdd(char *server, NsOpenSSLContext *sslcontext);

extern void
Ns_OpenSSLServerSSLContextRemove(char *server, NsOpenSSLContext *sslcontext);

extern NsOpenSSLContext *
Ns_OpenSSLServerSSLContextGet(char *server, char *name);

extern int 
Ns_OpenSSLIsPeerCertValid (NsOpenSSLConn *sslconn);

extern NsOpenSSLContext *
NsOpenSSLContextCreate(char *server, char *name);

extern int 
NsOpenSSLContextInit(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextRelease (char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextDestroy(char *server, NsOpenSSLContext *sslcontext);

/* XXX ugly. find a cleaner way to do this */
extern NsOpenSSLContext *
NsOpenSSLContextServerDefaultGet(char *server);

extern NsOpenSSLContext *
NsOpenSSLContextClientDefaultGet(char *server);

extern int 
NsOpenSSLContextRoleSet(char *server, NsOpenSSLContext *sslcontext, char *role);

extern char *
NsOpenSSLContextRoleGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextModuleDirSet(char *server, NsOpenSSLContext *sslcontext, char *moduleDir);

extern char *
NsOpenSSLContextModuleDirGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextCertFileSet(char *server, NsOpenSSLContext *sslcontext, char *certFile);

extern char *
NsOpenSSLContextCertFileGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextKeyFileSet(char *server, NsOpenSSLContext *sslcontext, char *keyFile);

extern char *
NsOpenSSLContextKeyFileGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextProtocolsSet(char *server, NsOpenSSLContext *sslcontext, char *protocols);

extern char *
NsOpenSSLContextProtocolsGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextCipherSuiteSet(char *server, NsOpenSSLContext *sslcontext, char *cipherSuite);

extern char *
NsOpenSSLContextCipherSuiteGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextCAFileSet(char *server, NsOpenSSLContext *sslcontext, char *CAFile);

extern char *
NsOpenSSLContextCAFileGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextCADirSet(char *server, NsOpenSSLContext *sslcontext, char *CADir);

extern char *
NsOpenSSLContextCADirGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextPeerVerifySet(char *server, NsOpenSSLContext *sslcontext, int peerVerify);

extern int 
NsOpenSSLContextPeerVerifyGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextPeerVerifyDepthSet(char *server, NsOpenSSLContext *sslcontext, int peerVerifyDepth);

extern int 
NsOpenSSLContextPeerVerifyDepthGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextSessionCacheSet(char *server, NsOpenSSLContext *sslcontext, int sessionCache);

extern int 
NsOpenSSLContextSessionCacheGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextSessionCacheSizeSet(char *server, NsOpenSSLContext *sslcontext, int sessionCacheSize);

extern int 
NsOpenSSLContextSessionCacheSizeGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextSessionCacheTimeoutSet(char *server, NsOpenSSLContext *sslcontext, int sessionCacheTimeout);

extern int 
NsOpenSSLContextSessionCacheTimeoutGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLContextTraceSet(char *server, NsOpenSSLContext *sslcontext, int trace);

extern int 
NsOpenSSLContextTraceGet(char *server, NsOpenSSLContext *sslcontext);

extern int 
NsOpenSSLModuleInit(char *server);


#if 0
/* XXX debug log */
extern void
NsOpenSSLDebug(char *fmt, ...);
#endif

