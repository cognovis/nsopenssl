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
 * The Original Code is AOLserver Code and related documentation
 * distributed by AOL.
 * 
 * The Initial Developer of the Original Code is America Online,
 * Inc. Portions created by AOL are Copyright (C) 1999 America Online,
 * Inc. All Rights Reserved.
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
 * Copyright (C) 2000 Rob Mayoff
 * Copyright (C) 1999 Stefan Arentz
 *
 * $Header$
 */

/* XXX remove from production */
#define NSOPENSSL_DEBUG
#define LOC() __FUNCTION__, __FILE__, __LINE__


/* Required for Tcl channels to work */
#ifndef USE_TCL8X
#define USE_TCL8X
#endif

#include <ns.h>

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
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

/* XXX don't forget to turn this back on */
#if 0
define OPENSSL_THREAD_DEFINES
 /* requires newer version of OpenSSL */
ifndef OPENSSL_THREADS
error "OpenSSL was not compiled with thread support!"
endif
#endif

#define MODULE                   "nsopenssl"

/*
 * It is possible to have the encryption library be different
 * from the SSL library. A good example would be if you are
 * using RSA's BSAFE encryption library within OpenSSL.
 */

#define SSL_LIBRARY_NAME  "OpenSSL"

#if OPENSSL_VERSION_NUMBER   == 0x0090603fL
#  define SSL_LIBRARY_VERSION  "0.9.6c"
#elif OPENSSL_VERSION_NUMBER   == 0x0090602fL
#  define SSL_LIBRARY_VERSION  "0.9.6b"
#elif OPENSSL_VERSION_NUMBER   == 0x0090601fL
#  define SSL_LIBRARY_VERSION  "0.9.6a"
#elif OPENSSL_VERSION_NUMBER == 0x0090600fL
#  define SSL_LIBRARY_VERSION  "0.9.6"
#elif OPENSSL_VERSION_NUMBER == 0x0090581fL
#  define SSL_LIBRARY_VERSION  "0.9.5a"
#elif OPENSSL_VERSION_NUMBER == 0x00905100L
#  define SSL_LIBRARY_VERSION  "0.9.5"
#else
#  define SSL_LIBRARY_VERSION  "Unknown"
#endif

#define SSL_CRYPTO_LIBRARY_NAME     SSL_LIBRARY_NAME
#define SSL_CRYPTO_LIBRARY_VERSION  SSL_LIBRARY_VERSION



/*
 * Hold SSL Context information. If refcnt is 0, then struct can be disposed
 * of or initialized.  If refcnt is 1 and NsOpenSSLContextFree is called, the
 * data pointed to in the structure that needs to be freed will be freed. If
 * refcnt is > 1, a call to NsOpenSSLContextFree simply decrements refcnt. If
 * refcnt > 0 and NsOpenSSLContextInit is called, nothing happens.
 */

typedef struct Ns_OpenSSLContext {
    char              *server; 
    char              *module;
    int                refcnt; 
    struct Ns_OpenSSLContext *next;
    int                conntype;
    int                role;
    char              *moduleDir;
    char              *name;
    char              *desc;
    char              *certFile;             /* Cert file, PEM format */
    char              *keyFile;              /* Key file, PEM format */
    char              *protocols;            /* Protocols to use */
    char              *cipherSuite;          /* OpenSSL-formatted cipher string */
    char              *caFile;               /* CA file, PEM format, concatenated */
    char              *caDir;                /* CA dir */
    int                peerVerify;           /* 0 = peer verify off; 1 = peer verify on */
    int                peerVerifyDepth;      /* How deep do we allow a verification path to be? */
    int                sessionCache;         /* 0 = off; 1 = on */
    int                sessionCacheId;
    int                sessionCacheSize;     /* In bytes */
    int                sessionCacheTimeout;  /* Flush session cache in seconds */
    int                trace;                /* 0 = off; 1 = on */
    Ns_Mutex           lock;
    SSL_CTX           *sslctx;
} Ns_OpenSSLContext;

/*
 * Used to manage SSL drivers on top of the AOLserver comm driver.
 */

typedef struct NsOpenSSLDriver {
    char                     *server;      
    char                     *module;      
    char                     *name;      
    char                     *path;
    struct Ns_Driver         *driver;        /* Driver that this SSL driver is tied to */
    struct NsOpenSSLDriver   *next;          /* pointer to next driver */
    struct Ns_OpenSSLContext *context;       /* SSL context assoc with this driver */ 
    struct Ns_OpenSSLConn    *firstFreeConn; /* List of unused conn structs */ 
    char                     *dir;
    /* XXX nsd core driver has location, hostname etc. get rid of them here */
#if 0
    char                     *location;
    char                     *hostname;
    char                     *address;	
#endif
    SOCKET                    lsock;
    Ns_Mutex                  lock;
    int                       refcnt;        /* Number of conns tied to this driver */
    /* XXX these are read by Ns_DriverInit directly from config - don't need them here */
#if 0
    int                       port;          /* The port this driver listens on */
    int                       bufsize;
    int                       timeout;
#endif
} NsOpenSSLDriver;

/*
 * Used for both core-driven and C/Tcl API-driven conns
 */

typedef struct Ns_OpenSSLConn {
    char                   *server;
    char                   *module;
    int                     role;
    struct NsOpenSSLDriver *ssldriver;    /* the driver this conn belongs to */
    struct Ns_OpenSSLConn  *next;      /* next conn */
    int                     type;      /* server = 0; client = 1 */
    int                     peerport;  /* port number of remote side */
    char                    peer[16];  /* peer's name */
    X509                   *peercert;  /* peer's cert in PEM format */
    SSL_CTX                *context;   /* XXX SSL context associated with conn */
    SSL                    *ssl;       /* initialized SSL instance itself */
    BIO                    *io;        /* block i/o */
    SOCKET                  sock;
    SOCKET                  wsock;
    Ns_Mutex                lock;
    int                     refcnt;    /* don't ns_free() unless this is 0 */
} Ns_OpenSSLConn;

/*
 * Session cache id management
 */

typedef struct SessionCacheId {
    Ns_Mutex lock;
    int id;
} SessionCacheId;

/*
 * Tcl Commands 
 */

/* XXX Move to one of the .c files */
typedef struct SSLTclCmd {
    char *name;
    Tcl_CmdProc *proc;
    ClientData clientData;
} SSLTclCmd;


/*
 * Default configuration
 */

#define DEFAULT_PORT                   443
#define DEFAULT_PROTOCOL               "https"

#define ROLE_SERVER                    0
#define ROLE_CLIENT                    1

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

#define DEFAULT_SOCKTIMEOUT            30
#define DEFAULT_BUFFERSIZE             16384

#define CONFIG_MODULE_DIR              "ModuleDir"
#define CONFIG_RANDOM_FILE             "RandomFile"

/*
 * If PRNG fails to seed, increase value of SeedBytes in the
 * nsd.tcl file.
 */

#define CONFIG_SEEDBYTES               "SeedBytes"
#define DEFAULT_SEEDBYTES              1024
#define DEFAULT_MAXBYTES               1024000


/*
 * ssl.c
 */

extern Ns_OpenSSLConn *NsOpenSSLConnCreate (SOCKET sock, NsOpenSSLDriver *ssldriver,
        int role);
extern void NsOpenSSLConnDestroy (Ns_OpenSSLConn *sslconn);

extern int NsOpenSSLFlush (Ns_OpenSSLConn *sslconn);

extern int NsOpenSSLRecv (Ns_OpenSSLConn *sslconn, void *buffer, int toread);
extern int NsOpenSSLSend (Ns_OpenSSLConn *sslconn, void *buffer, int towrite);

extern int Ns_OpenSSLFetchPage (Ns_DString *page, char *url, char *server);
extern int Ns_OpenSSLFetchURL (Ns_DString *page, char *url,
		Ns_Set *headers);
extern void NsOpenSSLTrace (SSL *ssl, int where, int rc);
extern int NsOpenSSLShutdown (SSL *ssl);
extern int Ns_OpenSSLIsPeerCertValid (Ns_OpenSSLConn *sslconn);

/*
 * tclcmds.c
 */

extern int NsOpenSSLCreateCmds (Tcl_Interp *interp, void *arg);

extern Ns_TclInterpInitProc NsOpenSSLCreateCmds;
extern Tcl_CmdProc NsTclOpenSSLCmd;
extern Tcl_CmdProc NsTclSSLGetUrlCmd;
extern Tcl_CmdProc NsTclSSLSockOpenCmd;
extern Tcl_CmdProc NsTclSSLSockReadCmd;
extern Tcl_CmdProc NsTclSSLSockWriteCmd;
extern Tcl_CmdProc NsTclSSLSockListenCmd;
extern Tcl_CmdProc NsTclSSLSockAcceptCmd;
extern Tcl_CmdProc NsTclSSLSockNReadCmd;
extern Tcl_CmdProc NsTclSSLSockSelectCmd;
extern Tcl_CmdProc NsTclSSLSockCheckCmd;
extern Tcl_CmdProc NsTclSSLSockSetBlockingCmd;
extern Tcl_CmdProc NsTclSSLSockSetNonBlockingCmd;
extern Tcl_CmdProc NsTclSSLSockCallbackCmd;
extern Tcl_CmdProc NsTclSSLSockListenCallbackCmd;

#if 0				/* not yet implemented */
extern Tcl_CmdProc NsTclSSLSocketPairCmd;
extern Tcl_CmdProc NsTclSSLGetByCmd;
#endif

/*
 * nsopenssl.c
 */

extern NsOpenSSLModuleInit(char *server, char *module);

/* XXX need to have SSL contexts tied to each via sslctx's name */
extern Ns_OpenSSLConn *Ns_OpenSSLSockConnect (char *host, 
		int port, int async, int timeout);

extern Ns_OpenSSLConn *Ns_OpenSSLSockAccept (SOCKET sock);

extern SOCKET Ns_OpenSSLSockListen (char *addr, int port);

extern int Ns_OpenSSLSockCallback (SOCKET sock, 
		Ns_SockProc *proc, void *arg, int when);

extern int Ns_OpenSSLSockListenCallback (char *addr, int port,
		Ns_SockProc *proc, void *arg);

extern Ns_OpenSSLContext *NsOpenSSLContextSockServerDefault (void);
extern Ns_OpenSSLContext *NsOpenSSLContextSockClientDefault (void);

extern Ns_OpenSSLContext *Ns_OpenSSLContextCreate (char *server, 
		char *module);
extern int Ns_OpenSSLContextDestroy(Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextInit(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextModuleDirSet(char *server, char *module, 
        Ns_OpenSSLContext *context, char *moduleDir);
extern char *Ns_OpenSSLContextModuleDirGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextCertFileSet(char *server, char *module, 
        Ns_OpenSSLContext *context, char *certFile);
extern char *Ns_OpenSSLContextCertFileGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextKeyFileSet(char *server, char *module, 
        Ns_OpenSSLContext *context, char *keyFile);
extern char *Ns_OpenSSLContextKeyFileGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextProtocolsSet(char *server, char *module, 
        Ns_OpenSSLContext *context, char *protocols);
extern char *Ns_OpenSSLContextProtocolsGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextCipherSuiteSet(char *server, char *module, 
        Ns_OpenSSLContext *context, char *cipherSuite);
extern char *Ns_OpenSSLContextCipherSuiteGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextCAFileSet(char *server, char *module, 
        Ns_OpenSSLContext *context, char *CAFile);
extern char *Ns_OpenSSLContextCAFileGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextCADirSet(char *server, char *module, 
        Ns_OpenSSLContext *context, char *CADir);
extern char *Ns_OpenSSLContextCADirGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextPeerVerifySet(char *server, char *module, 
        Ns_OpenSSLContext *context, int peerVerify);
extern int Ns_OpenSSLContextPeerVerifyGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextPeerVerifyDepthSet(char *server, char *module, 
        Ns_OpenSSLContext *context, int peerVerifyDepth);
extern int Ns_OpenSSLContextPeerVerifyDepthGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int NsOpenSSLSessionCacheInit(void);
extern int Ns_OpenSSLContextSessionCacheSet(char *server, char *module, 
        Ns_OpenSSLContext *context, int sessionCache);
extern int Ns_OpenSSLContextSessionCacheGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextSessionCacheSizeSet(char *server, char *module, 
        Ns_OpenSSLContext *context, int sessionCacheSize);
extern int Ns_OpenSSLContextSessionCacheSizeGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextSessionCacheTimeoutSet(char *server, char *module, 
        Ns_OpenSSLContext *context, int sessionCacheTimeout);
extern int Ns_OpenSSLContextSessionCacheTimeoutGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int Ns_OpenSSLContextTraceSet(char *server, char *module, 
        Ns_OpenSSLContext *context, int trace);
extern int Ns_OpenSSLContextTraceGet(char *server, char *module, 
        Ns_OpenSSLContext *context);

extern int NsOpenSSLDriverInit(char *server, char *module, char *name);
extern void NsOpenSSLDriverDestroy(NsOpenSSLDriver *ssldriver);



