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

/* Doesn't work
 * include <openssl/opensslconf.h>
 * 
 * define OPENSSL_THREAD_DEFINES
 * ifndef THREADS
 * error "OpenSSL was not compiled with thread support!"
 * endif
 */

#ifdef NS_MAJOR_VERSION
#define AOLSERVER_4
#else
#define AOLSERVER_3
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
    Ns_Mutex           lock;
    int                refcnt; 
    char              *server; 
    char              *module;
    struct Ns_OpenSSLContext *next;
    int                conntype;
    char              *name;
    char              *desc;
    char              *certfile;             /* Cert file, PEM format */
    char              *keyfile;              /* Key file, PEM format */
    char              *protocols;            /* Protocols to use */
    char              *ciphersuite;          /* OpenSSL-formatted cipher string */
    char              *cafile;               /* CA file, PEM format, concatenated */
    char              *cadir;                /* CA dir */
    char              *crlfile;              /* CRL file */
    char              *crldir;               /* CRL directory */
    int                peerverifyon;         /* 0 = peer verify off; 1 = peer verify on */
    int                peerverifydepth;      /* How deep do we allow a verification path to be? */
    int                peerabortoninvalid;   /* 1 = abort on invalid peer cert */
    char              *peerabortproc;        /* Tcl proc that will handle the aborted conn */
    int                sessioncacheon;       /* 0 = off; 1 = on */
    int                sessioncacheid;
    int                sessioncachesize;     /* In bytes */
    int                sessioncachetimeout;  /* Flush session cache in seconds */
    int                trace;                /* 0 = off; 1 = on */
    SSL_CTX           *sslctx;
} Ns_OpenSSLContext;

typedef struct NsOpenSSLDriver {
    Ns_Mutex           lock;
    int                refcnt;
    char              *server;      
    char              *module;      
    struct NsOpenSSLDriver   *next;       
    struct Ns_OpenSSLConn    *firstFree;  
    struct Ns_OpenSSLContext *context; 
    struct Ns_Driver         *driver;
    char              *configPath;
    char              *dir;
    char              *location;
    char              *address;	
    char              *bindaddr;
    char              *randomFile;
    SOCKET             lsock;
    int                port;
    int                bufsize;
    int                timeout;
} NsOpenSSLDriver;

typedef struct Ns_OpenSSLConn {
    Ns_Mutex         lock;
    int              refcnt;
    char            *server;
    char            *module;
    struct Ns_OpenSSLConn  *next;
    struct NsOpenSSLDriver *driver;
    int              conntype;
    int              peerport;
    char             peer[16];
    SOCKET           sock;
    SOCKET           wsock;
    SSL_CTX         *context;
    SSL             *ssl;
    BIO             *io;
    X509            *peercert;
} Ns_OpenSSLConn;

/*
 * Linked lists for managing structures
 */

static Ns_OpenSSLContext *firstSSLContext = NULL;
static Ns_OpenSSLConn    *firstSSLConn    = NULL;
static NsOpenSSLDriver   *firstSSLDriver  = NULL;

/*
 * Session cache id management
 */
 
typedef struct SessionCacheId {
	Ns_Mutex lock;
	int id;
} SessionCacheId;

static SessionCacheId *nextSessionCacheId;

/*
 * Tcl Commands
 */

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

/*
 * Used to determine whether the connection is going
 * through the comm API or not.
 */

#define CONNTYPE_SERVER                0
#define CONNTYPE_SOCKSERVER            1
#define CONNTYPE_SOCKCLIENT            2

#define DEFAULT_CIPHERSUITE            SSL_DEFAULT_CIPHER_LIST
#define DEFAULT_PROTOCOLS              "All"
#define DEFAULT_CERTFILE               "certificate.pem"
#define DEFAULT_KEYFILE                "key.pem"
#define DEFAULT_CAFILE                 "ca.pem"
#define DEFAULT_CADIR                  "ca"
#define DEFAULT_PEERVERIFYON           NS_FALSE
#define DEFAULT_PEERVERIFYDEPTH        10
#define DEFAULT_SESSIONCACHEON         NS_TRUE
#define DEFAULT_SESSIONCACHESIZE       128
#define DEFAULT_SESSIONTIMEOUT         300
#define DEFAULT_TRACE                  NS_FALSE

#define DEFAULT_SOCKTIMEOUT            30
#define DEFAULT_BUFFERSIZE             16384

#define CONFIG_MODULE_DIR              "ModuleDir"
#define CONFIG_RANDOMFILE              "RandomFile"

/*
 * If PRNG fails to seed, increase this number in the
 * nsd.tcl file.
 */

#define CONFIG_SEEDBYTES               "SeedBytes"
#define DEFAULT_SEEDBYTES              1024


/*
 * ssl.c
 */

extern Ns_OpenSSLConn * NsOpenSSLCreateConn (SOCKET sock,
		NsOpenSSLDriver * driver, int role, int conntype);
extern void NsOpenSSLDestroyConn (Ns_OpenSSLConn * conn);
extern int NsOpenSSLFlush (Ns_OpenSSLConn * conn);
extern int NsOpenSSLRecv (Ns_OpenSSLConn * conn, void *buffer, int toread);
extern int NsOpenSSLSend (Ns_OpenSSLConn * conn, void *buffer, int towrite);
extern int Ns_OpenSSLFetchPage (Ns_DString * dsPtr, char *url, char *server);
extern int Ns_OpenSSLFetchURL (Ns_DString * dsPtr, char *url,
		Ns_Set * headers);
extern void NsOpenSSLTrace (SSL * ssl, int where, int rc);
extern int NsOpenSSLShutdown (SSL * ssl);
extern int Ns_OpenSSLIsPeerCertValid (Ns_OpenSSLConn * conn);

/*
 * tclcmds.c
 */

extern int NsOpenSSLCreateCmds (Tcl_Interp * interp, void *arg);

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

extern Ns_OpenSSLConn *Ns_OpenSSLSockConnect (char *name, char *host, 
		int port, int async, int timeout);

extern Ns_OpenSSLConn *Ns_OpenSSLSockAccept (char *name, SOCKET sock);

extern SOCKET Ns_OpenSSLSockListen (char *name, char *addr, int port);

extern int Ns_OpenSSLSockCallback (char *name, SOCKET sock, 
		Ns_SockProc *proc, void *arg, int when);

extern int Ns_OpenSSLSockListenCallback (char *addr, int port,
		Ns_SockProc *proc, void *arg);

extern char *NsOpenSSLGetModuleName (void);

extern Ns_OpenSSLContext *NsOpenSSLContextSockServerDefault (void);
extern Ns_OpenSSLContext *NsOpenSSLContextSockClientDefault (void);

extern Ns_OpenSSLContext *Ns_OpenSSLContextCreate (char *server, 
		char *module, char *name, char *desc, char *type);
