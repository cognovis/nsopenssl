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
 * Copyright (C) 2000-2002 Scott S. Goodwin
 * Copyright (C) 2000 Rob Mayoff
 * Copyright (C) 1999 Stefan Arentz
 *
 * $Header$
 */


/* Required for Tcl channels to work */
#ifndef USE_TCL8X
#define USE_TCL8X
#endif

#include <ns.h>

/* openssl and nsd both define closesocket */
#ifdef closesocket
#undef closesocket
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#define DRIVER_NAME                   "nsopenssl"

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

/* XXX figure out how to autodetect BSAFE vs OpenSSL encryption lib */
#define SSL_CRYPTO_LIBRARY_NAME     SSL_LIBRARY_NAME
#define SSL_CRYPTO_LIBRARY_VERSION  SSL_LIBRARY_VERSION


struct Ns_OpenSSLConn;

typedef struct NsOpenSSLDriver {
    struct NsOpenSSLDriver *nextPtr;
    struct Ns_OpenSSLConn *firstFreePtr;
    Ns_Driver driver;
    Ns_Mutex lock;
    int      refcnt;

    char    *server;		/* Server name */
    char    *module;		/* Module name */
    char    *configPath;	/* E.g. ns/server/s1/module/nsopenssl */
    char    *dir;		/* Module directory (on disk) */
    char    *location;		/* E.g. https://example.com:8443 */
    char    *address;		/* Advertised address */
    char    *bindaddr;		/* Bind address - might be 0.0.0.0 */
    int      port;		/* Bind port */
    int      bufsize;
    int      timeout;

    SSL_CTX *context;		/* XXX change to nsdServerContext */
    SSL_CTX *sockClientContext;
    SSL_CTX *sockServerContext;
    
    SOCKET   lsock;
    char    *randomFile;	/* Used to seed PRNG */
} NsOpenSSLDriver;

typedef struct Ns_OpenSSLConn {
	/* These are NOT to be freed by NsOpenSSLDestroyConn */
    char    *server;		/* Server name */
    char    *module;		/* Module name (e.g. 'nsopenssl') */
    char    *configPath;	/* Path to the configuration file */
    char    *dir;		/* Module directory (on disk) */
    char    *location;		/* E.g. https://example.com:8443 */
    char    *address;		/* Advertised address for this module instance */
    char    *bindaddr;		/* Bind address for this module instance - might be 0.0.0.0 */
    int      port;		/* The port the server is listening on for this module instance */
    int      bufsize;
    int      timeout;

    SSL_CTX *context;		/* Read-only context for creating SSL structs */
        
    /* These must be freed by NsOpenSSLDestroyConn */
    int      refcnt;            /* Don't destroy struct if refcnt > 0 (tclcmds.c) */
    int      role;		/* client or server */
    int      conntype;		/* nsd server, sock server or client server conn */
    char    *type;		/* 'nsdserver', 'sockserver', sockclient' */
    SOCKET   sock;
    SOCKET   wsock;
    SSL     *ssl;
    BIO     *io;		/* All SSL i/o goes through this BIO */
    X509    *peercert;		/* Certificate for peer, may be NULL if no cert */
    char     peer[16];		/* Not used by nsd server conns in 4.x API */
    int      peerport;		/* Not used by nsd server conns in 4.x API */

    /* XXX These two used to be ifdef'd out of AOLserver 4.x compiles
       need to reevaluate. */
    struct Ns_OpenSSLConn *nextPtr;
    struct NsOpenSSLDriver *sdPtr;

} Ns_OpenSSLConn;


typedef struct SSLTclCmd {

    char *name;
    Tcl_CmdProc *proc;
    ClientData clientData;

} SSLTclCmd;


/*
 * Default configuration
 */

#define DEFAULT_PORT                          443
#define DEFAULT_PROTOCOL                      "https"
#define DEFAULT_NAME                          "nsopenssl"

/*
 * Used to determine whether NSD is handling the
 * underlying socket or not.
 */

#define CONNTYPE_SSL_NSD                       0
#define CONNTYPE_SSL_SOCK                      1

/*
 * Used to determine if we're the client or the server
 * for the connection.
 */

#define ROLE_SSL_CLIENT                        0
#define ROLE_SSL_SERVER                        1

#define STR_SOCK_CLIENT                        "sockclient"
#define STR_SOCK_SERVER                        "sockserver"
#define STR_NSD_SERVER                         "nsdserver"

#define CONFIG_SERVER_TRACE                    "ServerTrace"
#define DEFAULT_SERVER_TRACE                   NS_FALSE

#define CONFIG_SOCKSERVER_TRACE                "SockServerTrace"
#define DEFAULT_SOCKSERVER_TRACE               NS_FALSE

#define CONFIG_SOCKCLIENT_TRACE                "SockClientTrace"
#define DEFAULT_SOCKCLIENT_TRACE               NS_FALSE

#define CONFIG_SERVER_CIPHERSUITE              "ServerCipherSuite"
#define DEFAULT_SERVER_CIPHERSUITE             SSL_DEFAULT_CIPHER_LIST

#define CONFIG_SOCKSERVER_CIPHERSUITE          "SockServerCipherSuite"
#define DEFAULT_SOCKSERVER_CIPHERSUITE         SSL_DEFAULT_CIPHER_LIST

#define CONFIG_SOCKCLIENT_CIPHERSUITE          "SockClientCipherSuite"
#define DEFAULT_SOCKCLIENT_CIPHERSUITE         SSL_DEFAULT_CIPHER_LIST

#define	CONFIG_SERVER_PROTOCOLS                "ServerProtocols"
#define DEFAULT_SERVER_PROTOCOLS               "All"

#define	CONFIG_SOCKSERVER_PROTOCOLS            "SockServerProtocols"
#define DEFAULT_SOCKSERVER_PROTOCOLS           "All"

#define	CONFIG_SOCKCLIENT_PROTOCOLS            "SockClientProtocols"
#define DEFAULT_SOCKCLIENT_PROTOCOLS           "All"

#define CONFIG_SERVER_CERTFILE                 "ServerCertFile"
#define DEFAULT_SERVER_CERTFILE                "certificate.pem"

#define CONFIG_SOCKSERVER_CERTFILE             "SockServerCertFile"
#define DEFAULT_SOCKSERVER_CERTFILE            "certificate.pem"

#define CONFIG_SOCKCLIENT_CERTFILE             "SockClientCertFile"
#define DEFAULT_SOCKCLIENT_CERTFILE            NULL

#define CONFIG_SERVER_KEYFILE                  "ServerKeyFile"
#define DEFAULT_SERVER_KEYFILE                 "key.pem"

#define CONFIG_SOCKSERVER_KEYFILE              "SockServerKeyFile"
#define DEFAULT_SOCKSERVER_KEYFILE             "key.pem"

#define CONFIG_SOCKCLIENT_KEYFILE              "SockClientKeyFile"
#define DEFAULT_SOCKCLIENT_KEYFILE             NULL

#define CONFIG_SERVER_CAFILE                   "ServerCAFile"
#define DEFAULT_SERVER_CAFILE                  "ca.pem"

#define CONFIG_SOCKSERVER_CAFILE               "SockServerCAFile"
#define DEFAULT_SOCKSERVER_CAFILE              "ca.pem"

#define CONFIG_SOCKCLIENT_CAFILE               "SockClientCAFile"
#define DEFAULT_SOCKCLIENT_CAFILE              "ca.pem"

#define CONFIG_SERVER_CADIR                    "ServerCADir"
#define DEFAULT_SERVER_CADIR                   "ca"

#define CONFIG_SOCKSERVER_CADIR                "SockServerCADir"
#define DEFAULT_SOCKSERVER_CADIR               "ca"

#define CONFIG_SOCKCLIENT_CADIR                "SockClientCADir"
#define DEFAULT_SOCKCLIENT_CADIR               "ca"

#define CONFIG_SERVER_SESSIONCACHE             "ServerSessionCache"
#define DEFAULT_SERVER_SESSIONCACHE            NS_TRUE

#define CONFIG_SOCKSERVER_SESSIONCACHE         "SockServerSessionCache"
#define DEFAULT_SOCKSERVER_SESSIONCACHE        NS_TRUE

#define CONFIG_SOCKCLIENT_SESSIONCACHE         "SockClientSessionCache"
#define DEFAULT_SOCKCLIENT_SESSIONCACHE        NS_TRUE

#define CONFIG_SERVER_SESSIONCACHEID           "ServerSessionCacheId"
#define DEFAULT_SERVER_SESSIONCACHEID          1

#define CONFIG_SOCKSERVER_SESSIONCACHEID       "SockServerSessionCacheId"
#define DEFAULT_SOCKSERVER_SESSIONCACHEID      2

#define CONFIG_SOCKCLIENT_SESSIONCACHEID       "SockClientSessionCacheId"
#define DEFAULT_SOCKCLIENT_SESSIONCACHEID      3

#define CONFIG_SERVER_SESSIONCACHESIZE         "ServerSessionCacheSize"
#define DEFAULT_SERVER_SESSIONCACHESIZE        128

#define CONFIG_SOCKSERVER_SESSIONCACHESIZE     "SockServerSessionCacheSize"
#define DEFAULT_SOCKSERVER_SESSIONCACHESIZE    128

#define CONFIG_SOCKCLIENT_SESSIONCACHESIZE     "SockClientSessionCacheSize"
#define DEFAULT_SOCKCLIENT_SESSIONCACHESIZE    128

#define CONFIG_SERVER_SESSIONTIMEOUT           "ServerSessionTimeout"
#define DEFAULT_SERVER_SESSIONTIMEOUT          300

#define CONFIG_SOCKSERVER_SESSIONTIMEOUT       "SockServerSessionTimeout"
#define DEFAULT_SOCKSERVER_SESSIONTIMEOUT      300

#define CONFIG_SOCKCLIENT_SESSIONTIMEOUT       "SockClientSessionTimeout"
#define DEFAULT_SOCKCLIENT_SESSIONTIMEOUT      300

#define CONFIG_SERVER_SOCKTIMEOUT              "ServerSockTimeout"
#define DEFAULT_SERVER_SOCKTIMEOUT             30

#define CONFIG_SOCKSERVER_SOCKTIMEOUT          "SockServerSockTimeout"
#define DEFAULT_SOCKSERVER_SOCKTIMEOUT         30

#define CONFIG_SOCKCLIENT_SOCKTIMEOUT          "SockClientSockTimeout"
#define DEFAULT_SOCKCLIENT_SOCKTIMEOUT         30

#define CONFIG_SERVER_BUFFERSIZE               "ServerBufferSize"
#define DEFAULT_SERVER_BUFFERSIZE              16384

#define CONFIG_SOCKSERVER_BUFFERSIZE           "SockServerBufferSize"
#define DEFAULT_SOCKSERVER_BUFFERSIZE          16384

#define CONFIG_SOCKCLIENT_BUFFERSIZE           "SockClientBufferSize"
#define DEFAULT_SOCKCLIENT_BUFFERSIZE          16384

#define CONFIG_SERVER_PEERVERIFY               "ServerPeerVerify"
#define DEFAULT_SERVER_PEERVERIFY              NS_FALSE

#define CONFIG_SOCKSERVER_PEERVERIFY           "SockServerPeerVerify"
#define DEFAULT_SOCKSERVER_PEERVERIFY          NS_FALSE

#define CONFIG_SOCKCLIENT_PEERVERIFY           "SockClientPeerVerify"
#define DEFAULT_SOCKCLIENT_PEERVERIFY          NS_TRUE

#define CONFIG_SERVER_VERIFYDEPTH              "ServerPeerVerifyDepth"
#define DEFAULT_SERVER_VERIFYDEPTH             10

#define CONFIG_SOCKSERVER_VERIFYDEPTH          "SockServerPeerVerifyDepth"
#define DEFAULT_SOCKSERVER_VERIFYDEPTH         10

#define CONFIG_SOCKCLIENT_VERIFYDEPTH          "SockClientPeerVerifyDepth"
#define DEFAULT_SOCKCLIENT_VERIFYDEPTH         10

#define CONFIG_MODULE_DIR           "ModuleDir"

#define CONFIG_RANDOMFILE           "RandomFile"

/*
 * If PRNG fails to seed, increase this number in the
 * nsd.tcl file.
 */

#define CONFIG_SEEDBYTES            "SeedBytes"
#define DEFAULT_SEEDBYTES           1024


/*
 * init.c
 */

#ifndef NS_MAJOR_VERSION
extern NsOpenSSLDriver *NsOpenSSLCreateDriver (char *server, char *module,
					       Ns_DrvProc * procs);
#else
extern NsOpenSSLDriver *NsOpenSSLCreateDriver (char *server, char *module);
#endif
extern void NsOpenSSLFreeDriver (NsOpenSSLDriver * sdPtr);

/*
 * ssl.c
 */

extern int NsOpenSSLCreateConn (Ns_OpenSSLConn * ccPtr);
extern void NsOpenSSLDestroyConn (Ns_OpenSSLConn * ccPtr);
extern int NsOpenSSLFlush (Ns_OpenSSLConn * ccPtr);
extern int NsOpenSSLRecv (Ns_OpenSSLConn * ccPtr, void *buffer, int toread);
extern int NsOpenSSLSend (Ns_OpenSSLConn * ccPtr, void *buffer, int towrite);
extern Ns_OpenSSLConn *Ns_OpenSSLSockConnect (char *host, int port, int async,
					      int timeout);
extern int Ns_OpenSSLFetchPage (Ns_DString * dsPtr, char *url, char *server);
extern int Ns_OpenSSLFetchURL (Ns_DString * dsPtr, char *url,
			       Ns_Set * headers);
extern int Ns_OpenSSLSockCallback (SOCKET sock, Ns_SockProc * proc,
				   void *arg, int when);
extern int Ns_OpenSSLSockListenCallback (char *addr, int port,
					 Ns_SockProc * proc, void *arg);
extern SOCKET Ns_OpenSSLSockListen (char *address, int port);
extern Ns_OpenSSLConn *Ns_OpenSSLSockAccept (SOCKET sock);
extern void NsOpenSSLTrace (SSL * ssl, int where, int rc);
extern int NsOpenSSLShutdown (SSL * ssl);
extern int Ns_OpenSSLIsPeerCertValid (Ns_OpenSSLConn * ccPtr);

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

extern char *NsOpenSSLGetModuleName (void);
extern SSL_CTX *NsOpenSSLGetSockServerSSLContext (void);
extern SSL_CTX *NsOpenSSLGetSockClientSSLContext (void);

/*
 * thread.c
 */

extern int NsOpenSSLInitThreads (void);

