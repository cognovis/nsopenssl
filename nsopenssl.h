/*
 * The contents of this file are subject to the AOLserver Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://aolserver.lcs.mit.edu/.
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
 * Copyright (C) 2000-2002 Scott S. Goodwin
 * Copyright (C) 2000 Rob Mayoff
 * Copyright (C) 1999 Stefan Arentz
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
 */

/* @(#) $Header$ */

#if 0 /* XXX need to add version.h to AOLserver core */
/* XXX set this to have nsopenssl compile with aolserver 4.x */
#define NS_MAJOR_VERSION 4
#endif

/* Required for Tcl channels to work */
#ifndef USE_TCL8X
#define USE_TCL8X
#endif

#include <ns.h>

#ifdef closesocket
/* openssl and nsd both define this */
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

#include <openssl/opensslv.h>
#define SSL_LIBRARY_NAME     "OpenSSL"
#define SSL_LIBRARY_VERSION  OPENSSL_VERSION_TEXT

struct Ns_OpenSSLConn;

typedef struct NsOpenSSLDriver {

    struct NsOpenSSLDriver     *nextPtr;
    struct Ns_OpenSSLConn *firstFreePtr;

    Ns_Mutex         lock;
    int              refcnt;
    Ns_Driver        driver;

    char            *server;       /* Server name */
    char            *module;       /* Module name */
    char            *configPath;   /* E.g. ns/server/s1/module/nsopenssl */
    char            *dir;          /* Module directory (on disk) */

    char            *location;     /* E.g. https://example.com:8443 */
    char            *address;      /* Advertised address */
    char            *bindaddr;     /* Bind address - might be 0.0.0.0 */
    int              port;         /* Bind port */

    int              bufsize;
    int              timeout;
    SOCKET           lsock;

    SSL_CTX         *context; /* XXX change to nsdServerContext */
    SSL_CTX         *sockClientContext;
    SSL_CTX         *sockServerContext;

    char            *randomFile;   /* Used to seed PRNG */

} NsOpenSSLDriver;

typedef struct Ns_OpenSSLConn {

    char        *server;     /* Server name */
    char        *module;     /* Module name (e.g. 'nsopenssl') */
    char        *configPath; /* Path to the configuration file */
    char        *dir;        /* Module directory (on disk) */

    int          refcnt;     /* Don't free if refcnt > 0 */

    int          role;       /* client or server */
    int          conntype;   /* nsd server, sock server or client server conn */
    char        *type;       /* 'nsdserver', 'sockserver', sockclient' */

    int          bufsize;
    int          timeout;
    time_t       sendtimer;  /* XXX tmp inactivity timer to fix hanging thread */
    time_t       recvtimer;  /* XXX tmp inactivity timer to fix hanging thread */

    SOCKET       sock;
    SOCKET       wsock;

    SSL_CTX     *context;    /* Read-only context for creating SSL structs */
    SSL         *ssl;
    BIO         *io;         /* All SSL i/o goes through this BIO */
    X509        *peercert;   /* Certificate for peer, may be NULL if no cert */

    char         peer[16];   /* Not used by nsd server conns in 4.x API */
    int          port;       /* Not used by nsd server conns in 4.x API */

#ifndef NS_MAJOR_VERSION
    struct Ns_OpenSSLConn   *nextPtr;
    struct NsOpenSSLDriver  *sdPtr;
#endif

} Ns_OpenSSLConn;


typedef struct SSLTclCmd {

    char           *name;
    Tcl_CmdProc    *proc;
    ClientData      clientData;

} SSLTclCmd;

/*
 * config.c
 */

extern char *ConfigStringDefault(char *module, char *path, char *name,
    char *def);
extern int ConfigBoolDefault(char *module, char *path, char *name,
    int def);
extern int ConfigIntDefault(char *module, char *path, char *name,
    int def); 
extern char *ConfigPathDefault(char *module, char *path, char *name,
    char *dir, char *def); 

/*
 * init.c
 */

#ifndef NS_MAJOR_VERSION
extern NsOpenSSLDriver *NsOpenSSLCreateDriver(char *server, char *module,
           Ns_DrvProc *procs);
#else
extern NsOpenSSLDriver *NsOpenSSLCreateDriver(char *server, char *module);
#endif
extern void     NsOpenSSLFreeDriver(NsOpenSSLDriver *sdPtr);

/*
 * ssl.c
 */

extern int            NsOpenSSLCreateConn(Ns_OpenSSLConn *ccPtr);
extern void           NsOpenSSLDestroyConn(Ns_OpenSSLConn *ccPtr);
extern int            NsOpenSSLFlush(Ns_OpenSSLConn *ccPtr);
extern int            NsOpenSSLRecv(Ns_OpenSSLConn *ccPtr, void *buffer,
			  int toread);
extern int            NsOpenSSLSend(Ns_OpenSSLConn *ccPtr, void *buffer,
			  int towrite);
extern Ns_OpenSSLConn *Ns_OpenSSLSockConnect(char *host, int port, int async,
			  int timeout);
extern int            Ns_OpenSSLFetchPage(Ns_DString *dsPtr, char *url,
                          char *server);
extern int            Ns_OpenSSLFetchURL(Ns_DString *dsPtr, char *url,
                          Ns_Set *headers);
extern int            Ns_OpenSSLSockCallback(SOCKET sock, Ns_SockProc *proc,
                          void *arg, int when);
extern int            Ns_OpenSSLSockListenCallback(char *addr, int port,
                          Ns_SockProc *proc, void *arg);
extern SOCKET         Ns_OpenSSLSockListen(char *address, int port);
extern Ns_OpenSSLConn *Ns_OpenSSLSockAccept(SOCKET sock);
extern void           NsOpenSSLTrace(SSL *ssl, int where, int rc);
extern int            NsOpenSSLShutdown(SSL *ssl);
extern int            Ns_OpenSSLIsPeerCertValid(Ns_OpenSSLConn *ccPtr);

/*
 * tclcmds.c
 */

extern int NsOpenSSLCreateCmds(Tcl_Interp *interp, void *arg);

/*
 * nsopenssl.c
 */

extern char    *NsOpenSSLGetModuleName(void);
extern SSL_CTX *NsOpenSSLGetSockServerSSLContext(void);
extern SSL_CTX *NsOpenSSLGetSockClientSSLContext(void);

