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
 * Copyright (C) 1999 Stefan Arentz
 * Copyright (C) 2000 Scott S. Goodwin
 * Copyright (C) 2000 Rob Mayoff
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#ifdef closesocket
/* openssl and nsd both define this */
#undef closesocket
#endif

#include <ns.h>

#define DRIVER_NAME                   "nsopenssl"

/*
 * The encryption library may be different. For example, you may have
 * OpenSSL as the LIBRARY but BSAFE 4.3 as the CRYPTO_LIBRARY. There
 * should be ifdef's here that'll handle this later. But I haven't set
 * it up to autodetect BSAFE cryptolib yet.
 */

#define SSL_LIBRARY_NAME  "OpenSSL"
#if OPENSSL_VERSION_NUMBER == 0x0090601fL
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

#define SSL_CRYPTO_LIBRARY_NAME   "OpenSSL"
#define SSL_CRYPTO_LIBRARY_VERSION  SSL_LIBRARY_VERSION 

struct NsServerSSLConnection;

typedef struct NsOpenSSLDriver {
    struct NsOpenSSLDriver   *nextPtr;
    struct NsServerSSLConnection *firstFreePtr;

    Ns_Mutex         lock;
    int              refcnt;
    Ns_Driver        driver;

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

    SSL_CTX         *context;

    char            *randomFile;   /* Used to seed PRNG */
} NsOpenSSLDriver;

typedef struct NsServerSSLConnection {
    struct NsServerSSLConnection *nextPtr;
    struct NsOpenSSLDriver   *sdPtr;

    SOCKET  sock;
#ifndef NS_MAJOR_VERSION
    char    peer[16];
    int     port;
#endif

    SSL    *ssl;
    BIO    *io;

    X509   *clientcert;
} NsServerSSLConnection;

/*
 * init.c
 */

#ifndef NS_MAJOR_VERSION
extern NsOpenSSLDriver *NsOpenSSLCreateDriver(char *server, char *module,
    Ns_DrvProc *procs);
#else
extern NsOpenSSLDriver *NsOpenSSLCreateDriver(char *server, char *module);
#endif
extern void NsOpenSSLFreeDriver(NsOpenSSLDriver *sdPtr);

/*
 * ssl.c
 */

extern int NsServerSSLCreateConn(NsServerSSLConnection *scPtr);
extern void NsServerSSLDestroyConn(NsServerSSLConnection *scPtr);
extern void NsServerSSLTrace(SSL *ssl, int where, int rc);
extern int NsServerSSLShutdownConn(SSL *ssl);

/*
 * nsopenssl.c
 */

extern int NsServerSSLFlushConn(NsServerSSLConnection *scPtr);
extern void NsDestroySSLConn(NsServerSSLConnection *scPtr);
extern int NsServerSSLRecv(NsServerSSLConnection *scPtr, void *buffer,
    int toread);
extern int NsServerSSLSend(NsServerSSLConnection *scPtr, void *buffer,
    int towrite);

