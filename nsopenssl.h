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

/*
static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;
*/

#define DRIVER_NAME                   "nsopenssl"

/*
 * The encryption library may be different. For example, you may have
 * OpenSSL as the LIBRARY but BSAFE 4.3 as the CRYPTO_LIBRARY. There
 * should be ifdef's here that'll handle this later.
 */

#define SSL_LIBRARY_NAME               "OpenSSL"
#define SSL_LIBRARY_VERSION            "0.9.5a"
#define SSL_CRYPTO_LIBRARY_NAME        "OpenSSL"
#define SSL_CRYPTO_LIBRARY_VERSION     "0.9.5a"

#define SSL_PROTOCOL_NONE  (0)
#define SSL_PROTOCOL_SSLV2 (1<<0)
#define SSL_PROTOCOL_SSLV3 (1<<1)
#define SSL_PROTOCOL_TLSV1 (1<<2)
#define SSL_PROTOCOL_ALL   (SSL_PROTOCOL_SSLV2|SSL_PROTOCOL_SSLV3|SSL_PROTOCOL_TLSV1)

#define DEFAULT_PORT		     443
#define DEFAULT_PROTOCOL 	     "https"
#define DEFAULT_NAME		     "nsopenssl"

#define CONFIG_CIPHERSUITE           "CipherSuite"
#define DEFAULT_CIPHERSUITE          SSL_DEFAULT_CIPHER_LIST

#define CONFIG_PROTOCOL_LIST         "Protocol"
#define DEFAULT_PROTOCOL_LIST        "SSLv2,SSLv3,TLSv1"

#define CONFIG_CERTFILE              "CertFile"
#define DEFAULT_CERTFILE             "certificate.pem"

#define CONFIG_KEYFILE               "KeyFile"
#define DEFAULT_KEYFILE              "key.pem"

#define CONFIG_CACERTPATH            "ClientCACertPath"
#define DEFAULT_CACERTPATH          "ssl.ca"
#define CONFIG_CACERTFILE            "ClientCACertFile"
#define DEFAULT_CACERTFILE          "ssl.ca/ca-bundle.crt"

#define CONFIG_CLIENTVERIFY          "ClientVerify"
#define DEFAULT_CLIENTVERIFY         NS_FALSE

#define CONFIG_CLIENTVERIFYDEPTH     "ClientVerifyDepth"
#define DEFAULT_CLIENTVERIFYDEPTH    1

#define CONFIG_CLIENTVERIFYONCE      "ClientVerifyOnce"
#define DEFAULT_CLIENTVERIFYONCE     NS_TRUE

#define CONFIG_CLIENTVERIFYDEFAULT   "ClientVerifyDefault"
#define DEFAULT_CLIENTVERIFYDEFAULT  NS_FALSE

#define CONFIG_SESSIONCACHE          "SessionCache"
#define CONFIG_SESSIONCACHESIZE      "SessionCacheSize"
#define CONFIG_SESSIONCACHETIMEOUT   "SessionCacheTimeout"
#define DEFAULT_SESSIONCACHE         NS_TRUE
#define DEFAULT_SESSIONCACHESIZE     128
#define DEFAULT_SESSIONCACHETIMEOUT  300

#define BUFSIZZ 16*1024
static int Bufsize = BUFSIZZ;

/*
 * SSLConf is used to pass configuration parameters from NsModuleInit
 * to NsSSLCreateServer. NsSSLCreateServer then creates a server
 * context (think of it like a template) which is used to create a new
 * connection structure in NsSSLCreateConn for each incoming
 * connection.
 */

typedef struct SSLConf {
  char *certfile;           /* server's cert file */
  char *keyfile;            /* server's key file */
  char *ciphersuite;
  int  protocols;           /* SSLv2, SSLv3, TLSv1, ALL */
  char *cacertfile;
  char *cacertpath;
  int  clientverifymode;    /* determines whether we ask for client cert */
  int  clientverifydepth;   /* how deep we allow the ca chain */
  int  clientverifyonce;    /* don't keep revalidating the cert on session reuse */
  int  clientverifydefault; /* don't abort conn if no client cert or cert is invalid */
  int  cache;
  int  cachesize;
  int  cachetimeout;
} SSLConf;

typedef struct SSLServer {
    SSL_CTX *context;
    SSL_METHOD *method;
    char *certfile;
    char *keyfile;
    Ns_Cache *cachehash;
    char *ciphersuite;
    int  cachesize;
    int  cachetimeout;
    int  protocols;
    int  clientverify;
} SSLServer;

typedef struct SSLConnection {
    SSLServer *server;
    SSL  *ssl;
    BIO  *io;
    BIO  *ssl_bio;
    X509 *clientcert;
    int  clientcertisvalid;
} SSLConnection;

typedef struct SSLSessionCacheEntry {
    time_t time;		/* Entry time of this cache entry */
    int size;			/* Size of the data */
    void *data;			/* Ptr to the data */
} SSLSessionCacheEntry;

struct ConnData;

typedef struct SockDrv {
    struct SockDrv *nextPtr;
    struct ConnData *firstFreePtr;
    Ns_Mutex lock;
    int refcnt;
    Ns_Driver driver;
    char *name;
    char *location;
    char *address;
    char *bindaddr;
    int port;
    int bufsize;
    int timeout;
    SOCKET lsock;
    SSLServer *server;
} SockDrv;

typedef struct ConnData {
    struct ConnData *nextPtr;
    struct SockDrv *sdPtr;
    SOCKET sock;
    char peer[16];
    int port;
    SSLConnection *conn; /* This is here so we can get the conn data from within Tcl commands */
    int cnt;
    char *base;
    char buf[1];
} ConnData;

/* need to lose this? */
static int debug;

/*
 * SSL functions
 */

extern SSLServer *
NsSSLCreateServer (SSLConf * config);

extern int
NsSSLDestroyServer (SSLServer * server);

extern int
NsSSLFlush (SSLConnection * conn);

extern SSLConnection *
NsSSLCreateConn (SOCKET sock, int timeout,
		 SSLServer * server);

extern int
NsSSLDestroyConn (SSLConnection * conn);

extern int
NsSSLRecv (SSLConnection * conn, void *buffer, int toread);

extern int
NsSSLSend (SSLConnection * conn, void *buffer, int towrite);

extern SSLConnection *
NsSSLGetConn(Ns_Conn *conn);

/*
 * Cache functions
 */

extern int
NsSSLNewSessionCacheEntry (SSL * ssl, SSL_SESSION * session);

extern SSL_SESSION *
NsSSLGetSessionCacheEntry (SSL * ssl, unsigned char *id,
			   int idlen, int *pCopy);

extern void
NsSSLDelSessionCacheEntry (SSL_CTX * ctx, SSL_SESSION * pSession);

extern void
NsSSLFreeEntry (SSLSessionCacheEntry * cacheEntry);

/*
 * OpenSSL tracing
 */

extern void
NsSSLLogTracingState (SSL * ssl, int where, int rc);







