/*
 * The contents of this file are subject to the AOLserver Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://aolserver.com/.
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
 * Copyright (C) 1999 Stefan Arentz.
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
 * nsopenssl.c - version 0.2
 * Written by Stefan Arentz, stefan.arentz@soze.com
 *
 * This module implements an SSL socket driver using the OpenSSL library.
 *
 * WARNING THIS IS ALPHA SOFTWARE. IT HAS NOT BEEN TESTED AND SHOULD NOT
 * BE USED IN A PRODUCTION ENVIRONMENT. USE AT YOUR OWN RISK.
 *
 * Todo:
 *
 *  Add configuration options to configure OpenSSL caching.
 *  Better error messages in the logfile
 *  Bind on all interfaces if 'address' if not specified.
 *  Test test test test and test.
 *  Implement the 'debug' configuration option.
 *
 * References:
 *
 *  Distribution - http://stefan.arentz.nl/software/
 *  OpenSSL - http://www.openssl.org
 *  AOLServer Home - http://www.aolserver.com
 *  SSL for Apache - http://www.modssl.org
 *
 */



static const char *RCSID = "@(#) $Header$, compiled: " __DATE__ " " __TIME__;



#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>

#include "ns.h"



#define DEFAULT_PORT		     443
#define DEFAULT_PROTOCOL 	     "https"
#define DEFAULT_NAME		     "nsopenssl"

#define DEFAULT_CIPHERSUITE          SSL_DEFAULT_CIPHER_LIST
#define CONFIG_CIPHERSUITE           "CipherSuite"

#define CONFIG_CERTFILE              "CertFile"
#define CONFIG_KEYFILE               "KeyFile"

#define DEFAULT_CERTFILE             "certificate.pem"
#define DEFAULT_KEYFILE              "key.pem"

#define CONFIG_SESSIONCACHE          "SessionCache"
#define CONFIG_SESSIONCACHESIZE      "SessionCacheSize"
#define CONFIG_SESSIONCACHETIMEOUT   "SessionCacheTimeout"

#define DEFAULT_SESSIONCACHE         NS_TRUE
#define DEFAULT_SESSIONCACHESIZE     128
#define DEFAULT_SESSIONCACHETIMEOUT  300


typedef struct SSLServer {
    SSL_CTX*      context;
    SSL_METHOD*   method;
    char*         certfile;
    char*         keyfile;
    Tcl_HashTable cachehash;
    Ns_Mutex      cachemutex;
    int           cachesize;
    int           cachetimeout;
    char*         ciphersuite;
} SSLServer;

typedef struct SSLConnection {
    SSLServer* server;
    SSL*       ssl;
} SSLConnection;

typedef struct SSLSessionCacheEntry {
    time_t time;		/* Entry time of this cache entry */
    int    size;		/* Size of the data */
    void*  data;		/* Ptr to the data */
} SSLSessionCacheEntry;


struct ConnData;

typedef struct SockDrv {
    struct SockDrv *nextPtr;
    struct ConnData *firstFreePtr;
    Ns_Mutex	 lock;
    int		 refcnt;
    Ns_Driver	 driver;
    char        *name;
    char        *location;
    char        *address;
    char        *bindaddr;
    int          port;
    int     	 bufsize;
    int     	 timeout;
    SOCKET       lsock;
    SSLServer	*server;
} SockDrv;

typedef struct ConnData {
    struct ConnData *nextPtr;
    struct SockDrv  *sdPtr;
    SOCKET	     sock;
    char	     peer[16];
    int		     port;
    SSLConnection   *conn;
    int		     cnt;
    char            *base;
    char	     buf[1];
} ConnData;


/*
 * Local functions defined in this file
 */

static int debug;
static Ns_ThreadProc SockThread;
static void SockFreeConn(SockDrv *sdPtr, ConnData *cdPtr);
static SockDrv *firstSockDrvPtr;
static Ns_Thread sockThread;
static SOCKET trigPipe[2];

static Ns_DriverStartProc SockStart;
static Ns_DriverStopProc SockStop;
static Ns_ConnReadProc SockRead;
static Ns_ConnWriteProc SockWrite;
static Ns_ConnCloseProc SockClose;
static Ns_ConnConnectionFdProc SockConnectionFd;
static Ns_ConnDetachProc SockDetach;
static Ns_ConnPeerProc SockPeer;
static Ns_ConnLocationProc SockLocation;
static Ns_ConnPeerPortProc SockPeerPort;
static Ns_ConnPortProc SockPort;
static Ns_ConnHostProc SockHost;
static Ns_ConnDriverNameProc SockName;
static Ns_ConnInitProc SockInit;

static SSLServer* NsSSLCreateServer(char *cert, char *key, int cachesize, int cachetimeout, char *ciphersuite);
static int NsSSLDestroyServer(SSLServer *server);
static int NsSSLFlush(SSLConnection *conn);
static SSLConnection* NsSSLCreateConn(SOCKET sock, int timeout, SSLServer *server);
static int NsSSLDestroyConn(SSLConnection *conn);
static int NsSSLRecv(SSLConnection *conn, void *buffer, int toread);
static int NsSSLSend(SSLConnection *conn, void *buffer, int towrite);

static int SSL_smart_shutdown(SSL *ssl);

static int NsSSLNewSessionCacheEntry(SSL *ssl, SSL_SESSION *session);
static SSL_SESSION* NsSSLGetSessionCacheEntry(SSL *ssl, unsigned char *id, int idlen, int *pCopy);
static void NsSSLDelSessionCacheEntry(SSL_CTX *ctx, SSL_SESSION *pSession);



static Ns_DrvProc sockProcs[] = {
    {Ns_DrvIdStart,        (void *) SockStart},
    {Ns_DrvIdStop,         (void *) SockStop},
    {Ns_DrvIdRead,         (void *) SockRead},
    {Ns_DrvIdWrite,        (void *) SockWrite},
    {Ns_DrvIdClose,        (void *) SockClose},
    {Ns_DrvIdHost,         (void *) SockHost},
    {Ns_DrvIdPort,         (void *) SockPort},
    {Ns_DrvIdName,         (void *) SockName},
    {Ns_DrvIdPeer,         (void *) SockPeer},
    {Ns_DrvIdPeerPort,     (void *) SockPeerPort},
    {Ns_DrvIdLocation,     (void *) SockLocation},
    {Ns_DrvIdConnectionFd, (void *) SockConnectionFd},
    {Ns_DrvIdDetach,       (void *) SockDetach},
    {Ns_DrvIdInit,         (void *) SockInit},
    {0,                    NULL}
};



#ifndef NS_EXPORT
# define NS_EXPORT
#endif



NS_EXPORT int Ns_ModuleVersion = 1;


/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *	Sock module init routine.
 *
 * Results:
 *	NS_OK if initialized ok, NS_ERROR otherwise.
 *
 * Side effects:
 *	Calls Ns_RegisterLocation as specified by this instance
 *	in the config file.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int
Ns_ModuleInit(char *server, char *module)
{
    char *path,*address, *host, *bindaddr;
    int n;
    Ns_DString ds;
    struct in_addr  ia;
    struct hostent *he;
    SockDrv *sdPtr;
    char *certfile, *keyfile, *ciphersuite;
    int cache, cachesize, cachetimeout;
    
    /*
     * Global SSL Initialization.
     */
    
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    /*
     * Do we want debugging?
     */

    path = Ns_ConfigGetPath(server, module, NULL);    
    if (Ns_ConfigGetBool(path, "debug", &debug) == NS_FALSE) {
	debug = 0;
    }

    /*
     * Determine the hostname used for the local address to bind
     * to and/or the HTTP location string.
     */

    host = Ns_ConfigGet(path, "hostname");
    bindaddr = address = Ns_ConfigGet(path, "address");

    /*
     * If the listen address was not specified, attempt to determine it
     * through a DNS lookup of the specified hostname or the server's
     * primary hostname.
     */

    if (address == NULL) {
        he = gethostbyname(host ? host : Ns_InfoHostname());

        /*
	 * If the lookup suceeded but the resulting hostname does not
	 * appear to be fully qualified, attempt a reverse lookup on the
	 * address which often return the fully qualified name.
	 *
	 * NB: This is a common, but sloppy configuration for a Unix
	 * network.
	 */

        if (he != NULL && he->h_name != NULL &&
	    strchr(he->h_name, '.') == NULL) {
            he = gethostbyaddr(he->h_addr, he->h_length, he->h_addrtype);
	}

	/*
	 * If the lookup suceeded, use the first address in host entry list.
	 */

        if (he == NULL || he->h_name == NULL) {
            Ns_Log(Error, "nsopenssl(%s):  Could not resolve '%s':  %s", module,
		host ? host : Ns_InfoHostname(), strerror(errno));
	    return NS_ERROR;
	}
        if (*(he->h_addr_list) == NULL) {
            Ns_Log(Error, "nsopenssl(%s): NULL address list in (derived) "
	           "host entry for '%s'", module, he->h_name);
	    return NS_ERROR;
	}
        memcpy(&ia.s_addr, *(he->h_addr_list), sizeof(ia.s_addr));
        address = ns_inet_ntoa(ia);

	/*
	 * Finally, if no hostname was specified, set it to the hostname
	 * derived from the lookup(s) above.
	 */ 

	if (host == NULL) {
	    host = he->h_name;
	}
    }

    /*
     * If the hostname was not specified and not determined by the loookups
     * above, set it to the specified or derived IP address string.
     */

    if (host == NULL) {
	host = address;
    }

    /*
     * Determine the port and then set the HTTP location string either
     * as specified in the config file or constructed from the
     * hostname and port.
     */

    sdPtr = ns_calloc(1, sizeof(SockDrv));
    
    /*
     * Create the module specific directory.
     */

    Ns_DStringInit(&ds);
    
    Ns_ModulePath(&ds, server, module, NULL, NULL);
    if (mkdir(Ns_DStringValue(&ds), 0755) != 0 && errno != EEXIST) {
	Ns_Log(Error, "mkdir(%s) failed: %s", Ns_DStringValue(&ds), strerror(errno));
	return NS_ERROR;
    }

    /*
     * Determine the path to the SSL Certificate and Public Key file. If the
     * paths are not absolute then we assume that the files are stored in the module
     * specific directory .../server1/modules/nsopenssl/. The default names are
     * certificate.pem and key.pem.
     */

    certfile = Ns_ConfigGet(path, CONFIG_CERTFILE);
    if (certfile == NULL) {
	certfile = DEFAULT_CERTFILE;
    }

    if (Ns_PathIsAbsolute(certfile) == NS_FALSE) {
	Ns_DStringTrunc(&ds, 0);
	Ns_ModulePath(&ds, server, module, certfile, NULL);
	certfile = Ns_DStringExport(&ds);
    } else {
	certfile = Ns_StrDup(certfile);
    }

    if (debug) {
	Ns_Log(Debug, "Cert file: %s", certfile);
    }

    keyfile = Ns_ConfigGet(path, CONFIG_KEYFILE);
    if (keyfile == NULL) {
	keyfile = DEFAULT_KEYFILE;
    }

    if (Ns_PathIsAbsolute(keyfile) == NS_FALSE) {
	Ns_DStringTrunc(&ds, 0);
	Ns_ModulePath(&ds, server, module, keyfile, NULL);
	keyfile = Ns_DStringExport(&ds);
    } else {
	keyfile = Ns_StrDup(keyfile);
    }
    
    if (debug) {
	Ns_Log(Debug, "Key file: %s", keyfile);
    }
    
    /*
     * Determine the Cache settings. Defaults are:
     *  SessionCache = on
     *  SessionCacheSize = 512
     *  SessionCacheTimeout = 300
     */

    cachesize = 0;
    cachetimeout = 0;

    if (Ns_ConfigGetBool(path, CONFIG_SESSIONCACHE, &cache) == NS_FALSE) {
	cache = DEFAULT_SESSIONCACHE;
    }

    if (cache == NS_TRUE) {
	if (Ns_ConfigGetInt(path, CONFIG_SESSIONCACHETIMEOUT, &cachetimeout) == NS_FALSE) {
	    cachetimeout = DEFAULT_SESSIONCACHETIMEOUT;
	}
	
	if (Ns_ConfigGetInt(path, CONFIG_SESSIONCACHESIZE, &cachesize) == NS_FALSE) {
	    cachesize = DEFAULT_SESSIONCACHESIZE;
	}
	
	if (debug) {
	    Ns_Log(Debug, "SessionCacheSize = '%d'; SessionCacheTimout = '%d'\n", cachesize, cachetimeout);
	}
    }

    /*
     * Determine the cipher suite.
     */

    ciphersuite = Ns_ConfigGet(path, CONFIG_CIPHERSUITE);
    if (ciphersuite == NULL) {
	ciphersuite = DEFAULT_CIPHERSUITE;
    }
    
    ciphersuite = Ns_StrDup(ciphersuite);
    
    /*
     * Create a new server using those files.
     */

    sdPtr->server = NsSSLCreateServer(certfile, keyfile, cachesize, cachetimeout, ciphersuite);
    if (sdPtr->server == NULL) {
	ns_free(sdPtr);
	return NS_ERROR;
    }

    sdPtr->bufsize = 0;
    
    sdPtr->refcnt = 1;
    sdPtr->lsock = INVALID_SOCKET;
    sdPtr->name = module;
    sdPtr->bindaddr = bindaddr;
    sdPtr->address = ns_strdup(address);
    if (!Ns_ConfigGetInt(path, "port", &sdPtr->port)) {
	sdPtr->port = DEFAULT_PORT;
    }
    sdPtr->location = Ns_ConfigGet(path, "location");
    if (sdPtr->location != NULL) {
	sdPtr->location = ns_strdup(sdPtr->location);
    } else {
    	Ns_DStringTrunc(&ds, 0);
	Ns_DStringVarAppend(&ds, DEFAULT_PROTOCOL "://", host, NULL);
	if (sdPtr->port != DEFAULT_PORT) {
	    Ns_DStringPrintf(&ds, ":%d", sdPtr->port);
	}
	sdPtr->location = Ns_DStringExport(&ds);
    }
    if (!Ns_ConfigGetInt(path, "socktimeout", &n) || n < 1) {
	n = 30;
    }
    sdPtr->timeout = n;
    sdPtr->driver = Ns_RegisterDriver(server, module, sockProcs, sdPtr);
    if (sdPtr->driver == NULL) {
	SockFreeConn(sdPtr, NULL);
	return NS_ERROR;
    }
    sdPtr->nextPtr = firstSockDrvPtr;
    firstSockDrvPtr = sdPtr;
    
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SockStart --
 *
 *	Configure and then start the SockThread servicing new
 *	connections.  This is the final initializiation routine
 *	called from main().
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	SockThread is created.
 *
 *----------------------------------------------------------------------
 */

static int
SockStart(char *server, char *label, void **drvDataPtr)
{
    SockDrv *sdPtr = *((SockDrv **) drvDataPtr);
    
    sdPtr->lsock = Ns_SockListen(sdPtr->bindaddr, sdPtr->port);
    if (sdPtr->lsock == INVALID_SOCKET) {
	Ns_Log(Error, "%s: could not listen on %s:%d: %s",
	       sdPtr->name, sdPtr->address ? sdPtr->address : "*",
	       sdPtr->port, ns_sockstrerror(ns_sockerrno));
	return NS_ERROR;
    }
    if (sockThread == NULL) {
	if (ns_sockpair(trigPipe) != 0) {
	    Ns_Fatal("ns_sockpair() failed: %s",
		     ns_sockstrerror(ns_sockerrno));
	}
	Ns_ThreadCreate(SockThread, NULL, 0, &sockThread);
    }
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SockFreeConn --
 *
 *	Return a conneciton to the free list, decrement the driver
 *	refcnt, and free the driver if no longer in use.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void
SockFreeConn(SockDrv *sdPtr, ConnData *cdPtr)
{
    int refcnt;

    Ns_MutexLock(&sdPtr->lock);
    if (cdPtr != NULL) {
	cdPtr->nextPtr = sdPtr->firstFreePtr;
	sdPtr->firstFreePtr = cdPtr;
    }
    refcnt = --sdPtr->refcnt;
    Ns_MutexUnlock(&sdPtr->lock);

    if (refcnt == 0) {
    	ns_free(sdPtr->location);
    	ns_free(sdPtr->address);
	while ((cdPtr = sdPtr->firstFreePtr) != NULL) {
	    sdPtr->firstFreePtr = cdPtr->nextPtr;
	    ns_free(cdPtr);
	}

    	NsSSLDestroyServer(sdPtr->server);

	Ns_MutexDestroy(&sdPtr->lock);
    	ns_free(sdPtr);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * SockThread --
 *
 *	Main listening socket driver thread.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Connections are accepted on the configured listen sockets
 *	and placed on the run queue to be serviced.
 *
 *----------------------------------------------------------------------
 */

static void
SockThread(void *ignored)
{
    fd_set set, watch;
    char c;
    int slen, n, stop;
    SockDrv *sdPtr, *nextPtr;
    ConnData *cdPtr;
    struct sockaddr_in sa;
    SOCKET max, sock;

    Ns_ThreadSetName("-nsopenssl-");
    Ns_Log(Notice, "waiting for startup");
    Ns_WaitForStartup();

    Ns_Log(Notice, "starting");
    FD_ZERO(&watch);
    FD_SET(trigPipe[0], &watch);
    max = trigPipe[0];
    sdPtr = firstSockDrvPtr;
    firstSockDrvPtr = NULL;
    while (sdPtr != NULL) {
	nextPtr = sdPtr->nextPtr;
	if (sdPtr->lsock != INVALID_SOCKET) {
    	    Ns_Log(Notice, "%s: listening on %s (%s:%d)",
			    sdPtr->name, sdPtr->location,
	      		    sdPtr->address ? sdPtr->address : "*",
			    sdPtr->port);
	    if (max < sdPtr->lsock) {
	        max = sdPtr->lsock;
	    }
	    FD_SET(sdPtr->lsock, &watch);
    	    Ns_SockSetNonBlocking(sdPtr->lsock);
	    sdPtr->nextPtr = firstSockDrvPtr;
	    firstSockDrvPtr = sdPtr;
	}
	sdPtr = nextPtr;
    }
    ++max;

    Ns_Log(Notice, "accepting connections");
    stop = 0;
    do {
    	memcpy(&set, &watch, sizeof(fd_set));    	
	do {
	    n = select(max, &set, NULL, NULL, NULL);
	} while (n < 0  && ns_sockerrno == EINTR);
	if (n < 0) {
	    Ns_Fatal("select() failed: %s", ns_sockstrerror(ns_sockerrno));
	} else if (FD_ISSET(trigPipe[0], &set)) {
	    if (recv(trigPipe[0], &c, 1, 0) != 1) {
	    	Ns_Fatal("trigger recv() failed: %s",
			 ns_sockstrerror(ns_sockerrno));
	    }
	    stop = 1;
	    --n;
	}
	
	sdPtr = firstSockDrvPtr;
	while (n > 0 && sdPtr != NULL) {
	    if (FD_ISSET(sdPtr->lsock, &set)) {
		--n;
    		slen = sizeof(sa);
    		sock = accept(sdPtr->lsock, (struct sockaddr *) &sa, &slen);
		if (sock != INVALID_SOCKET) {
		    Ns_MutexLock(&sdPtr->lock);
		    ++sdPtr->refcnt;
		    cdPtr = sdPtr->firstFreePtr;
		    if (cdPtr != NULL) {
			sdPtr->firstFreePtr = cdPtr->nextPtr;
		    }
		    Ns_MutexUnlock(&sdPtr->lock);
		    if (cdPtr == NULL) {
			cdPtr = ns_malloc(sizeof(ConnData) + sdPtr->bufsize);
		    }
		    cdPtr->sdPtr = sdPtr;
		    cdPtr->sock = sock;
		    cdPtr->port = ntohs(sa.sin_port);

		    cdPtr->conn = NULL;

		    strcpy(cdPtr->peer, ns_inet_ntoa(sa.sin_addr));
		    if (Ns_QueueConn(sdPtr->driver, cdPtr) != NS_OK) {
			(void) SockClose(cdPtr);
		    }
	    	}
	    }
	    sdPtr = sdPtr->nextPtr;
	}
    } while (!stop);

    while ((sdPtr = firstSockDrvPtr) != NULL) {
	firstSockDrvPtr = sdPtr->nextPtr;
	Ns_Log(Notice, "%s: closing %s", sdPtr->name, sdPtr->location);
	ns_sockclose(sdPtr->lsock);
	SockFreeConn(sdPtr, NULL);
    }

    ns_sockclose(trigPipe[0]);
    ns_sockclose(trigPipe[1]);
}


/*
 *----------------------------------------------------------------------
 *
 * SockStop --
 *
 *	Trigger the SockThread to shutdown.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	SockThread will close ports.
 *
 *----------------------------------------------------------------------
 */

static void
SockStop(void *arg)
{
    SockDrv *sdPtr = (SockDrv *) arg;

    if (sockThread != NULL) {
    	Ns_Log(Notice, DEFAULT_NAME ":  exiting: triggering shutdown");
	if (send(trigPipe[1], "", 1, 0) != 1) {
	    Ns_Fatal("trigger send() failed: %s",
		     ns_sockstrerror(ns_sockerrno));
	}
	Ns_ThreadJoin(&sockThread, NULL);
	sockThread = NULL;
    	Ns_Log(Notice, DEFAULT_NAME ":  exiting: shutdown complete");
    }
}


/*
 *----------------------------------------------------------------------
 *
 * SockClose --
 *
 *	Close the socket 
 *
 * Results:
 *	NS_OK/NS_ERROR 
 *
 * Side effects:
 *	Socket will be closed and buffer returned to free list.
 *
 *----------------------------------------------------------------------
 */

static int
SockClose(void *arg)
{
    ConnData *cdPtr = arg;
    SockDrv *sdPtr = cdPtr->sdPtr;

    if (cdPtr->sock != INVALID_SOCKET) {
	if (cdPtr->conn != NULL) {
	    (void) NsSSLFlush(cdPtr->conn);
	    NsSSLDestroyConn(cdPtr->conn);
	    cdPtr->conn = NULL;
	}
	ns_sockclose(cdPtr->sock);
	cdPtr->sock = INVALID_SOCKET;
    }
    SockFreeConn(cdPtr->sdPtr, cdPtr);
    return NS_OK;
}



/*
 *----------------------------------------------------------------------
 *
 * SockRead --
 *
 *	Read from the socket 
 *
 * Results:
 *	# bytes read 
 *
 * Side effects:
 *	Will read from socket 
 *
 *----------------------------------------------------------------------
 */

static int
SockRead(void *arg, void *vbuf, int toread)
{
    ConnData   *cdPtr = arg;

    return NsSSLRecv(cdPtr->conn, vbuf, toread);
}


/*
 *----------------------------------------------------------------------
 *
 * SockWrite --
 *
 *	Writes data to a socket.
 *	NOTE: This may not write all of the data you send it!
 *
 * Results:
 *	Number of bytes written, -1 for error 
 *
 * Side effects:
 *	Bytes may be written to a socket
 *
 *----------------------------------------------------------------------
 */

static int
SockWrite(void *arg, void *buf, int towrite)
{
    ConnData   *cdPtr = arg;

    return NsSSLSend(cdPtr->conn, buf, towrite);
}


/*
 *----------------------------------------------------------------------
 *
 * SockHost --
 *
 *	Return the host (addr) I'm bound to 
 *
 * Results:
 *	String hostname 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static char *
SockHost(void *arg)
{
    ConnData   *cdPtr = arg;

    return cdPtr->sdPtr->address;
}


/*
 *----------------------------------------------------------------------
 *
 * SockPort --
 *
 *	Get the port I'm listening on.
 *
 * Results:
 *	A TCP port number 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static int
SockPort(void *arg)
{
    ConnData   *cdPtr = arg;

    return cdPtr->sdPtr->port;
}


/*
 *----------------------------------------------------------------------
 *
 * SockName --
 *
 *	Return the name of this driver 
 *
 * Results:
 *	"nsopenssl" (the standard socket)
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static char *
SockName(void *arg)
{
    ConnData   *cdPtr = arg;

    return cdPtr->sdPtr->name;
}


/*
 *----------------------------------------------------------------------
 *
 * SockPeer --
 *
 *	Return the string name of the peer address 
 *
 * Results:
 *	String peer (ip) addr 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static char *
SockPeer(void *arg)
{
    ConnData   *cdPtr = arg;

    return cdPtr->peer;
}


/*
 *----------------------------------------------------------------------
 *
 * SockConnectionFd --
 *
 *	Get the socket fd 
 *
 * Results:
 *	The socket fd 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static int
SockConnectionFd(void *arg)
{
    ConnData   *cdPtr = arg;

    if (cdPtr->conn == NULL || !NsSSLFlush(cdPtr->conn)) {
	return -1;
    }

    return (int) cdPtr->sock;
}


/*
 *----------------------------------------------------------------------
 *
 * SockDetach --
 *
 *	Detach the connection data from this conneciton for keep-alive.
 *
 * Results:
 *	Pointer to connection data.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void *
SockDetach(void *arg)
{
    return arg;
}


/*
 *----------------------------------------------------------------------
 *
 * SockPeerPort --
 *
 *	Get the peer's originating tcp port 
 *
 * Results:
 *	A tcp port 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static int
SockPeerPort(void *arg)
{
    ConnData   *cdPtr = arg;

    return cdPtr->port;
}


/*
 *----------------------------------------------------------------------
 *
 * SockLocation --
 *
 *	Returns the location, suitable for making anchors 
 *
 * Results:
 *	String location 
 *
 * Side effects:
 *	none 
 *
 *----------------------------------------------------------------------
 */

static char *
SockLocation(void *arg)
{
    ConnData   *cdPtr = arg;

    return cdPtr->sdPtr->location;
}


/*
 *----------------------------------------------------------------------
 *
 * SockInit --
 *
 *      Initialize the SSL connection.
 *
 * Results:
 *	NS_OK/NS_ERROR
 *
 * Side effects:
 *	Stuff may be written to a socket.
 *
 *----------------------------------------------------------------------
 */

static int
SockInit(void *arg)
{
    ConnData   *cdPtr = arg;

    if (cdPtr->conn == NULL) {
	cdPtr->conn = NsSSLCreateConn(cdPtr->sock, cdPtr->sdPtr->timeout,
				      cdPtr->sdPtr->server);
	if (cdPtr->conn == NULL) {
	    return NS_ERROR;
	}
    }
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SSL_smart_shutdown --
 *
 *      Close an SSL connection.
 *
 * Results:
 *	OpenSSL Error.
 *
 * Side effects:
 *	None.
 *
 * Copyright:
 *      Taken from mod_ssl; ssl_util_ssl.c / http://www.modssl.org
 *      Copyright (c) 1998-1999 Ralf S. Engelschall. All rights reserved.
 *
 *----------------------------------------------------------------------
 */

static int
SSL_smart_shutdown(SSL *ssl)
{
    int i;
    int rc;

    /*
     * Repeat the calls, because SSL_shutdown internally dispatches through a
     * little state machine. Usually only one or two interation should be
     * needed, so we restrict the total number of restrictions in order to
     * avoid process hangs in case the client played bad with the socket
     * connection and OpenSSL cannot recognize it.
     */
    rc = 0;
    for (i = 0; i < 4 /* max 2x pending + 2x data = 4 */; i++) {
        if ((rc = SSL_shutdown(ssl)))
            break;
    }
    return rc;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLCreateServer --
 *
 *      Create an SSL server.
 *
 * Results:
 *      Always NS_OK.
 *
 * Side effects:
 *      None.
 *
 * Todo:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static SSLServer*
NsSSLCreateServer(char *certfile, char *keyfile, int cachesize, int cachetimeout, char *ciphersuite)
{
    SSLServer* srvPtr;

    if (debug) {
	Ns_Log(Debug, ">>> NsSSLCreateServer()");
    }
    
    assert(certfile  != NULL && *certfile  != 0x00);
    assert(keyfile   != NULL && *keyfile   != 0x00);
    
    srvPtr = (SSLServer*) ns_calloc(1, sizeof(SSLServer));
    if (srvPtr != NULL) {
	
	/*
	 * Store the config settings
	 */

	srvPtr->certfile     = certfile;
	srvPtr->keyfile      = keyfile;
	srvPtr->cachesize    = cachesize;
	srvPtr->cachetimeout = cachetimeout;
	srvPtr->ciphersuite  = ciphersuite;
	
	/*
	 * Set the protocols that the server supports.
	 * XXX Get this from the config file in InitModule
	 */
	
	srvPtr->method = SSLv2_server_method();
	
	/*
	 * Create and initialize a new SSL server context.
	 */
	
	srvPtr->context = SSL_CTX_new(srvPtr->method);
	if (srvPtr->context == NULL) {
	    Ns_Log(Error, "Could not create new SSL context.");
	    NsSSLDestroyServer(srvPtr);
	    return NULL;
	}
	
	SSL_CTX_set_options(srvPtr->context, SSL_OP_ALL); /* XXX What does this do? */	
	SSL_CTX_set_options(srvPtr->context, SSL_OP_SINGLE_DH_USE);
	
	/*
	 * Store a copy to out SSLServer record in the SSL context.
	 */
	
	SSL_CTX_set_app_data(srvPtr->context, srvPtr);
	
	/*
	 * Set the cipher suite that we support.
	 */
	
	if (SSL_CTX_set_cipher_list(srvPtr->context, ciphersuite) == 0) {
	    Ns_Log(Error, "Unable to configure permitted SSL ciphers (%s).", ciphersuite);
	    NsSSLDestroyServer(srvPtr);
	    return NULL;
	}

	/*
	 * Initialize the session cache.
	 */

	if (srvPtr->cachesize != 0) {
	    Tcl_InitHashTable(&srvPtr->cachehash, TCL_STRING_KEYS);
	    Ns_MutexInit(&srvPtr->cachemutex);
	    
	    SSL_CTX_sess_set_new_cb(srvPtr->context,    NsSSLNewSessionCacheEntry);
	    SSL_CTX_sess_set_get_cb(srvPtr->context,    NsSSLGetSessionCacheEntry);
	    SSL_CTX_sess_set_remove_cb(srvPtr->context, NsSSLDelSessionCacheEntry);

	    SSL_CTX_set_session_cache_mode(srvPtr->context, SSL_SESS_CACHE_SERVER);
	} else {
	    SSL_CTX_set_session_cache_mode(srvPtr->context, SSL_SESS_CACHE_OFF);
	}
	
	/*
	 * Load the SSL Certificate and Private Key. If either of these fail then
	 * the server cannot be started.
	 */
	
	if (debug) {
	    Ns_Log(Notice, "Loading SSL certificate '%s'", certfile);
	}
	
	if (SSL_CTX_use_certificate_file(srvPtr->context, certfile, SSL_FILETYPE_PEM) <= 0) {
	    Ns_Log(Error, "Could not load the certificate.");
	    NsSSLDestroyServer(srvPtr);
	    return NULL;
	}
	
	if (debug) {
	    Ns_Log(Notice, "Loading SSL private key '%s'", keyfile);
	}
	
	if (SSL_CTX_use_PrivateKey_file(srvPtr->context, keyfile, SSL_FILETYPE_PEM) <= 0) {
	    Ns_Log(Error, "Could not load the private key.");
	    NsSSLDestroyServer(srvPtr);
	    return NULL;
	}
	
	/*
	 * Check if the private key matches the certificate's public key.
	 */
	
	if (debug) {
	    Ns_Log(Notice, "Checking SSL private key");
	}
	
	if (SSL_CTX_check_private_key(srvPtr->context) == 0) {
	    Ns_Log(Error, "Private key does not match the certificate public key");
	    return NULL;
	}
    }

    return srvPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLDestroyServer --
 *
 *      Destroy an SSL Server structure.
 *
 * Results:
 *      Always NS_OK.
 *
 * Side effects:
 *      None.
 *
 * Todo:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
NsSSLDestroyServer(SSLServer *server)
{
    if (debug) {
	Ns_Log(Debug, ">>> NsSSLDestroyServer()");
    }
    
    assert(server != NULL);

    if (server->context != NULL) {
	SSL_CTX_free(server->context);
    }
    
    if (server->certfile != NULL) {
	Ns_Free(server->certfile);
    }

    if (server->keyfile != NULL) {
	Ns_Free(server->keyfile);
    }

    if (server->cachesize != 0) {
	Tcl_DeleteHashTable(&server->cachehash);
	Ns_MutexDestroy(&server->cachemutex);
    }

    if (server->ciphersuite != NULL) {
	Ns_Free(server->ciphersuite);
    }
    
    Ns_Free(server);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLFlushConn --
 *
 *      Flush the SSL connection.
 *
 * Results:
 *      Always NS_OK.
 *
 * Side effects:
 *      None.
 *
 * Todo:
 *      Implement
 *
 *----------------------------------------------------------------------
 */

static int
NsSSLFlush(SSLConnection *conn)
{
    if (debug) {
	Ns_Log(Debug, ">>> NsSSLFlush()");
    }

    assert(conn != NULL);
    assert(conn->ssl != NULL);

    BIO_flush(SSL_get_wbio(conn->ssl));
    
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLCreateConn --
 *
 *	Create an SSL connection. The socket has already been accept()ed
 *      and is ready for reading/writing.
 *
 * Results:
 *      An SSLConnection object or NULL. ->server is always guaranteed
 *      filled in.
 *
 * Side effects:
 *      If the SSL connection was open then it will be forced to close
 *      first.
 *
 * Todo:
 *      Implement timeouts using an alarm and a OpenSSL callback.
 *
 *----------------------------------------------------------------------
 */

static SSLConnection*
NsSSLCreateConn(SOCKET sock, int timeout, SSLServer *server)
{
    SSLConnection* conPtr;
    int err;
    X509* xs;
    char* cp;

    if (debug) {
	Ns_Log(Debug, ">>> NsSSLCreateConn()");
    }

    assert(server != NULL);

    conPtr = (SSLConnection*) ns_calloc(1, sizeof(SSLConnection));
    if (conPtr != NULL) {
	/* Remember the server in the connection */
	conPtr->server = server;
	
	conPtr->ssl = SSL_new(server->context);
	if (conPtr->ssl == NULL) {
	    /* XXX Send an error message to the log */
	    (void) NsSSLDestroyConn(conPtr);
	    return NULL;
	}
	
	SSL_clear(conPtr->ssl);
	
	/*SSL_set_session_id_context(ssl, (unsigned char *)cpVHostID, strlen(cpVHostID));*/

	/* Store our SSLConnection as OpenSSL's app data */
	SSL_set_app_data(conPtr->ssl, conPtr);
	
	/* Connect this connection's descriptor to the SSL connection */
	SSL_set_fd(conPtr->ssl, sock);
	
	SSL_set_verify_result(conPtr->ssl, X509_V_OK);
	
	while (SSL_is_init_finished(conPtr->ssl) == 0) {
	    if ((err = SSL_accept(conPtr->ssl)) <= 0) {
		Ns_Log(Notice, "Failed to accept SSL connection, err = %d / %d", err, SSL_get_error(conPtr->ssl, err));
		if (SSL_get_error(conPtr->ssl, err) == SSL_ERROR_ZERO_RETURN) {
		    Ns_Log(Notice, "Error: SSL_ERROR_ZERO_RETURN");
		    /*
		     * The case where the connection was closed before any data
		     * was transferred. That's not a real error and can occur
		     * sporadically with some clients.
		     */
		    Ns_Log(Notice, "handshake stopped: connection was closed");
		    SSL_set_shutdown(conPtr->ssl, SSL_RECEIVED_SHUTDOWN);
		    SSL_smart_shutdown(conPtr->ssl);
		} else if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
		    Ns_Log(Notice, "Error: This is an HTTP request");
		    /* What to do here? */
		} else if (SSL_get_error(conPtr->ssl, err) == SSL_ERROR_SYSCALL) {
		    Ns_Log(Notice, "Error: SSL_ERROR_SYSCALL");

		    /* Let interrupted syscalls continue */
		    if (errno == EINTR) {
			continue;
		    }
		    
		    if (errno > 0) {
			Ns_Log(Notice, "SSL handshake interrupted by system [Hint: Stop button pressed in browser?!]");
		    } else {
			Ns_Log(Notice, "Spurious SSL handshake interrupt [Hint: Usually just one of those OpenSSL confusions!?]");
		    }
		    
		    SSL_set_shutdown(conPtr->ssl, SSL_RECEIVED_SHUTDOWN);
		    SSL_smart_shutdown(conPtr->ssl);
		} else {
		    Ns_Log(Notice, "Error: Other");
		}
		
		/* For all errors we destroy the connection */
		(void) NsSSLDestroyConn(conPtr);
		return NULL;
		
	    } else {
		
		/*
		 * Successful SSL_accept. This means that the handshake was done
		 * and that the SSL communication channel has been setup. Before
		 * we continue, we do some extra checks.
		 */

		/*Check for failed client authentication */
		if ((err = SSL_get_verify_result(conPtr->ssl)) != X509_V_OK) {
		    char* errstr = (char*) X509_verify_cert_error_string(err);
		    Ns_Log(Notice, "SSL client authentication failed: %s",  errstr != NULL ? errstr : "unknown reason");
		    SSL_set_shutdown(conPtr->ssl, SSL_RECEIVED_SHUTDOWN);
		    SSL_smart_shutdown(conPtr->ssl);
		    (void) NsSSLDestroyConn(conPtr);
		    return NULL;
		}
	    }
	}
	
	/* Print the cipher */
	if (debug) {
	    Ns_Log(Debug, "SSL connection using %s", SSL_get_cipher(conPtr->ssl));
	}
    }

    return conPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLDestroyConn --
 *
 *	Destroy an SSL connection.
 *
 * Results:
 *      NS_OK
 *
 * Side effects:
 *      If the SSL connection was open then it will be forced to close
 *      first.
 *
 *----------------------------------------------------------------------
 */

static int
NsSSLDestroyConn(SSLConnection *conn)
{
    if (debug) {
	Ns_Log(Debug, ">>> NsSSLDestroyConn()");
    }

    assert(conn != NULL);
    
    if (conn->ssl != NULL) {
	SSL_free(conn->ssl);
    }
    
    Ns_Free(conn);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLRecv --
 *
 *	Read data from an SSL connection
 *
 * Results:
 *	The number of bytes read or a negative number in case of
 *      an error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
NsSSLRecv(SSLConnection *conn, void *buffer, int toread)
{
  assert(conn != NULL);
  assert(conn->ssl != NULL);
  assert(buffer != NULL);
  
  return SSL_read(conn->ssl, buffer, toread);
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLSend --
 *
 *	Send data through an SSL connection
 *
 * Results:
 *	The number of bytes send or a negative number in case of
 *      an error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
NsSSLSend(SSLConnection *conn, void *buffer, int towrite)
{
    assert(conn != NULL);
    assert(conn->ssl != NULL);
    assert(buffer != NULL);

    return SSL_write(conn->ssl, buffer, towrite);
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLNewSessionCacheEntry --
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
NsSSLNewSessionCacheEntry(SSL *ssl, SSL_SESSION *session)
{
    SSLConnection* connection;
    SSLServer* server;
    SSLSessionCacheEntry* cacheEntry;
    Tcl_HashEntry* hashEntry;
    int new;
    char key[1024];
    unsigned char data[16 * 1024]; /* How to calc this? Standard base64 size rule on SSL_SESSION? */
    unsigned char *datap, *value;
    int datalength;
    int result;
    
    if (debug) {
	Ns_Log(Debug, ">>> NsSSLNewSessionCacheEntry()");
    }

    /*
     * Get our server record via the SSL's application data.
     */

    connection = (SSLConnection*) SSL_get_app_data(ssl);
    server = connection->server;

    /*
     * Check if the hash table has exceeded it's max size.
     */

    //if (NsSSLGetSessionCacheSize(server) > server->cachesize) {
    //    NsSSLExpireSessionCache(server);
    //}
    
    /*
     * Convert the session id to a base64 encoded string.
     */

    Ns_HtuuEncode(session->session_id, session->session_id_length, key);
    
    /*
     * Transform the session into a data stream.
     * XXX Rewrite this. Crappy code.
     */
    
    datap = data;
    datalength = i2d_SSL_SESSION(session, &datap);
    
    value = Ns_Malloc(datalength);
    memcpy(value, data, datalength);

    /*
     * Set the timeout for this session.
     */
    
    SSL_set_timeout(session, server->cachetimeout);
    
    /*
     * Now insert the session into the hash.
     */

    cacheEntry = (SSLSessionCacheEntry*) Ns_Malloc(sizeof(SSLSessionCacheEntry));
    
    cacheEntry->time = time(NULL);
    cacheEntry->data = value;
    cacheEntry->size = datalength;
    
    Ns_LockMutex(&server->cachemutex);
    {
	hashEntry = Tcl_CreateHashEntry(&server->cachehash, key, &new);
	if (hashEntry != NULL && new == 1) { /* XXX What to do if it's not a new entry? */
	    Tcl_SetHashValue(hashEntry, (ClientData) cacheEntry);
	} else {
	    Ns_Free(value);
	}
    }
    Ns_UnlockMutex(&server->cachemutex);
    
    return 0;
}

static SSL_SESSION*
NsSSLGetSessionCacheEntry(SSL *ssl, unsigned char *id, int id_length, int *copy)
{
    SSLConnection* connection;
    SSLServer* server;
    SSL_SESSION *session;
    SSLSessionCacheEntry* cacheEntry;
    Tcl_HashEntry* hashEntry;
    char key[1024];    
    
    if (debug) {
	Ns_Log(Debug, ">>> NsSSLGetSessionCacheEntry()");
    }
    
    session = NULL;
    
    /*
     * Get our server record via the SSL's application data.
     */

    connection = (SSLConnection*) SSL_get_app_data(ssl);
    server = connection->server;
    
    /*
     * Convert the session id to ascii base64
     */
    
    Ns_HtuuEncode(id, id_length, key);
    Ns_Log(Debug, "Session ID: '%s'", key);
    
    Ns_LockMutex(&server->cachemutex);
    {
	hashEntry = Tcl_FindHashEntry(&server->cachehash, key);
	if (hashEntry == NULL) {
	    Ns_Log(Debug, "SSLCache: Did not find entry for key '%s'", key);	    
	} else {
	    cacheEntry = Tcl_GetHashValue(hashEntry);
	    session = d2i_SSL_SESSION(NULL, (unsigned char**) &cacheEntry->data, cacheEntry->size);
	}
    }
    Ns_UnlockMutex(&server->cachemutex);

    *copy = 0;
    return session;
}

static void
NsSSLDelSessionCacheEntry(SSL_CTX *ctx, SSL_SESSION *session)
{
    SSLConnection* connection;
    SSLServer* server;
    Tcl_HashEntry* hashEntry;
    SSLSessionCacheEntry* cacheEntry;
    char key[1024];
    
    if (debug) {
	Ns_Log(Debug, ">>> NsSSLDelSessionCacheEntry()");
    }
    
    /*
     * Get our server record via the SSL_CTX's application data.
     */
    
    server = (SSLServer*) SSL_CTX_get_app_data(ctx);
    
    /*
     * Convert the session id to ascii base64
     */
    
    Ns_HtuuEncode(session->session_id, session->session_id_length, key);
    Ns_Log(Debug, "Session ID: '%s'", key);

    Ns_LockMutex(&server->cachemutex);
    {
	hashEntry = Tcl_FindHashEntry(&server->cachehash, key);
	if (hashEntry != NULL) {
	    cacheEntry = Tcl_GetHashValue(hashEntry);
	    if (cacheEntry == NULL) {
		Ns_Log(Debug, "SSLCache: Did not find entry for key '%s'", key);
	    } else {
		Ns_Free(cacheEntry->data);
		Ns_Free(cacheEntry);
		Tcl_DeleteHashEntry(hashEntry);
	    }
	}
    }
    Ns_UnlockMutex(&server->cachemutex);
}
