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
 * driver.c --
 *
 *       This module implements an SSL socket driver using the OpenSSL library.
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include "nsopenssl.h"
#include "config.h"

static int CheckModuleDir (NsOpenSSLDriver * sdPtr);
static int MakeDriverSSLContext (NsOpenSSLDriver * sdPtr);
static int MakeSockServerSSLContext (NsOpenSSLDriver * sdPtr);
static int MakeSockClientSSLContext (NsOpenSSLDriver * sdPtr);
static int SetProtocols (char *module, SSL_CTX * context, char *protocols);
static int SetCipherSuite (char *module, SSL_CTX * context,
			   char *cipherSuite);
static int LoadCertificate (char *module, SSL_CTX * context, char *certFile);
static int LoadKey (char *module, SSL_CTX * context, char *keyFile);
static int CheckKey (char *module, SSL_CTX * context);
static int LoadCACerts (char *module, SSL_CTX * context, char *caFile,
			char *caDir);
static int InitLocation (NsOpenSSLDriver * sdPtr);
static int InitSessionCache (char *module, SSL_CTX * context,
			     int cacheEnabled, int cacheId, int cacheTimeout,
			     int cacheSize);
static int PeerVerifyCallback (int preverify_ok, X509_STORE_CTX * x509_ctx);
static RSA *IssueTmpRSAKey (SSL * ssl, int export, int keylen);

/* Linked list of all configured nsopenssl instances */
static NsOpenSSLDriver *firstSSLDriverPtr;

#ifndef NS_MAJOR_VERSION

/*
 * AOLserver 3.x Comm API
 */

static Ns_ThreadProc SockThread;
static void SockFreeConn (NsOpenSSLDriver * sdPtr, Ns_OpenSSLConn * scPtr);
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

static Ns_DrvProc sockProcs[] = {
    {Ns_DrvIdStart, (void *) SockStart},
    {Ns_DrvIdStop, (void *) SockStop},
    {Ns_DrvIdRead, (void *) SockRead},
    {Ns_DrvIdWrite, (void *) SockWrite},
    {Ns_DrvIdClose, (void *) SockClose},
    {Ns_DrvIdHost, (void *) SockHost},
    {Ns_DrvIdPort, (void *) SockPort},
    {Ns_DrvIdName, (void *) SockName},
    {Ns_DrvIdPeer, (void *) SockPeer},
    {Ns_DrvIdPeerPort, (void *) SockPeerPort},
    {Ns_DrvIdLocation, (void *) SockLocation},
    {Ns_DrvIdConnectionFd, (void *) SockConnectionFd},
    {Ns_DrvIdDetach, (void *) SockDetach},
    {Ns_DrvIdInit, (void *) SockInit},
    {0, NULL}
};

#else

/*
 * AOLserver 4.x Comm API
 */

static Ns_DriverProc OpenSSLProc;

#endif


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLCreateDriver --
 *
 *       Create the SSL driver.
 *
 * Results:
 *       An NsOpenSSLDriver* or NULL.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

extern NsOpenSSLDriver *
NsOpenSSLCreateDriver (char *server, char *module)
{
    NsOpenSSLDriver *sdPtr;

    sdPtr = (NsOpenSSLDriver *) ns_calloc (1, sizeof *sdPtr);
    Ns_MutexSetName (&sdPtr->lock, module);
    sdPtr->server = server;
    sdPtr->module = module;
    sdPtr->refcnt = 1;
    sdPtr->lsock = INVALID_SOCKET;
    sdPtr->configPath = Ns_ConfigGetPath (server, module, NULL);

    if (CheckModuleDir (sdPtr) == NS_ERROR
	|| MakeDriverSSLContext (sdPtr) == NS_ERROR
	|| MakeSockServerSSLContext (sdPtr) == NS_ERROR
	|| MakeSockClientSSLContext (sdPtr) == NS_ERROR
	|| InitLocation (sdPtr) == NS_ERROR) {
	NsOpenSSLFreeDriver (sdPtr);
	return NULL;
    }

    sdPtr->timeout = ConfigIntDefault (module, sdPtr->configPath,
				       CONFIG_SERVER_SOCKTIMEOUT,
				       DEFAULT_SERVER_SOCKTIMEOUT);
    if (sdPtr->timeout < 1) {
	sdPtr->timeout = DEFAULT_SERVER_SOCKTIMEOUT;
    }

    sdPtr->bufsize = ConfigIntDefault (module, sdPtr->configPath,
				       CONFIG_SERVER_BUFFERSIZE,
				       DEFAULT_SERVER_BUFFERSIZE);
    if (sdPtr->bufsize < 1) {
	sdPtr->bufsize = DEFAULT_SERVER_BUFFERSIZE;
    }

#ifndef NS_MAJOR_VERSION
    sdPtr->driver = Ns_RegisterDriver (server, module, sockProcs, sdPtr);
    if (sdPtr->driver == NULL) {
	NsOpenSSLFreeDriver (sdPtr);
	return NULL;
    }
#endif

#ifndef NS_MAJOR_VERSION
    sdPtr->nextPtr = firstSSLDriverPtr;
    firstSSLDriverPtr = sdPtr;
#else
    if (Ns_DriverInit (server, module, "nsopenssl", OpenSSLProc,
                sdPtr, NS_DRIVER_SSL) != NS_OK) {
	NsOpenSSLFreeDriver (sdPtr);
        return NULL;
    }
#endif
 
    return sdPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLFreeDriver --
 *
 *      Destroy an NsOpenSSLDriver.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

extern void
NsOpenSSLFreeDriver (NsOpenSSLDriver * sdPtr)
{
    Ns_OpenSSLConn *scPtr;

    Ns_Log (Debug, "%s: freeing(%p)",
	    sdPtr == NULL ? DRIVER_NAME : sdPtr->module, sdPtr);

    if (sdPtr != NULL) {
	while ((scPtr = sdPtr->firstFreePtr) != NULL) {
	    sdPtr->firstFreePtr = scPtr->nextPtr;
	    ns_free (scPtr);
	}
	Ns_MutexDestroy (&sdPtr->lock);
	if (sdPtr->context != NULL)
	    SSL_CTX_free (sdPtr->context);
	if (sdPtr->sockServerContext != NULL)
	    SSL_CTX_free (sdPtr->sockServerContext);
	if (sdPtr->sockClientContext != NULL)
	    SSL_CTX_free (sdPtr->sockClientContext);
	if (sdPtr->dir != NULL)
	    ns_free (sdPtr->dir);
	if (sdPtr->address != NULL)
	    ns_free (sdPtr->address);
	if (sdPtr->location != NULL)
	    ns_free (sdPtr->location);
	ns_free (sdPtr);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLGetModuleName --
 *
 *	Return a pointer to the name this module was loaded as.
 *
 * Results:
 *	Pointer to string.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

extern char *
NsOpenSSLGetModuleName (void)
{
#ifndef NS_MAJOR_VERSION
    NsOpenSSLDriver *sdPtr;

    sdPtr = firstSSLDriverPtr;
    return sdPtr->module;
#else
    return "nsopenssl";
#endif
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLGetSockServerSSLContext --
 *
 *	Return a pointer to the default SSL_CTX for Sock Servers. 
 *
 * Results:
 *	Pointer to SSL_CTX.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

extern SSL_CTX *
NsOpenSSLGetSockServerSSLContext (void)
{
    NsOpenSSLDriver *sdPtr;

    sdPtr = firstSSLDriverPtr;

    return sdPtr->sockServerContext;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLGetSockClientSSLContext --
 *
 *	Return a pointer to the default SSL_CTX for Sock Clients. 
 *
 * Results:
 *	Pointer to SSL_CTX.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

extern SSL_CTX *
NsOpenSSLGetSockClientSSLContext (void)
{
    NsOpenSSLDriver *sdPtr;

    /* XXX - for AS 4.x, looks like I'll need to get the module's name from
     * XXX - the config section, then ask the core server to find and return
     * XXX - a pointer to the datastructure or return the values I want */
    sdPtr = firstSSLDriverPtr;

    return sdPtr->sockClientContext;
}

#ifndef NS_MAJOR_VERSION

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
 *	NS_OK or NS_ERROR.
 *
 * Side effects:
 *	SockThread is created.
 *
 *----------------------------------------------------------------------
 */

static int
SockStart (char *server, char *label, void **drvDataPtr)
{
    NsOpenSSLDriver *sdPtr = *((NsOpenSSLDriver **) drvDataPtr);

    sdPtr->lsock = Ns_SockListen (sdPtr->bindaddr, sdPtr->port);
    if (sdPtr->lsock == INVALID_SOCKET) {
	Ns_Fatal ("%s: could not listen on %s:%d: %s",
		  sdPtr->module, sdPtr->address ? sdPtr->address : "*",
		  sdPtr->port, ns_sockstrerror (ns_sockerrno));
	return NS_ERROR;
    }

    if (sockThread == NULL) {
	if (ns_sockpair (trigPipe) != 0) {
	    Ns_Fatal ("ns_sockpair() failed: %s",
		      ns_sockstrerror (ns_sockerrno));
	}
	Ns_ThreadCreate (SockThread, NULL, 0, &sockThread);
    }
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SockFreeConn --
 *
 *  Return a connection to the free list.
 *
 * Results:
 *  None.
 *
 * Side effects:
 *  None.
 *
 *----------------------------------------------------------------------
 */

static void
SockFreeConn (NsOpenSSLDriver * sdPtr, Ns_OpenSSLConn * scPtr)
{
    int refcnt;

    Ns_MutexLock (&sdPtr->lock);
    if (scPtr != NULL) {
	scPtr->nextPtr = sdPtr->firstFreePtr;
	sdPtr->firstFreePtr = scPtr;
    }
    refcnt = --sdPtr->refcnt;
    Ns_MutexUnlock (&sdPtr->lock);

    if (refcnt == 0) {
	NsOpenSSLFreeDriver (sdPtr);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * SockThread --
 *
 *  Main listening socket driver thread.
 *
 * Results:
 *  None.
 *
 * Side effects:
 *  Connections are accepted on the configured listen sockets
 *  and placed on the run queue to be serviced.
 *
 *----------------------------------------------------------------------
 */

static void
SockThread (void *ignored)
{
    fd_set set, watch;
    char c;
    int slen, n, stop;
    NsOpenSSLDriver *sdPtr, *nextPtr;
    Ns_OpenSSLConn *scPtr;
    struct sockaddr_in sa;
    SOCKET max, sock;
    char module[32];

    sprintf (module, "-%s-", NsOpenSSLGetModuleName ());
    Ns_ThreadSetName ((char *) &module);
    Ns_Log (Notice, "waiting for startup");
    Ns_WaitForStartup ();
    Ns_Log (Notice, "starting");

    FD_ZERO (&watch);
    FD_SET (trigPipe[0], &watch);
    max = trigPipe[0];

    sdPtr = firstSSLDriverPtr;
    firstSSLDriverPtr = NULL;
    while (sdPtr != NULL) {

	nextPtr = sdPtr->nextPtr;
	if (sdPtr->lsock != INVALID_SOCKET) {
	    Ns_Log (Notice, "%s: listening on %s (%s:%d)",
		    sdPtr->module, sdPtr->location,
		    sdPtr->address ? sdPtr->address : "*", sdPtr->port);
	    if (max < sdPtr->lsock) {
		max = sdPtr->lsock;
	    }
	    FD_SET (sdPtr->lsock, &watch);
	    Ns_SockSetNonBlocking (sdPtr->lsock);
	    sdPtr->nextPtr = firstSSLDriverPtr;
	    firstSSLDriverPtr = sdPtr;
	}
	sdPtr = nextPtr;

    }
    ++max;

    Ns_Log (Notice, "accepting connections");

    stop = 0;
    do {
	memcpy (&set, &watch, sizeof (fd_set));
	do {
	    n = select (max, &set, NULL, NULL, NULL);
	} while (n < 0 && ns_sockerrno == EINTR);
	if (n < 0) {
	    Ns_Fatal ("select() failed: %s", ns_sockstrerror (ns_sockerrno));
	} else if (FD_ISSET (trigPipe[0], &set)) {
	    if (recv (trigPipe[0], &c, 1, 0) != 1) {
		Ns_Fatal ("trigger recv() failed: %s",
			  ns_sockstrerror (ns_sockerrno));
	    }
	    Ns_Log (Notice, "stopping");
	    stop = 1;
	    --n;
	}

	sdPtr = firstSSLDriverPtr;
	while (n > 0 && sdPtr != NULL) {
	    if (FD_ISSET (sdPtr->lsock, &set)) {
		--n;
		slen = sizeof (sa);
		sock = accept (sdPtr->lsock, (struct sockaddr *) &sa, &slen);
		if (sock != INVALID_SOCKET) {
		    Ns_MutexLock (&sdPtr->lock);
		    sdPtr->refcnt++;
		    scPtr = sdPtr->firstFreePtr;
		    if (scPtr != NULL) {
			sdPtr->firstFreePtr = scPtr->nextPtr;
		    }
		    Ns_MutexUnlock (&sdPtr->lock);
		    if (scPtr == NULL) {
			scPtr = (Ns_OpenSSLConn *)
			    ns_malloc (sizeof *scPtr);
		    }

		    memset (scPtr, 0, sizeof *scPtr);

		    /* These are freed by NsOpenSSLFreeDriver */
		    scPtr->server       = sdPtr->server;
		    scPtr->module       = sdPtr->module;
		    scPtr->configPath   = sdPtr->configPath;
		    scPtr->address      = sdPtr->address;	/* Do not free - driver frees it */
		    scPtr->bindaddr     = sdPtr->bindaddr;	/* Do not free - driver frees it */
		    scPtr->port         = sdPtr->port;
		    scPtr->bufsize      = sdPtr->bufsize;
		    scPtr->timeout      = sdPtr->timeout;

		    scPtr->context      = sdPtr->context;

		    /* These need to be freed by NsOpenSSLDestroyConn */
		    scPtr->sdPtr        = sdPtr;
		    scPtr->refcnt       = 0;	                /* always 0 for server conns */
		    scPtr->role         = ROLE_SSL_SERVER;      /* ssl server mode */
		    scPtr->conntype     = CONNTYPE_SSL_NSD;     /* socket driven by core nsd */
		    scPtr->type         = STR_NSD_SERVER;       /* pretty name for the conntype */
		    scPtr->sock         = sock;
		    scPtr->wsock        = INVALID_SOCKET;
		    scPtr->ssl          = NULL;
		    scPtr->io           = NULL;
		    scPtr->peercert     = NULL;
		    strcpy (scPtr->peer, ns_inet_ntoa (sa.sin_addr));
		    scPtr->peerport     = ntohs (sa.sin_port);

		    if (Ns_QueueConn (sdPtr->driver, scPtr) != NS_OK) {
			Ns_Log (Warning, "%s: connection dropped",
				sdPtr->module);
			(void) SockClose (scPtr);
		    }
		}
	    }
	    sdPtr = sdPtr->nextPtr;
	}
    } while (!stop);

    while ((sdPtr = firstSSLDriverPtr) != NULL) {
	firstSSLDriverPtr = sdPtr->nextPtr;
	Ns_Log (Notice, "%s: closing %s", sdPtr->module, sdPtr->location);
	ns_sockclose (sdPtr->lsock);
	SockFreeConn (sdPtr, NULL);
    }

    ns_sockclose (trigPipe[0]);
    ns_sockclose (trigPipe[1]);
}

/*
 *----------------------------------------------------------------------
 *
 * SockStop --
 *
 *  Trigger the SockThread to shutdown.
 *
 * Results:
 *  None.
 *
 * Side effects:
 *  SockThread will close ports.
 *
 *----------------------------------------------------------------------
 */

static void
SockStop (void *arg)
{
    if (sockThread != NULL) {
	Ns_Log (Notice, DEFAULT_NAME ":  exiting: triggering shutdown");
	if (send (trigPipe[1], "", 1, 0) != 1) {
	    Ns_Fatal ("trigger send() failed: %s",
		      ns_sockstrerror (ns_sockerrno));
	}
	Ns_ThreadJoin (&sockThread, NULL);
	sockThread = NULL;
	Ns_Log (Notice, DEFAULT_NAME ":  exiting: shutdown complete");
    }
}

/*
 *----------------------------------------------------------------------
 *
 * SockClose --
 *
 *  Close the socket
 *
 * Results:
 *  NS_OK/NS_ERROR
 *
 * Side effects:
 *  Socket will be closed and buffer returned to free list.
 *
 *----------------------------------------------------------------------
 */

static int
SockClose (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;
    NsOpenSSLDriver *sdPtr = scPtr->sdPtr;

    if (scPtr->sock != INVALID_SOCKET) {
	if (scPtr->ssl != NULL) {
	    NsOpenSSLFlush ((Ns_OpenSSLConn *) scPtr);
	}
	NsOpenSSLDestroyConn ((Ns_OpenSSLConn *) scPtr);
    }
    SockFreeConn (sdPtr, scPtr);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SockRead --
 *
 *  Read from the socket
 *
 * Results:
 *  # bytes read
 *
 * Side effects:
 *  Will read from socket
 *
 *----------------------------------------------------------------------
 */

static int
SockRead (void *arg, void *vbuf, int toread)
{
    Ns_OpenSSLConn *ccPtr = (Ns_OpenSSLConn *) arg;

    return NsOpenSSLRecv (ccPtr, vbuf, toread);
}

/*
 *----------------------------------------------------------------------
 *
 * SockWrite --
 *
 *  Writes data to a socket.
 *  NOTE: This may not write all of the data you send it!
 *
 * Results:
 *  Number of bytes written, -1 for error
 *
 * Side effects:
 *  Bytes may be written to a socket
 *
 *----------------------------------------------------------------------
 */

static int
SockWrite (void *arg, void *buf, int towrite)
{
    Ns_OpenSSLConn *ccPtr = (Ns_OpenSSLConn *) arg;

    return NsOpenSSLSend (ccPtr, buf, towrite);
}

/*
 *----------------------------------------------------------------------
 *
 * SockHost --
 *
 *  Return the host (addr) I'm bound to
 *
 * Results:
 *  String hostname
 *
 * Side effects:
 *  None
 *
 *----------------------------------------------------------------------
 */

static char *
SockHost (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;

    return scPtr->sdPtr->address;
}

/*
 *----------------------------------------------------------------------
 *
 * SockPort --
 *
 *  Get the port I'm listening on.
 *
 * Results:
 *  A TCP port number
 *
 * Side effects:
 *  None
 *
 *----------------------------------------------------------------------
 */

static int
SockPort (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;

    return scPtr->sdPtr->port;
}

/*
 *----------------------------------------------------------------------
 *
 * SockName --
 *
 * 	Return the name of this driver
 *
 * Results:
 *	DRIVER_NAME.
 *
 * Side effects:
 * 	None
 *
 *----------------------------------------------------------------------
 */

static char *
SockName (void *arg)
{
#if 0
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;
#endif

    return DRIVER_NAME;
}

/*
 *----------------------------------------------------------------------
 *
 * SockPeer --
 *
 *  Return the string name of the peer address
 *
 * Results:
 *  String peer (ip) addr
 *
 * Side effects:
 *  None
 *
 *----------------------------------------------------------------------
 */

static char *
SockPeer (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;

    return scPtr->peer;
}

/*
 *----------------------------------------------------------------------
 *
 * SockConnectionFd --
 *
 *  Get the socket fd
 *
 * Results:
 *  The socket fd
 *
 * Side effects:
 *  None
 *
 *----------------------------------------------------------------------
 */

static int
SockConnectionFd (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;

    if (NsOpenSSLFlush ((Ns_OpenSSLConn *) scPtr) == NS_ERROR) {
	return -1;
    }

    return (int) scPtr->sock;
}

/*
 *----------------------------------------------------------------------
 *
 * SockDetach --
 *
 *  Detach the connection data from this connection for keep-alive.
 *
 * Results:
 *  Pointer to connection data.
 *
 * Side effects:
 *  None.
 *
 *----------------------------------------------------------------------
 */

static void *
SockDetach (void *arg)
{
    return arg;
}

/*
 *----------------------------------------------------------------------
 *
 * SockPeerPort --
 *
 *  Get the peer's originating tcp port
 *
 * Results:
 *  A tcp port
 *
 * Side effects:
 *  None
 *
 *----------------------------------------------------------------------
 */

static int
SockPeerPort (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;

    return scPtr->peerport;
}

/*
 *----------------------------------------------------------------------
 *
 * SockLocation --
 *
 *  Returns the location, suitable for making anchors
 *
 * Results:
 *  String location
 *
 * Side effects:
 *  none
 *
 *----------------------------------------------------------------------
 */

static char *
SockLocation (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;

    return scPtr->sdPtr->location;
}

/*
 *----------------------------------------------------------------------
 *
 * SockInit --
 *
 *      Initialize the SSL connection.
 *
 * Results:
 *  NS_OK/NS_ERROR
 *
 * Side effects:
 *  Stuff may be written to a socket.
 *
 *----------------------------------------------------------------------
 */

static int
SockInit (void *arg)
{
    Ns_OpenSSLConn *scPtr = (Ns_OpenSSLConn *) arg;

    if (scPtr->ssl == NULL) {
	return NsOpenSSLCreateConn ((Ns_OpenSSLConn *) scPtr);
    } else {
	return NS_OK;
    }
}

#else /* use the new comm model in 4.x */

/*            
 *----------------------------------------------------------------------
 *
 * OpenSSLProc --
 *
 *      SSL driver callback proc.  This driver performs the necessary
 *      handshake and encryption of SSL.
 *
 * Results:   
 *      For close, always 0.  For keep, 0 if connection could be
 *      properly flushed, -1 otherwise.  For send and recv, # of bytes
 *      processed or -1 on error.
 *
 * Side effects:
 *      None. 
 *            
 *----------------------------------------------------------------------
 */

static int
OpenSSLProc (Ns_DriverCmd cmd, Ns_Sock * sock, struct iovec * bufs, int nbufs)
{
    Ns_OpenSSLConn *scPtr;
    Ns_Driver *driver = sock->driver;
    struct msghdr msg;
    int n;

    /*          
     * Initialize the connection context on the first I/O.
     */
    
    scPtr = sock->arg;
    if (scPtr == NULL) {
	scPtr = ns_calloc (1, sizeof (*scPtr));
	scPtr->role = ROLE_SSL_SERVER;
	scPtr->conntype = CONNTYPE_SSL_NSD;
	scPtr->type = STR_NSD_SERVER;
	scPtr->sdPtr = driver->arg;
	scPtr->module = scPtr->sdPtr->module;
	scPtr->bufsize = scPtr->sdPtr->bufsize;
	scPtr->timeout = scPtr->sdPtr->timeout;
	scPtr->context = scPtr->sdPtr->context;
	scPtr->refcnt = 0;	/* always 0 for nsdserver conns */
	scPtr->sock = sock->sock;
	sock->arg = scPtr;
	
	if (NsOpenSSLCreateConn ((Ns_OpenSSLConn *) scPtr) != NS_OK) {
	    return NS_ERROR;
	}
    }

    switch (cmd) {
    case DriverRecv:
	n = recvmsg(sock->sock, &msg, 0);
        if (n < 0 && errno == EWOULDBLOCK
            && Ns_SockWait(sock->sock, NS_SOCK_READ, sock->driver->recvwait) == NS_OK) {
            n = recvmsg(sock->sock, &msg, 0);
        }
        break;

    case DriverSend:
	n = sendmsg(sock->sock, &msg, 0);
        if (n < 0 && errno == EWOULDBLOCK
            && Ns_SockWait(sock->sock, NS_SOCK_WRITE, sock->driver->sendwait) == NS_OK) {
            n = sendmsg(sock->sock, &msg, 0);
        }
        break;

    case DriverKeep:
	/* XXX Revisit */
	if (sock->arg != NULL && NsOpenSSLFlush (sock->arg) == NS_OK) {
	    n = 0;
	} else {
	    n = -1;
	}
	break;

    case DriverClose:
	/* Revisit */
	if (sock->arg != NULL) {
	    (void) NsOpenSSLFlush (sock->arg);
	    NsOpenSSLDestroyConn (sock->arg);
	    ns_free (sock->arg);
	    sock->arg = NULL;
	}
	n = 0;
	break;

    default:
	/* Unsupported command. */
	n = -1;
	break;
    }
    return n;
}

#endif


/*
 *----------------------------------------------------------------------
 *
 * CheckModuleDir --
 *
 *       Set sdPtr->dir to the absolute path of the module's directory.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       May create the directory on disk.
 *
 *----------------------------------------------------------------------
 */

static int
CheckModuleDir (NsOpenSSLDriver * sdPtr)
{
    char *value;
    Ns_DString ds;

    value = Ns_ConfigGetValue (sdPtr->configPath, CONFIG_MODULE_DIR);

    if (value == NULL) {
	Ns_DStringInit (&ds);
	Ns_ModulePath (&ds, sdPtr->server, sdPtr->module, NULL);
	sdPtr->dir = Ns_DStringExport (&ds);
	Ns_Log (Notice, "Module directory defaults to %s", sdPtr->dir);
	if (mkdir (sdPtr->dir, 0755) != 0 && errno != EEXIST) {
	    Ns_Log (Error, "mkdir (%s) failed: %s", sdPtr->dir,
		    strerror (errno));
	    ns_free (sdPtr->dir);
	    sdPtr->dir = NULL;
	    return NS_ERROR;
	}
    } else {
	if (Ns_PathIsAbsolute (value)) {
	    sdPtr->dir = ns_strdup (value);
	} else {
	    Ns_DStringInit (&ds);
	    Ns_DStringVarAppend (&ds, sdPtr->dir, value, NULL);
	    sdPtr->dir = Ns_DStringExport (&ds);
	    Ns_DStringFree (&ds);
	}
	Ns_Log (Notice, "Module directory set by ModuleDir to %s",
		sdPtr->dir);
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * MakeDriverSSLContext --
 *
 *       Create a new SSL context for the specified SSLDriver and set
 *       default values or values from the configuration file.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Sets sdPtr->context.
 *
 *----------------------------------------------------------------------
 */

static int
MakeDriverSSLContext (NsOpenSSLDriver * sdPtr)
{
    char *protocols;
    char *cipherSuite;
    char *certFile;
    char *keyFile;
    char *caFile;
    char *caDir;
    int connTrace;
    int peerVerify;
    int verifyDepth;
    int cacheEnabled;
    int cacheId;
    int cacheSize;
    int cacheTimeout;

    sdPtr->context = SSL_CTX_new (SSLv23_server_method ());
    if (sdPtr->context == NULL) {
	Ns_Log (Error, "%s: error creating SSL context", sdPtr->module);
	return NS_ERROR;
    }

    SSL_CTX_set_app_data (sdPtr->context, sdPtr);

    /* Enable SSL bug compatibility.  */
    SSL_CTX_set_options (sdPtr->context, SSL_OP_ALL);

    /* This apparently prevents some sort of DH attack.  */
    SSL_CTX_set_options (sdPtr->context, SSL_OP_SINGLE_DH_USE);

    /* Temporary key callback required for 40-bit export browsers */
    SSL_CTX_set_tmp_rsa_callback (sdPtr->context, IssueTmpRSAKey);

    /* Set peer verify and verify depth */

    peerVerify = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
  				    CONFIG_SERVER_PEERVERIFY,
  				    DEFAULT_SERVER_PEERVERIFY);

    if (peerVerify) {
        Ns_Log(Notice, "*** !!! ServerPeerVerify set to true");
	SSL_CTX_set_verify (sdPtr->context,
			    (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE),
			    PeerVerifyCallback);
	verifyDepth = (int) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				    CONFIG_SERVER_VERIFYDEPTH,
				    DEFAULT_SERVER_VERIFYDEPTH);
	SSL_CTX_set_verify_depth (sdPtr->context, verifyDepth);
    } else {
        Ns_Log(Notice, "*** !!! ServerPeerVerify set to false");
	SSL_CTX_set_verify (sdPtr->context, SSL_VERIFY_NONE, NULL);
    }

    /*
     * Set SSL handshake and connection tracing
     */

    connTrace = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				   CONFIG_SERVER_TRACE, DEFAULT_SERVER_TRACE);

    if (connTrace) {
	SSL_CTX_set_info_callback (sdPtr->context, NsOpenSSLTrace);
    }

    /*
     * Set protocols
     */

    protocols = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
				     CONFIG_SERVER_PROTOCOLS,
				     DEFAULT_SERVER_PROTOCOLS);

    if (SetProtocols (sdPtr->module, sdPtr->context, protocols) != NS_OK)
	return NS_ERROR;

    /*
     * Set cipher suite
     */

    cipherSuite = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
				       CONFIG_SERVER_CIPHERSUITE,
				       DEFAULT_SERVER_CIPHERSUITE);

    if (SetCipherSuite (sdPtr->module, sdPtr->context, cipherSuite) != NS_OK)
	return NS_ERROR;

    /*
     * Load certificate
     */

    certFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				  CONFIG_SERVER_CERTFILE, sdPtr->dir,
				  DEFAULT_SERVER_CERTFILE);

    if (LoadCertificate (sdPtr->module, sdPtr->context, certFile) != NS_OK)
	return NS_ERROR;

    /*
     * Load the key that unlocks the certificate
     */

    keyFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				 CONFIG_SERVER_KEYFILE, sdPtr->dir,
				 DEFAULT_SERVER_KEYFILE);

    if (LoadKey (sdPtr->module, sdPtr->context, keyFile) != NS_OK)
	return NS_ERROR;

    /*
     * Check the key against the certificate
     */

    if (CheckKey (sdPtr->module, sdPtr->context) != NS_OK)
	return NS_ERROR;

    /*
     * Load CA certificates
     */

    caFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				CONFIG_SERVER_CAFILE, sdPtr->dir,
				DEFAULT_SERVER_CAFILE);

    caDir = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
			       CONFIG_SERVER_CADIR, sdPtr->dir,
			       DEFAULT_SERVER_CADIR);

    if (LoadCACerts (sdPtr->module, sdPtr->context, caFile, caDir) != NS_OK)
	return NS_ERROR;

    /*
     * Initialize the session cache
     */

    cacheEnabled = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				      CONFIG_SERVER_SESSIONCACHE,
				      DEFAULT_SERVER_SESSIONCACHE);

    cacheId = (int) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				      CONFIG_SERVER_SESSIONCACHEID,
				      DEFAULT_SERVER_SESSIONCACHEID);

    cacheTimeout = (long) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
					    CONFIG_SERVER_SESSIONTIMEOUT,
					    DEFAULT_SERVER_SESSIONTIMEOUT);

    cacheSize = ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				  CONFIG_SERVER_SESSIONCACHESIZE,
				  DEFAULT_SERVER_SESSIONCACHESIZE);

    if (InitSessionCache
	(sdPtr->module, sdPtr->context, cacheEnabled, cacheId, cacheTimeout,
	 cacheSize) != NS_OK)
	return NS_ERROR;

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * MakeSockServerSSLContext --
 *
 *       Create a new SSL sock server context for the specified
 *       SSLDriver.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Sets sdPtr->sockServerContext.
 *
 *----------------------------------------------------------------------
 */

static int
MakeSockServerSSLContext (NsOpenSSLDriver * sdPtr)
{
    char *protocols;
    char *cipherSuite;
    char *certFile;
    char *keyFile;
    char *caFile;
    char *caDir;
    int connTrace;
    int peerVerify;
    int verifyDepth;
    int cacheEnabled;
    int cacheId;
    int cacheSize;
    int cacheTimeout;

    sdPtr->sockServerContext = SSL_CTX_new (SSLv23_server_method ());
    if (sdPtr->sockServerContext == NULL) {
	Ns_Log (Error, "%s: error creating SSL context", sdPtr->module);
	return NS_ERROR;
    }

    SSL_CTX_set_app_data (sdPtr->sockServerContext, sdPtr);

    /*
     * Enable SSL bug compatibility.
     */

    SSL_CTX_set_options (sdPtr->sockServerContext, SSL_OP_ALL);

    /*
     * This apparently prevents some sort of DH attack.
     */

    SSL_CTX_set_options (sdPtr->sockServerContext, SSL_OP_SINGLE_DH_USE);

    /*
     * Temporary key callback required for 40-bit export browsers
     */

    SSL_CTX_set_tmp_rsa_callback (sdPtr->sockServerContext, IssueTmpRSAKey);

    /*
     * Set peer verify and verify depth
     */

    peerVerify = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				    CONFIG_SOCKSERVER_PEERVERIFY,
				    DEFAULT_SOCKSERVER_PEERVERIFY);

    if (peerVerify) {
	SSL_CTX_set_verify (sdPtr->sockServerContext,
			    (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE),
			    PeerVerifyCallback);
	verifyDepth =
	    (int) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				    CONFIG_SOCKSERVER_VERIFYDEPTH,
				    DEFAULT_SOCKSERVER_VERIFYDEPTH);
	SSL_CTX_set_verify_depth (sdPtr->sockServerContext, verifyDepth);
    } else {
	SSL_CTX_set_verify (sdPtr->sockServerContext, SSL_VERIFY_NONE,
			    PeerVerifyCallback);
    }

    /*
     * Set SSL handshake and connection tracing
     */

    connTrace = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				   CONFIG_SOCKSERVER_TRACE,
				   DEFAULT_SOCKSERVER_TRACE);

    if (connTrace) {
	SSL_CTX_set_info_callback (sdPtr->sockServerContext, NsOpenSSLTrace);
    }

    /*
     * Set protocols
     */

    protocols = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
				     CONFIG_SOCKSERVER_PROTOCOLS,
				     DEFAULT_SOCKSERVER_PROTOCOLS);

    if (SetProtocols (sdPtr->module, sdPtr->sockServerContext, protocols) !=
	NS_OK) return NS_ERROR;

    /*
     * Set cipher suite
     */

    cipherSuite = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
				       CONFIG_SOCKSERVER_CIPHERSUITE,
				       DEFAULT_SOCKSERVER_CIPHERSUITE);

    if (SetCipherSuite (sdPtr->module, sdPtr->sockServerContext, cipherSuite)
	!= NS_OK)
	return NS_ERROR;

    /*
     * Load certificate
     */

    certFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				  CONFIG_SOCKSERVER_CERTFILE, sdPtr->dir,
				  DEFAULT_SOCKSERVER_CERTFILE);

    if (LoadCertificate (sdPtr->module, sdPtr->sockServerContext, certFile) !=
	NS_OK) return NS_ERROR;

    /*
     * Load the key that unlocks the certificate
     */

    keyFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				 CONFIG_SOCKSERVER_KEYFILE, sdPtr->dir,
				 DEFAULT_SOCKSERVER_KEYFILE);

    if (LoadKey (sdPtr->module, sdPtr->sockServerContext, keyFile) != NS_OK)
	return NS_ERROR;

    /*
     * Check the key against the certificate
     */

    if (CheckKey (sdPtr->module, sdPtr->sockServerContext) != NS_OK)
	return NS_ERROR;

    /*
     * Load CA certificates
     */

    caFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				CONFIG_SOCKSERVER_CAFILE, sdPtr->dir,
				DEFAULT_SOCKSERVER_CAFILE);

    caDir = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
			       CONFIG_SOCKSERVER_CADIR, sdPtr->dir,
			       DEFAULT_SOCKSERVER_CADIR);

    if (LoadCACerts (sdPtr->module, sdPtr->sockServerContext, caFile, caDir)
	!= NS_OK)
	return NS_ERROR;

    /*
     * Initialize the session cache
     */

    cacheEnabled = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				      CONFIG_SOCKSERVER_SESSIONCACHE,
				      DEFAULT_SOCKSERVER_SESSIONCACHE);

    cacheId = (int) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				      CONFIG_SOCKSERVER_SESSIONCACHEID,
				      DEFAULT_SOCKSERVER_SESSIONCACHEID);

    cacheTimeout = (long) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
					    CONFIG_SOCKSERVER_SESSIONTIMEOUT,
					    DEFAULT_SOCKSERVER_SESSIONTIMEOUT);

    cacheSize = ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				  CONFIG_SOCKSERVER_SESSIONCACHESIZE,
				  DEFAULT_SOCKSERVER_SESSIONCACHESIZE);

    if (InitSessionCache
	(sdPtr->module, sdPtr->sockServerContext, cacheEnabled, cacheId,
	 cacheTimeout, cacheSize) != NS_OK)
	return NS_ERROR;

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * MakeSockClientSSLContext --
 *
 *       Create a new SSL sock client context for the specified
 *       SSLDriver.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Sets sdPtr->sockServerContext.
 *
 *----------------------------------------------------------------------
 */

static int
MakeSockClientSSLContext (NsOpenSSLDriver * sdPtr)
{
    char *protocols;
    char *cipherSuite;
    char *certFile;
    char *keyFile;
    char *caFile;
    char *caDir;
    int connTrace;
    int peerVerify;
    int verifyDepth;
    int cacheEnabled;
    int cacheId;
    int cacheSize;
    int cacheTimeout;

    sdPtr->sockClientContext = SSL_CTX_new (SSLv23_client_method ());
    if (sdPtr->sockClientContext == NULL) {
	Ns_Log (Error, "%s: error creating SSL context", sdPtr->module);
	return NS_ERROR;
    }

    SSL_CTX_set_app_data (sdPtr->sockClientContext, sdPtr);

    /*
     * Enable SSL bug compatibility.
     */

    SSL_CTX_set_options (sdPtr->sockClientContext, SSL_OP_ALL);

    /*
     * This apparently prevents some sort of DH attack.
     */

    SSL_CTX_set_options (sdPtr->sockClientContext, SSL_OP_SINGLE_DH_USE);

    /*
     * Temporary key callback required for 40-bit export browsers
     */

    SSL_CTX_set_tmp_rsa_callback (sdPtr->sockClientContext, IssueTmpRSAKey);

    /*
     * Set peer verify and verify depth
     */

    peerVerify = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				    CONFIG_SOCKCLIENT_PEERVERIFY,
				    DEFAULT_SOCKCLIENT_PEERVERIFY);

    if (peerVerify) {
	SSL_CTX_set_verify (sdPtr->sockClientContext, SSL_VERIFY_PEER,
			    PeerVerifyCallback);
	verifyDepth =
	    (int) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				    CONFIG_SOCKCLIENT_VERIFYDEPTH,
				    DEFAULT_SOCKCLIENT_VERIFYDEPTH);
	SSL_CTX_set_verify_depth (sdPtr->sockClientContext, verifyDepth);
    } else {
	SSL_CTX_set_verify (sdPtr->sockClientContext, SSL_VERIFY_NONE,
			    PeerVerifyCallback);
    }

    /*
     * Set SSL handshake and connection tracing
     */

    connTrace = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				   CONFIG_SOCKCLIENT_TRACE,
				   DEFAULT_SOCKCLIENT_TRACE);

    if (connTrace) {
	SSL_CTX_set_info_callback (sdPtr->sockClientContext, NsOpenSSLTrace);
    }

    /*
     * Set protocols
     */

    protocols = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
				     CONFIG_SOCKCLIENT_PROTOCOLS,
				     DEFAULT_SOCKCLIENT_PROTOCOLS);

    if (SetProtocols (sdPtr->module, sdPtr->sockClientContext, protocols) !=
	NS_OK) return NS_ERROR;

    /*
     * Set cipher suite
     */

    cipherSuite = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
				       CONFIG_SOCKCLIENT_CIPHERSUITE,
				       DEFAULT_SOCKCLIENT_CIPHERSUITE);

    if (SetCipherSuite (sdPtr->module, sdPtr->sockClientContext, cipherSuite)
	!= NS_OK)
	return NS_ERROR;

    /*
     * Load certificate
     */

    certFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				  CONFIG_SOCKCLIENT_CERTFILE, sdPtr->dir,
				  DEFAULT_SOCKCLIENT_CERTFILE);

    if (certFile != NULL) {

	if (LoadCertificate
	    (sdPtr->module, sdPtr->sockClientContext, certFile) != NS_OK)
	    return NS_ERROR;

	/*
	 * Load the key that unlocks the certificate
	 */

	keyFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				     CONFIG_SOCKCLIENT_KEYFILE, sdPtr->dir,
				     DEFAULT_SOCKCLIENT_KEYFILE);

	if (LoadKey (sdPtr->module, sdPtr->sockClientContext, keyFile) !=
	    NS_OK) return NS_ERROR;

	/*
	 * Check the key against the certificate
	 */

	if (CheckKey (sdPtr->module, sdPtr->sockClientContext) != NS_OK)
	    return NS_ERROR;
    }

    /*
     * Load CA certificates
     */

    caFile = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
				CONFIG_SOCKCLIENT_CAFILE, sdPtr->dir,
				DEFAULT_SOCKCLIENT_CAFILE);

    caDir = ConfigPathDefault (sdPtr->module, sdPtr->configPath,
			       CONFIG_SOCKCLIENT_CADIR, sdPtr->dir,
			       DEFAULT_SOCKCLIENT_CADIR);

    if (LoadCACerts (sdPtr->module, sdPtr->sockClientContext, caFile, caDir)
	!= NS_OK)
	return NS_ERROR;

    /*
     * Initialize the session cache
     */

    cacheEnabled = ConfigBoolDefault (sdPtr->module, sdPtr->configPath,
				      CONFIG_SOCKCLIENT_SESSIONCACHE,
				      DEFAULT_SOCKCLIENT_SESSIONCACHE);

    cacheId = (int) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				      CONFIG_SOCKCLIENT_SESSIONCACHEID,
				      DEFAULT_SOCKCLIENT_SESSIONCACHEID);

    cacheTimeout = (long) ConfigIntDefault (sdPtr->module, sdPtr->configPath,
					    CONFIG_SOCKCLIENT_SESSIONTIMEOUT,
					    DEFAULT_SOCKCLIENT_SESSIONTIMEOUT);

    cacheSize = ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				  CONFIG_SOCKCLIENT_SESSIONCACHESIZE,
				  DEFAULT_SOCKCLIENT_SESSIONCACHESIZE);

    if (InitSessionCache
	(sdPtr->module, sdPtr->sockClientContext, cacheEnabled, cacheId,
	 cacheTimeout, cacheSize) != NS_OK)
	return NS_ERROR;

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SetCipherSuite --
 *
 *       Set the cipher suite to be used by the SSL server according
 *       to the config file.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
SetCipherSuite (char *module, SSL_CTX * context, char *cipherSuite)
{
    int rc;

    rc = SSL_CTX_set_cipher_list (context, cipherSuite);

    if (rc == 0) {
	Ns_Log (Error, "%s: error configuring cipher suite to \"%s\"",
		module, cipherSuite);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SetProtocols --
 *
 *       Set the list of protocols that the server will
 *       use.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       Sets pdPtr->protocols.
 *
 *----------------------------------------------------------------------
 */

static int
SetProtocols (char *module, SSL_CTX * context, char *protocols)
{
    int bits;

    protocols = ns_strdup (protocols);
    protocols = Ns_StrToLower (protocols);

    bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

    if (strstr (protocols, "all") != NULL) {
	bits = 1;
	Ns_Log (Notice, "%s: using all protocols: SSLv2, SSLv3 and TLSv1",
		module);
    } else {
	if (strstr (protocols, "sslv2") != NULL) {
	    bits &= ~SSL_OP_NO_SSLv2;
	    Ns_Log (Notice, "%s: Using SSLv2 protocol", module);
	}
	if (strstr (protocols, "sslv3") != NULL) {
	    bits &= ~SSL_OP_NO_SSLv3;
	    Ns_Log (Notice, "%s: Using SSLv3 protocol", module);
	}
	if (strstr (protocols, "tlsv1") != NULL) {
	    bits &= ~SSL_OP_NO_TLSv1;
	    Ns_Log (Notice, "%s: Using TLSv1 protocol", module);
	}
    }

    SSL_CTX_set_options (context, bits);

    ns_free (protocols);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadCertificate --
 *
 *       Load the certificate for the SSL server and SSL sock server
 *       from the file specified in the server config. Also loads a
 *       certificate chain that follows the certificate in the same
 *       file. To use a cert chain, simply append the CA certs to the
 *       end of your certificate file and they'll be passed to the
 *       client at connection time. If no certs are appended, no cert
 *       chain will be passed to the client.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       Frees *file.
 *
 *----------------------------------------------------------------------
 */

static int
LoadCertificate (char *module, SSL_CTX * context, char *certFile)
{
    int rc;

    /*
     * This allows the server to pass the entire certificate
     * chain to the client. It can simply hold just the server's
     * certificate if there is no chain.
     */

    rc = SSL_CTX_use_certificate_chain_file (context, certFile);

    if (rc == 0) {
	Ns_Log (Error, "%s: error loading certificate file \"%s\"",
		module, certFile);
    }

    ns_free (certFile);

    return (rc == 0) ? NS_ERROR : NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadKey --
 *
 *       Load the private key for the SSL server and SSL sock server
 *       from the file specified in the server config.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
LoadKey (char *module, SSL_CTX * context, char *keyFile)
{
    int rc;
    int fd;

    /*
     * We should check for a passphrase to try on the key file if it fails to
     * load, but we don't yet.
     */

    rc = SSL_CTX_use_PrivateKey_file (context, keyFile, SSL_FILETYPE_PEM);

    if (rc == 0) {

	Ns_Log (Error, "%s: error loading private key file \"%s\"",
		module, keyFile);

	/*
	 * Try to give the user some idea of why the key file wasn't
	 * loadable...
	 */

	fd = open (keyFile, O_RDONLY);
	if (fd < 0) {
	    if (errno == ENOENT) {
		Ns_Log (Notice, "%s: the private key file does not exist", module);
	    } else if (errno == EACCES) {
		Ns_Log (Error, "%s: permission denied trying to open the private key file for read", module);
	    } else {
		Ns_Log (Error, "%s: errno %d reported opening the private key file", module, errno);
	    }
	} else {
	    Ns_Log (Error, "%s: the private key file *is* readable; make sure it is not passphrase-protected", module, keyFile);
	    close (fd);
	}

    }

    ns_free (keyFile);

    return (rc == 0) ? NS_ERROR : NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * CheckKey --
 *
 *       Make sure that the private key for the SSL server and SSL sock server
 *       matches the certificate.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
CheckKey (char *module, SSL_CTX * context)
{
    if (SSL_CTX_check_private_key (context) == 0) {
	Ns_Log (Error, "%s: private key does not match certificate", module);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadCACerts --
 *
 *       Load the CA certificates for the SSL server from the file
 *       specified in the server config.  Not an error if there
 *       are no CA certificates.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
LoadCACerts (char *module, SSL_CTX * context, char *caFile, char *caDir)
{
    int status;
    int rc;
    int fd;
    DIR *dd;

    status = NS_OK;

    /*
     * Load CAs from a file
     */

    fd = open (caFile, O_RDONLY);
    if (fd < 0) {
	if (errno == ENOENT) {
	    Ns_Log (Notice, "%s: CA certificate file does not exist", module);
	} else {
	    Ns_Log (Error, "%s: error opening CA certificate file", module);
	    status = NS_ERROR;
	}
	ns_free (caFile);
	caFile = NULL;
    }

    else {
	close (fd);
    }

    /*
     * Load CAs from directory
     */

    dd = opendir (caDir);
    if (dd == NULL) {
	if (errno == ENOENT) {
	    Ns_Log (Notice, "%s: CA certificate directory does not exist",
		    module);
	} else {
	    Ns_Log (Error, "%s: error opening CA certificate directory",
		    module);
	    status = NS_ERROR;
	}

	ns_free (caDir);
	caDir = NULL;
    }

    else {
	closedir (dd);
    }

    if (status == NS_OK && (caFile != NULL || caDir != NULL)) {
	rc = SSL_CTX_load_verify_locations (context, caFile, caDir);

	if (rc == 0) {
	    Ns_Log (Error, "%s: error loading CA certificates", module);
	    status = NS_ERROR;
	}
    }

    if (caFile != NULL)
	ns_free (caFile);
    if (caDir != NULL)
	ns_free (caDir);

    return status;
}

/*
 *----------------------------------------------------------------------
 *
 * InitSessionCache --
 *
 *       Initialize the session cache for the SSL server as specified
 *       in the server config. This is an internal OpenSSL cache, so
 *       we don't do anything other than set a timeout and size.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
InitSessionCache (char *module, SSL_CTX * context, int cacheEnabled,
		  int cacheId, int cacheTimeout, int cacheSize)
{
    if (cacheEnabled) {

	SSL_CTX_set_session_cache_mode (context, SSL_SESS_CACHE_SERVER);

	SSL_CTX_set_session_id_context (context,
					(void *) &cacheId, sizeof (cacheId));

	SSL_CTX_set_timeout (context, cacheTimeout);

	SSL_CTX_sess_set_cache_size (context, cacheSize);

    } else {

	SSL_CTX_set_session_cache_mode (context, SSL_SESS_CACHE_OFF);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * InitLocation --
 *
 *       Set the location, hostname, advertised address, bind address,
 *       and port of the driver as specified in the server config.
 *
 * Results:
 *       NS_ERROR or NS_OK
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
InitLocation (NsOpenSSLDriver * sdPtr)
{
    char *hostname;
    char *lookupHostname;
    Ns_DString ds;

    sdPtr->bindaddr = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
					   "ServerAddress", NULL);

    hostname = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
				    "ServerHostname", NULL);

    if (sdPtr->bindaddr == NULL) {
	lookupHostname = (hostname != NULL) ? hostname : Ns_InfoHostname ();
	Ns_DStringInit (&ds);
	if (Ns_GetAddrByHost (&ds, lookupHostname) == NS_ERROR) {
	    Ns_Log (Error, "%s: failed to resolve '%s': %s",
		    sdPtr->module, lookupHostname, strerror (errno));
	    return NS_ERROR;
	}

	sdPtr->address = Ns_DStringExport (&ds);
    } else {
	sdPtr->address = ns_strdup (sdPtr->bindaddr);
    }

    if (hostname == NULL) {
	Ns_DStringInit (&ds);
	if (Ns_GetHostByAddr (&ds, sdPtr->address) == NS_ERROR) {
	    Ns_Log (Warning, "%s: failed to reverse resolve '%s': %s",
		    sdPtr->module, sdPtr->address, strerror (errno));
	    hostname = ns_strdup (sdPtr->address);
	} else {
	    hostname = Ns_DStringExport (&ds);
	}
    }

    sdPtr->port = ConfigIntDefault (sdPtr->module, sdPtr->configPath,
				    "ServerPort", DEFAULT_PORT);

    sdPtr->location = ConfigStringDefault (sdPtr->module, sdPtr->configPath,
					   "ServerLocation", NULL);
    if (sdPtr->location != NULL) {
	sdPtr->location = ns_strdup (sdPtr->location);
    } else {
	Ns_DStringInit (&ds);
	Ns_DStringVarAppend (&ds, DEFAULT_PROTOCOL "://", hostname, NULL);
	if (sdPtr->port != DEFAULT_PORT) {
	    Ns_DStringPrintf (&ds, ":%d", sdPtr->port);
	}
	sdPtr->location = Ns_DStringExport (&ds);
    }
    Ns_Log (Notice, "%s: location %s", sdPtr->module, sdPtr->location);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * PeerVerifyCallback --
 *
 *      Called by the SSL library at each stage of client certificate
 *      verification.
 *
 * Results:
 *
 *      Always returns 1 to prevent verification errors from halting
 *      the SSL handshake.  We'd rather finish the handshake so we
 *      can either authenticate by other means or return an HTTP error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
PeerVerifyCallback (int preverify_ok, X509_STORE_CTX * x509_ctx)
{
    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * IssueTmpRSAKey --
 *
 *       Give out the temporary key when needed. This is a callback
 *       function used by OpenSSL.
 *
 * Results:
 *       Returns a pointer to the new temporary key.
 *
 * Side effects:
 *       Attempts to Seed the PRNG if needed. If PRNG doesn't contain 
 *       enough entropy, key won't be returned and the connection
 *       will fail.
 *
 *----------------------------------------------------------------------
 */

static RSA *
IssueTmpRSAKey (SSL *ssl, int export, int keylen)
{
    Ns_OpenSSLConn *scPtr;
    NsOpenSSLDriver *sdPtr;
    static RSA *rsa_tmp = NULL;

    /* XXX do I need Ns_OpenSSLConn and Driver here? */
    scPtr = (Ns_OpenSSLConn *) SSL_get_app_data (ssl);
    sdPtr = scPtr->sdPtr;

    rsa_tmp = RSA_generate_key (keylen, RSA_F4, NULL, NULL);
    if (rsa_tmp != NULL) {
        Ns_Log (Notice, "%s: Generated %d-bit temporary RSA key",
            sdPtr->module, keylen);
    } else {
        Ns_Log (Warning,
            "%s: Cannot generate temporary RSA key",
            sdPtr->module);
    }

    return rsa_tmp;
}

