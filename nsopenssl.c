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
 * Copyright (C) 2000 Freddie Mendoza
 * Copyright (C) 1999 Stefan Arentz
 */

/*
 * nsopenssl.c --
 *
 *       This module implements an SSL socket driver using the OpenSSL library.
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>

#include "nsopenssl.h"


#ifdef AOLSERVER_4

/*
 * AOLserver 4.x Comm API
 */

static Ns_DriverProc OpenSSLProc;

#else

/*
 * AOLserver 3.x Comm API
 */


static Ns_ThreadProc SockThread;
static void SockFreeConn (NsOpenSSLDriver * driver, Ns_OpenSSLConn * conn);
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
#if 0
    {Ns_DrvIdInit, (void *) SockInit},
#endif
    {0, NULL}
};

#endif

NS_EXPORT int Ns_ModuleVersion = 1;


/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *     nsopenssl module initialization.
 *
 * Results:
 *     NS_OK or NS_ERROR
 *
 * Side effects:
 *     Calls Ns_RegisterLocation as specified by this instance
 *     in the config file.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int
Ns_ModuleInit (char *server, char *module)
{
    NsOpenSSLDriver *driver;

#ifdef NSOPENSSL_DEBUG
    Ns_Log(Debug, "%s: NSOPENSSL_DEBUG is set", DRIVER_NAME);
#endif

    /*
     * Create nsopenssl Tcl API commands
     */

    if (Ns_TclInitInterps (server, NsOpenSSLCreateCmds, NULL)
	!= NS_OK) {
	return NS_ERROR;
    }

#ifdef AOLSERVER_4

    if ((driver = NsOpenSSLCreateDriver (server, module)) == NULL) {
	return NS_ERROR;
    }

    /* XXX TEMP FIX for AOLserver 4.x -- in order to use the SockClient
     * XXX and SockServer capabilities, we need to know the SSL_CTX for each
     * XXX which is currently stored in the driver ptr. This will go away in
     * XXX the next release and be replaced by another mechanism to keep track
     * XXX of which certs go with which conns. Yes, it's all clear to me now.
     */

    driver->nextPtr = firstSSLDriverPtr;
    firstSSLDriverPtr = driver;

    return Ns_DriverInit (server, module, DRIVER_NAME, OpenSSLProc, driver,
			  NS_DRIVER_SSL);

#else /* AOLserver_3 */

    if ((driver = NsOpenSSLCreateDriver (server, module, sockProcs)) == NULL) {
	return NS_ERROR;
    }

    driver->nextPtr = firstSSLDriverPtr;
    firstSSLDriverPtr = driver;

    return NS_OK;

#endif

}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockConnect --
 *
 *      Open an SSL connection to the given host and port.
 *
 * Results:
 *      A pointer to a new Ns_OpenSSLConn structure.
 *
 * Side effects:
 *      Runs the SSL handshake.
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLConn *
Ns_OpenSSLSockConnect (char *host, int port, int async, int timeout)
{
    Ns_OpenSSLConn *conn;
    SOCKET sock;

#ifdef NSOPENSSL_DEBUG
    Ns_Log (Debug, "%s: NsOpenSSLSockConnect -- enter", DRIVER_NAME);
#endif

    if (timeout < 0) {
	sock = Ns_SockConnect (host, port);
    } else {
	sock = Ns_SockTimedConnect (host, port, timeout);
    }

    if (sock == INVALID_SOCKET) {
	return NULL;
    }

    /*
     * XXX temporary solution -- note that use of firstSSLDriverPtr
     * XXX forces you to use the cert and key from the LAST loaded
     * XXX nsopenssl module for outgoing and incoming SSL sock operations.
     * XXX This does not apply to the regular SSL conns coming into the
     * XXX core server. Also note that firstSSLDriverPtr isn't really
     * XXX necessary for AOLserver 4.x, but is used for now just to store
     * XXX the SockClient and SockServer stuff.
     * XXX
     * XXX This will be fixed in the upcoming 3.0 release of nsopenssl.
     * XXX For now, just duplicate the sections for SockServer and SockClient
     * XXX in your nsd.tcl file for all loaded nsopenssl modules.
     */

    if ((conn = NsOpenSSLCreateConn(sock, firstSSLDriverPtr, ROLE_SSL_CLIENT, CONNTYPE_SSL_SOCK)) == NULL) {
	return NULL;
    }

    /*
     * We leave the socket blocking until after the handshake.
     */

    if (async)
	Ns_SockSetNonBlocking (conn->sock);

    SSL_set_app_data (conn->ssl, conn);

#ifdef NSOPENSSL_DEBUG
    Ns_Log (Debug, "%s: NsOpenSSLSockConnect -- leave", DRIVER_NAME);
#endif

    return conn;
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockAccept --
 *
 *      Accept a TCP socket, setting close on exec.
 *
 * Results:
 *      A socket or INVALID_SOCKET on error.
 *
 * Side effects:
 *      The socket is always placed in non-blocking mode.
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLConn *
Ns_OpenSSLSockAccept (SOCKET sock)
{
    Ns_OpenSSLConn *conn = NULL;

    if (sock == INVALID_SOCKET)
        return NULL;

    if ((conn = NsOpenSSLCreateConn(sock, firstSSLDriverPtr, ROLE_SSL_SERVER, CONNTYPE_SSL_SOCK)) == NULL) {
	return NULL;
    }

    Ns_SockSetNonBlocking (conn->sock);

    SSL_set_app_data (conn->ssl, conn);

    return conn;
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockListen --
 *
 *      Listen for connections with default backlog. Just a wrapper
 *      around Ns_SockListen at the moment.
 *
 * Results:
 *      A socket.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

extern SOCKET
Ns_OpenSSLSockListen (char *address, int port)
{
    return Ns_SockListen (address, port);
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockCallback --
 *
 *      Register a callback to be run when a socket that underlies an
 *      SSL connection reaches a certain state. The callback proc is
 *      responsible for layering SSL on top of the connected socket.
 *
 * Results:
 *      NS_OK/NS_ERROR
 *
 * Side effects:
 *      Will wake up the callback thread.
 *
 *----------------------------------------------------------------------
 */

/* XXX unusable with a direct call except from NsTclSSLSockCallback */
/* XXX essentially, the callback proc is going to have to be reponsible */
/* XXX for layering SSL on top of the socket once a connection comes in, */
/* XXX and before the script is run. I might need a new type, Ns_OpenSSLSockProc */
/* XXX but we'll see. I may be able to create a generic way to do this */
/* XXX so the developer using the API won't have to */

int
Ns_OpenSSLSockCallback (SOCKET sock, Ns_SockProc * proc, void *arg, int when)
{
    return Ns_SockCallback (sock, proc, arg, when);
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockListenCallback --
 *
 *      Listen on an address/port that underlies an SSL connection and
 *      register a callback to be run when connections come in on it.
 *
 * Results:
 *      NS_OK/NS_ERROR
 *
 * Side effects:
 *      Will wake up the callback thread.
 *
 *----------------------------------------------------------------------
 */

/* XXX unusable with a direct call except from NsTclSSLSockListenCallback */
/* XXX essentially, the callback proc is going to have to be reponsible */
/* XXX for layering SSL on top of the socket once a connection comes in, */
/* XXX and before the script is run. I might need a new type, Ns_OpenSSLSockProc */
/* XXX but we'll see. I may be able to create a generic way to do this */
/* XXX so the developer using the API won't have to */

extern int
Ns_OpenSSLSockListenCallback (char *addr, int port, Ns_SockProc * proc,
			      void *arg)
{
    return Ns_SockListenCallback (addr, port, proc, arg);
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
    return DRIVER_NAME;

#if 0 /* XXX revisit */
    NsOpenSSLDriver *driver;

    driver = firstSSLDriverPtr;
    return driver->module;
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
    return sockServerContext;
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
    return sockClientContext;
}


#ifdef AOLSERVER_3


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
    NsOpenSSLDriver *driver = *((NsOpenSSLDriver **) drvDataPtr);

    driver->lsock = Ns_SockListen (driver->bindaddr, driver->port);
    if (driver->lsock == INVALID_SOCKET) {
	Ns_Fatal ("%s: could not listen on %s:%d: %s",
		  driver->module, driver->address ? driver->address : "*",
		  driver->port, ns_sockstrerror (ns_sockerrno));
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
SockFreeConn (NsOpenSSLDriver * driver, Ns_OpenSSLConn * conn)
{
    int refcnt;

    Ns_MutexLock (&driver->lock);
    if (conn != NULL) {
	conn->nextPtr = driver->firstFreePtr;
	driver->firstFreePtr = conn;
    }
    refcnt = --driver->refcnt;
    Ns_MutexUnlock (&driver->lock);

    if (refcnt == 0) {
	NsOpenSSLFreeDriver (driver);
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
    NsOpenSSLDriver *driver, *nextPtr;
    Ns_OpenSSLConn *conn;
    struct sockaddr_in sa;
    SOCKET max, sock;
    char module[32];

    sprintf (module, "-%s-", DRIVER_NAME);
    Ns_ThreadSetName ((char *) &module);

    Ns_Log (Notice, "waiting for startup");
    Ns_WaitForStartup ();
    Ns_Log (Notice, "starting");

    FD_ZERO (&watch);
    FD_SET (trigPipe[0], &watch);
    max = trigPipe[0];

    driver = firstSSLDriverPtr;
    firstSSLDriverPtr = NULL;
    while (driver != NULL) {

	nextPtr = driver->nextPtr;
	if (driver->lsock != INVALID_SOCKET) {
	    Ns_Log (Notice, "%s: listening on %s (%s:%d)",
		    driver->module, driver->location,
		    driver->address ? driver->address : "*", driver->port);
	    if (max < driver->lsock) {
		max = driver->lsock;
	    }
	    FD_SET (driver->lsock, &watch);
	    Ns_SockSetNonBlocking (driver->lsock);
	    driver->nextPtr = firstSSLDriverPtr;
	    firstSSLDriverPtr = driver;
	}
	driver = nextPtr;

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

	driver = firstSSLDriverPtr;
	while (n > 0 && driver != NULL) {
	    if (FD_ISSET (driver->lsock, &set)) {
		--n;
		slen = sizeof (sa);
		sock = accept (driver->lsock, (struct sockaddr *) &sa, &slen);
		if (sock != INVALID_SOCKET) {
		    Ns_MutexLock (&driver->lock);
		    driver->refcnt++;
		    conn = driver->firstFreePtr;
		    if (conn != NULL) {
			driver->firstFreePtr = conn->nextPtr;
		    }
		    Ns_MutexUnlock (&driver->lock);

#ifdef NSOPENSSL_DEBUG
		    Ns_Log(Debug, "SockThread: driver->nsdServerContext = %p", driver->nsdServerContext);
#endif

		    if (conn == NULL) {
			conn = NsOpenSSLCreateConn(sock, driver, ROLE_SSL_SERVER, CONNTYPE_SSL_NSD);
		    }

		    /* 
		     * XXX need to handle the case where conn is STILL NULL
		     * XXX and cleanup gracefully
		     */

#if 0
		    conn->driver        = driver;
#endif
		    conn->sock         = sock;
		    conn->peerport     = ntohs (sa.sin_port);

		    strcpy (conn->peer, ns_inet_ntoa (sa.sin_addr));

		    if (Ns_QueueConn (driver->driver, conn) != NS_OK) {
			Ns_Log (Warning, "%s: connection dropped",
				driver->module);
			(void) SockClose (conn);
		    }
		}
	    }
	    driver = driver->nextPtr;
	}
    } while (!stop);

    while ((driver = firstSSLDriverPtr) != NULL) {
	firstSSLDriverPtr = driver->nextPtr;
	Ns_Log (Notice, "%s: closing %s", driver->module, driver->location);
	ns_sockclose (driver->lsock);
	SockFreeConn (driver, NULL);
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
	Ns_Log (Notice, DRIVER_NAME ":  exiting: triggering shutdown");
	if (send (trigPipe[1], "", 1, 0) != 1) {
	    Ns_Fatal ("trigger send() failed: %s",
		      ns_sockstrerror (ns_sockerrno));
	}
	Ns_ThreadJoin (&sockThread, NULL);
	sockThread = NULL;
	Ns_Log (Notice, DRIVER_NAME ":  exiting: shutdown complete");
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;
    NsOpenSSLDriver *driver = conn->driver;

    if (conn->sock != INVALID_SOCKET) {
	if (conn->ssl != NULL) {
	    NsOpenSSLFlush ((Ns_OpenSSLConn *) conn);
	}
	NsOpenSSLDestroyConn ((Ns_OpenSSLConn *) conn);
    }
    SockFreeConn (driver, conn);
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    return NsOpenSSLRecv (conn, vbuf, toread);
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    return NsOpenSSLSend (conn, buf, towrite);
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    return conn->driver->address;
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    return conn->driver->port;
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    return conn->peer;
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    if (NsOpenSSLFlush ((Ns_OpenSSLConn *) conn) == NS_ERROR) {
	return -1;
    }

    return (int) conn->sock;
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    return conn->peerport;
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
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;

    return conn->driver->location;
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

/* XXX EVALUATE -- is this even needed? */

static int
SockInit (void *arg)
{
#if 0
    Ns_OpenSSLConn *conn = (Ns_OpenSSLConn *) arg;
#endif

#ifdef NSOPENSSL_DEBUG
    Ns_Log(Debug, "%s: SockInit: enter", DRIVER_NAME);
#endif

#if 0
    conn->context = conn->driver->nsdServerContext;
#endif

#if 0
    if (conn->ssl == NULL) {
	return NsOpenSSLCreateConn ((Ns_OpenSSLConn *) conn);
    } else {
	return NS_OK;
    }
#endif

#ifdef NSOPENSSL_DEBUG
    Ns_Log(Debug, "%s: SockInit: leave", DRIVER_NAME);
#endif
    return NS_OK;
}

#else /* AOLSERVER_4 */


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
    Ns_OpenSSLConn *conn;
    Ns_Driver *driver = sock->driver;
    int n, total;

    switch (cmd) {
    case DriverRecv:
    case DriverSend:

	/*          
	 * On first I/O, initialize the connection context.
	 */

	conn = sock->arg;
	if (conn == NULL) {
	    conn = ns_calloc (1, sizeof (*conn));

	    conn->driver = driver->arg;

	    conn->role     = ROLE_SSL_SERVER;
	    conn->conntype = CONNTYPE_SSL_NSD;
	    conn->type     = STR_NSD_SERVER;
	    conn->refcnt   = 0;	/* always 0 for nsdserver conns */
	    conn->sock     = sock->sock;
	    sock->arg       = conn;

	    if (NsOpenSSLCreateConn ((Ns_OpenSSLConn *) conn) != NS_OK) {
		return NS_ERROR;
	    }
	}

	/*
	 * Process each buffer one at a time.
	 */

	total = 0;
	do {
	    if (cmd == DriverSend) {
		n =
		    NsOpenSSLSend ((Ns_OpenSSLConn *) sock->arg, bufs->ns_buf,
				   bufs->ns_len);
	    } else {
		n =
		    NsOpenSSLRecv ((Ns_OpenSSLConn *) sock->arg, bufs->ns_buf,
				   bufs->ns_len);
	    }
	    if (n < 0 && total > 0) {
		/* NB: Mask error if some bytes were read. */
		n = 0;
	    }
	    ++bufs;
	    total += n;
	} while (n > 0 && --nbufs > 0);
	n = total;
	break;

    case DriverKeep:
	if (sock->arg != NULL && NsOpenSSLFlush (sock->arg) == NS_OK) {
	    n = 0;
	} else {
	    n = -1;
	}
	break;

    case DriverClose:
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
