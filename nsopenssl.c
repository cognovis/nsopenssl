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

#include "nsopenssl.h"


#ifdef AOLSERVER_3
static NsOpenSSLDriver *NsOpenSSLDriverCreate (char *server, char *module,
		Ns_DrvProc *procs);
#else
static NsOpenSSLDriver *NsOpenSSLDriverCreate (char *server, char *module);
#endif

static void NsOpenSSLDriverFree (NsOpenSSLDriver *driver);

static void DriverStructClear (void);
static int InitOpenSSL (void);
static int SessionCacheIdGetNext (void);
static int AddEntropyFromRandomFile (NsOpenSSLDriver *driver, long maxbytes);
static int SeedPRNG (NsOpenSSLDriver *driver);
static RSA *IssueTmpRSAKey (SSL *ssl, int export, int keylen);
static int ConfigLoadSSLContexts (char *server, char *module);

static Ns_OpenSSLContext *ConfigLoadSSLContext (char *server, char *module, 
		char *name, char *desc, char *type);
static int InitSSLContexts (Ns_OpenSSLContext *context);

static int SetProtocols (Ns_OpenSSLContext *context);
static int SetCipherSuite (Ns_OpenSSLContext *context);

static int LoadCertificate (char *module, SSL_CTX *context, char *certFile);
static int LoadKey (char *module, SSL_CTX *context, char *keyFile);
static int CheckKey (char *module, SSL_CTX *context);
static int LoadCACerts (char *module, SSL_CTX *context, char *caFile,
		char *caDir);
static int InitLocation (NsOpenSSLDriver *driver);
static int PeerVerifyCallback (int preverify_ok, X509_STORE_CTX *x509_ctx);
static char *GetModuleDir (char *server, char *module);

static char *ConfigGetStringDefault (char *module, char *path, char *name,
		char *def);
static int ConfigGetBoolDefault (char *module, char *path, char *name, int def);
static int ConfigGetIntDefault (char *module, char *path, char *name, int def);
static char *
ConfigGetPathValue (char *path, char *name, char *dir)

static char *ConfigGetPathDefault (char *module, char *path, char *name, char *dir, char *def);
static char *ConfigGetPathValueDefault (char *path, char *name, char *dir, char *def);
static char *ConfigGetPathValueRequired (char *path, char *name, char *dir);
static char *ConfigGetPath (char *path, char *name, char *dir, char *def, int required);

/* XXX needed still? */
static Ns_Mutex *locks;


/*
 * OpenSSL Callbacks
 */

static void LockCallback (int mode, int n, const char *file, int line);
static unsigned long IdCallback (voNs_OpenSSLContext *contextid);
static struct CRYPTO_dynlock_value *DynlockCreateCallback (char *file,
		int line);
static void DynlockLockCallback (int mode,
		struct CRYPTO_dynlock_value *dynlock,
		const char *file, int line);
static void DynlockDestroyCallback (struct CRYPTO_dynlock_value *dynlock,
		const char *file, int line);


static int SetProtocols (Ns_OpenSSLContext *context);


typedef struct SessionCacheId {
	Ns_Mutex lock = NULL;
	int id = 0;
} SessionCacheId;

static SessionCacheId *nextSessionCacheId;

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

#ifdef AOLSERVER_3


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
    static int loaded = 0;
    int seedcount = 0;

#ifdef NSOPENSSL_DEBUG
    Ns_Log(Debug, "%s: NSOPENSSL_DEBUG is set", MODULE_NAME);
#endif

    /*
     * Loading nsopenssl more than once is a fatal error. Previous versions
     * could be loaded under different module names, but this was never
     * supported. This and future versions of nsopenssl have been improved to
     * handle multiple drivers and SSL contexts.  If you really think you need
     * to load more than one copy of this module, let me know and we'll figure
     * out what you're attempting to do.
     */

    if (loaded) {
	    Ns_Log(Error, "%s: Loading this module multiple times is not supported",
			    MODULE_NAME);
	    return NS_ERROR;
    }
    loaded = 1;

    /*
     * Initialize the OpenSSL library
     */

    if (InitOpenSSL () == NS_ERROR) {
	    Ns_Log(Error, "%s: Failed to initialize OpenSSL", MODULE_NAME);
	    return NS_ERROR;
    }
    
    /*
     * Load and initialize the SSL context structures defined in the config
     * file
     */

    if (LoadSSLContexts(void) == NS_ERROR) {
	    Ns_Log(Error, "%s: Failed to load the SSL Contexts", MODULE_NAME);
	    return NS_ERROR;
    }

    if (InitSSLContexts(void) == NS_ERROR) {
	    Ns_Log(Error, "%s: Failed to initialize the SSL Contexts", MODULE_NAME);
	    return NS_ERROR;
    }

    /*
     * Create the nsopenssl Tcl API
     */

    if (Ns_TclInitInterps (server, NsOpenSSLCreateCmds, NULL) != NS_OK) {
	return NS_ERROR;
    }

#ifdef AOLSERVER_4

    /* XXX need a for loop to init each of multiple drivers, or none if nsd
     * XXX server is not to manage core nsd server conns */

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

    return Ns_DriverInit (server, module, MODULE_NAME, OpenSSLProc, driver,
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
 * NsOpenSSLDriverCreate --
 *
 *       Create an SSL driver. There will be one for each port managed.
 *
 * Results:
 *       An NsOpenSSLDriver* or NULL.
 *
 * Side effects:
 *       Allocates memory. Adds driver to driver linked list.
 *
 *----------------------------------------------------------------------
 */

static NsOpenSSLDriver *
#ifdef AOLSERVER_3
NsOpenSSLDriverCreate (char *server, char *module, Ns_DrvProc * procs)
#else
NsOpenSSLDriverCreate (char *server, char *module)
#endif
{
    NsOpenSSLDriver *driver = NULL;

    driver = (NsOpenSSLDriver *) ns_calloc (1, sizeof *driver);

    if (driver == NULL) {
	    Ns_Log(Error, "%s: Failed to create driver structure", module);
	    return NULL;
    }

    DriverStructClear (driver);

    driver->server     = server;
    driver->module     = module;
    driver->configPath = Ns_ConfigGetPath(server, module, NULL);

    Ns_MutexSetName(&driver->lock, module);

    /* XXX this is now global and needs to be moved to AddEntropyFromFile */
    driver->randomFile = ConfigGetPathDefault (driver->module, driver->configPath,
					   CONFIG_RANDOMFILE, driver->dir,
					   NULL);

    driver->timeout = ConfigIntDefault (module, driver->configPath,
				       CONFIG_SERVER_SOCKTIMEOUT,
				       DEFAULT_SERVER_SOCKTIMEOUT);
    if (driver->timeout < 1) {
	driver->timeout = DEFAULT_SERVER_SOCKTIMEOUT;
    }

    driver->bufsize = ConfigIntDefault (module, driver->configPath,
				       CONFIG_SERVER_BUFFERSIZE,
				       DEFAULT_SERVER_BUFFERSIZE);
    if (driver->bufsize < 1) {
	driver->bufsize = DEFAULT_SERVER_BUFFERSIZE;
    }

    if (SetModuleDir (driver) == NS_ERROR || InitLocation (driver) == NS_ERROR) {
	NsOpenSSLFreeDriver (driver);
	return NULL;
    }

#ifdef AOLSERVER_3
    driver->driver = Ns_RegisterDriver (server, module, procs, driver);
    if (driver->driver == NULL) {
	NsOpenSSLFreeDriver (driver);
	return NULL;
    }
#endif

    return driver;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDriverFree --
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

static void
NsOpenSSLDriverFree (NsOpenSSLDriver *driver)
{
    if (driver == NULL)
	    return void;

    Ns_Log (Debug, "%s: freeing(%p)",
	    driver == NULL ? MODULE_NAME : driver->module, driver);

    DriverStructClear (driver);

    Ns_Free (driver);
}



/*
 *----------------------------------------------------------------------
 *
 * DriverStructClear --
 *
 *      Initialize all values for an NsOpenSSLDriver struct. Called both when
 *      creating a new driver to clear it, and just before freeing a driver, to
 *      clear it.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Memory may be freed.
 *
 *----------------------------------------------------------------------
 */

static void
DriverStructClear (NsOpenSSLDriver *driver)
{
    Ns_OpenSSLConn *conn;

    if (driver == NULL)
	    return void;
    
    /* 
     * Free all of the conn structures associated with this driver, if any.
     */

    while ((conn = driver->firstFree) != NULL) {
	    driver->firstFree = conn->next;
	    /* XXX doesn't this need to have it's contents free'd? */
	    Ns_Free (conn);
    }

    Ns_MutexDestroy (&driver->lock);
    
    if (driver->sslContext != NULL) {
	    Ns_OpenSSLContextFree(driver->sslContext);
	    driver->sslContext = NULL;
    }
    
    if (driver->dir != NULL)
	    Ns_Free (driver->dir);
    
    if (driver->address != NULL)
	    Ns_Free (driver->address);
    
    if (driver->location != NULL)
	    Ns_Free (driver->location);
    
    if (driver->randomFile != NULL)
	    Ns_Free (driver->randomFile);
    
    driver->driver            = NULL;
    driver->next              = NULL;
    driver->lock              = NULL;
    driver->server            = NULL;
    driver->module            = NULL;
    driver->configPath        = NULL;
    driver->dir               = NULL;
    driver->location          = NULL;
    driver->address           = NULL;
    driver->bindaddr          = NULL;
    driver->randomFile        = NULL;
    driver->lsock             = INVALID_SOCKET;
    driver->port              = -1;
    driver->refcnt            = 1;
    driver->bufsize           = DEFAULT_SERVER_BUFFERSIZE;
    driver->timeout           = DEFAULT_SERVER_SOCKTIMEOUT;

    return void;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockConnect --
 *
 *      Open an SSL connection to the given host and port.
 *
 * Arguments:
 *      name:    The name of the SSL context to use
 *      host:    The remote hosts name or IP address
 *      port:    The port to connect to
 *      async:   If 0, leave socket in synchronous mode, otherwise async
 *      timeout: How long to wait for response from remote host
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
Ns_OpenSSLSockConnect (char *name, char *host, int port, int async, int timeout)
{
    Ns_OpenSSLConn *conn;
    SOCKET sock;

#ifdef NSOPENSSL_DEBUG
    Ns_Log (Debug, "%s: NsOpenSSLSockConnect -- enter", MODULE_NAME);
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
    Ns_Log (Debug, "%s: NsOpenSSLSockConnect -- leave", MODULE_NAME);
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
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      sock: the socket id that we're accept'ing on
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
Ns_OpenSSLSockAccept (char *name, SOCKET sock)
{
    Ns_OpenSSLConn *conn = NULL;

    if (sock == INVALID_SOCKET)
        return NULL;

    /* XXX these args must be changed */
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
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      addr: the IP address to bind to
 *      port: the port to listen on
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
Ns_OpenSSLSockListen (char *name, char *addr, int port)
{
    return Ns_SockListen (addr, port);
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
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      sock: the id of the socket to listen on
 *      proc: the proc to run when a connection comes in
 *      when:
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
Ns_OpenSSLSockCallback (char *name, SOCKET sock, Ns_SockProc *proc, void *arg, int when)
{
	/* XXX need to handle SSL wrapping here somehow... */
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
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      addr: the IP address to listen on
 *      port: the port to listen on
 *      proc: the proc to run when a connection comes in
 *      arg:  the argument to pass to the proc
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
Ns_OpenSSLSockListenCallback (char *name, char *addr, int port, Ns_SockProc *proc,
			      void *arg)
{
    return Ns_SockListenCallback (addr, port, proc, arg);
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLModuleNameGet --
 *
 *	Return this module's name.
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
    return MODULE_NAME;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSockServerDefault --
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

extern Ns_OpenSSLContext *
NsOpenSSLContextSockServerDefault (void)
{
    return sockServerContext;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSockClientDefault --
 *
 *	Return a pointer to the default SSL Context for Sock Clients. 
 *
 * Results:
 *	Pointer to Ns_OpenSSLContext.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

extern Ns_OpenSSLContext *
NsOpenSSLContextSockClientDefault (void)
{
    return sockClientContext;
}


/*
 *----------------------------------------------------------------------
 *
 * InitOpenSSL --
 *
 *       Initialize the SSL library.
 *
 * Results:
 *       NS_OK
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
InitOpenSSL (void)
{
    static int initialized = 0;
    int i;
    int num_locks;
    char buf[100];

    /*
     * Initialize OpenSSL callbacks
     */

    if (!initialized) {
	initialized = 1;

	if (CRYPTO_set_mem_functions (Ns_Malloc, Ns_Realloc, Ns_Free) == 0) {
	    Ns_Log (Warning, MODULE_NAME
		    ": could not set OpenSSL memory callbacks to use AOLserver memory allocation");
	}

	num_locks = CRYPTO_num_locks ();
	locks = Ns_Calloc (num_locks, sizeof *locks);
	for (i = 0; i < num_locks; i++) {
	    sprintf (buf, "openssl-%d", i);
	    Ns_MutexSetName2 (locks + i, MODULE_NAME, buf);
	}

	CRYPTO_set_locking_callback (LockCallback);
	CRYPTO_set_id_callback (IdCallback);
    }

    /*
     * Initialize the OpenSSL library
     */

    SSL_load_error_strings ();
    OpenSSL_add_ssl_algorithms ();
    SSL_library_init ();
    X509V3_add_standard_extensions ();

    /*
     * Seed the OpenSSL Pseudo-Random Number Generator.
     */

    while (! RAND_status () && seedcnt < 3) {
	    seedcnt++;
	    Ns_Log (Notice, MODULE_NAME, ": Seeding OpenSSL's PRNG");
	    SeedPRNG (void);
    }

    if (! RAND_status ()) {
	    Ns_Log (Warning, MODULE_NAME, 
			    ": OpenSSL PRNG fails to have enough entropy after %d tries", 
			    seedcnt);
    } else {
	    Ns_Log (Notice, MODULE_NAME, ": OpenSSL's PRNG is seeded properly"); 
    }

    /*
     * Initialize the session cache id number generator.
     */

    nextSessionCacheId = (SessionCacheId *) ns_calloc (1, sizeof *nextSessionCacheId);

    if (nextSessionCacheId == NULL) {
	    Ns_Log (Error, MODULE_NAME,
			    ": Failed to allocate memory for session id generator");
	    return NS_ERROR;
    }

    Ns_MutexLock(&nextSessionCacheId->lock);
    Ns_MutexSetName2(&nextSessionCacheId->lock, MODULE_NAME, "sessioncacheid");
    nextSessionCacheId->id = 1;
    Ns_MutexUnlock(&nextSessionCacheId->lock);
    
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SessionCacheIdGetNext --
 *
 *      Get the next unique session cache id number
 *
 * Results:
 *      Integer number
 *
 * Side effects:
 *      Increments the global session cache id generator.
 *
 *----------------------------------------------------------------------
 */

static int
SessionCacheIdGetNext (void)
{
    int id;

    Ns_MutexLock(&nextSessionCacheId->lock);
    id = nextSessionCacheId->id;
    nextSessionCacheId->id++;
    Ns_MutexUnlock(&nextSessionCacheId->lock);

    return id;
}

/*
 *----------------------------------------------------------------------
 *
 * LockCallback --
 *
 *      Lock or unlock a mutex for OpenSSL.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
LockCallback (int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
	Ns_MutexLock (locks + n);
    } else {
	Ns_MutexUnlock (locks + n);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * IdCallback --
 *
 *      Return this thread's id for OpenSSL.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static unsigned long
IdCallback (void)
{
    return (unsigned long) Ns_ThreadId ();
}

/*
 *----------------------------------------------------------------------
 *
 * DynlockCreateCallback --
 *
 *      Create a dynamically-allocated mutex for OpenSSL.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static struct CRYPTO_dynlock_value *
DynlockCreateCallback (char *file, int line)
{
    Ns_Mutex *lock;
    Ns_DString ds;

    lock = ns_calloc (1, sizeof *lock);

    Ns_DStringInit (&ds);
    Ns_DStringVarAppend (&ds, "openssl: ", file, ": ");
    Ns_DStringPrintf (&ds, "%d", line);

    Ns_MutexSetName2 (lock, MODULE_NAME, Ns_DStringValue (&ds));

    return (struct CRYPTO_dynlock_value *) lock;
}

/*
 *----------------------------------------------------------------------
 *
 * DynlockLockCallback --
 *
 *      Lock or unlock a dynamically-allocated mutex for OpenSSL.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DynlockLockCallback (int mode, struct CRYPTO_dynlock_value *dynlock,
		     const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
	Ns_MutexLock ((Ns_Mutex *) dynlock);
    } else {
	Ns_MutexUnlock ((Ns_Mutex *) dynlock);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * DynlockDestroyCallback --
 *
 *      Destroy a dynamically-allocated mutex for OpenSSL.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DynlockDestroyCallback (struct CRYPTO_dynlock_value *dynlock,
			const char *file, int line)
{
    Ns_MutexDestroy ((Ns_Mutex *) dynlock);
}

/*
 *----------------------------------------------------------------------
 *
 * AddEntropyFromRandomFile --
 *
 *       Grabs a number of bytes from a file to seed the OpenSSL
 *       PRNG.
 *
 * Results:
 *       None.
 *
 * Side effects:
 *       Directly seeds OpenSSL's PRNG by calling RAND_load_file.
 *
 *----------------------------------------------------------------------
 */

static int
AddEntropyFromRandomFile (NsOpenSSLDriver *driver, long maxbytes)
{
    int readbytes;

    if (driver->randomFile == NULL) {
	return NS_FALSE;
    }

    if (access (driver->randomFile, F_OK) == 0) {
	if ((readbytes = RAND_load_file (driver->randomFile, maxbytes))) {
	    Ns_Log (Debug, "%s: Obtained %d random bytes from %s",
		    driver->module, readbytes, driver->randomFile);
	    return NS_TRUE;
	} else {
	    Ns_Log (Warning, "%s: Unable to retrieve any random data from %s",
		    driver->module, driver->randomFile);
	    return NS_FALSE;
	}
    }
    return NS_FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * SeedPRNG --
 *
 *       Seed OpenSSL's PRNG. Note that OpenSSL will seed the PRNG
 *       transparently if /dev/urandom is available, which it is
 *       on Linux.
 *
 * Results:
 *       NS_TRUE or NS_FALSE.
 *
 * Side effects:
 *       An NS_FALSE will result in the connection failing. This function
 *       might be called at any time by the temporary key generating
 *       function if the PRNG is not sufficiently entropinous (yes, I
 *       made that word up).
 *       
 *
 *----------------------------------------------------------------------
 */

/* XXX need to eliminate looking to config file here, and need to incorporate
 * XXX AddEntropyFromRandomFile into this routine */
static int
SeedPRNG (void)
{
    int i;
    double *buf_ptr = NULL;
    double *bufoffset_ptr = NULL;
    size_t size;
    int seedbytes;

    if (RAND_status ()) 
	return NS_TRUE;

    Ns_Log (Notice, "%s: Seeding the PRNG", MODULE_NAME);

    seedbytes = ConfigGetIntDefault (driver->module, driver->configPath,
				  CONFIG_SEEDBYTES, DEFAULT_SEEDBYTES);

    /*
     * Try to use the file specified by the user.
     */

    AddEntropyFromRandomFile (driver, seedbytes);

    if (RAND_status ()) {
	return NS_TRUE;
    }

    /*
     * Use Ns API; I have no idea how to measure the amount of entropy, so for
     * now I just pass the same number as the 2nd arg to RAND_add. Not all of
     * the buffer is used.
     */

    size = sizeof (double) * seedbytes;
    buf_ptr = Ns_Malloc (size);
    bufoffset_ptr = buf_ptr;
    for (i = 0; i < seedbytes; i++) {
	*bufoffset_ptr = Ns_DRand ();
	bufoffset_ptr++;
    }
    RAND_add (buf_ptr, seedbytes, (long) seedbytes);
    Ns_Free (buf_ptr);
    Ns_Log (Notice, "%s: Seeded PRNG with %d bytes from Ns_DRand",
	    MODULE_NAME, seedbytes);

    if (RAND_status ())
	return NS_TRUE;

    Ns_Log (Warning, "%s: Failed to seed PRNG with enough entropy",
	    MODULE_NAME);
    return NS_FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * IssueTmpRSAKey --
 *
 *       Give out the temporary key when needed. This is a callback function
 *       used by OpenSSL and is required for 40-bit browsers.
 *
 * Results:
 *       Returns a pointer to the new temporary key.
 *
 * Side effects:
 *       Attempts to Seed the PRNG if needed. If PRNG doesn't contain enough
 *       entropy, key won't be returned and the connection will fail.
 *
 *----------------------------------------------------------------------
 */

static RSA *
IssueTmpRSAKey (SSL * ssl, int export, int keylen)
{
    Ns_OpenSSLConn *conn;
    NsOpenSSLDriver *driver;
    static RSA *rsa_tmp = NULL;

    conn = (Ns_OpenSSLConn *) SSL_get_app_data (ssl);
    driver = conn->driver;

    if (SeedPRNG (driver)) {
	rsa_tmp = RSA_generate_key (keylen, RSA_F4, NULL, NULL);
	Ns_Log (Notice, "%s: Generated %d-bit temporary RSA key",
		driver->module, keylen);
	return rsa_tmp;
    } else {
	Ns_Log (Warning,
		"%s: temporary RSA key issue failed: insufficient entropy in PRNG",
		MODULE_NAME);
	return NULL;
    }
}


/*
 *----------------------------------------------------------------------
 *
 * ConfigLoadSSLContexts --
 *
 *      Load SSL Contexts that are defined in the configuration file.
 *
 * Results:
 *      NS_OK or NS_ERROR
 *
 * Side effects:
 *      NsOpenSSLContext structures are created
 *
 *----------------------------------------------------------------------
 */
static int
ConfigLoadSSLContexts(char *server, char *module)
{
	Ns_Set *servers;
	Ns_Set *sockservers;
	Ns_Set *sockclients;
	int i = 0;
	char *key = NULL;
	char *configPath = Ns_ConfigGetPath(server, module, NULL);

	/*
	 * Identify defined servers, sockservers and sockclients
	 */

	servers     = Ns_ConfigGetSection("servers");
	sockservers = Ns_ConfigGetSection("sockservers");
	sockclients = Ns_ConfigGetSection("sockclients");

	/*
	 * Load server contexts
	 */

	for (i = 0; i < Ns_SetSize(servers); ++i) {
		key = Ns_SetKey(servers, i);
		LoadSSLContext(server, module, servers, key, 
				Ns_SetGet(servers, key), "server");
	}

	/*
	 * Load sockserver contexts
	 */

	for (i = 0; i < Ns_SetSize(sockservers); ++i) {
		key = Ns_SetKey(sockservers, i);
		LoadSSLContext(server, module, sockservers, key, 
				Ns_SetGet(sockservers, key), "sockserver");
	}

	/*
	 * Load sockclient contexts
	 */

	for (i = 0; i < Ns_SetSize(sockclients); ++i) {
		key = Ns_SetKey(sockclients, i);
		LoadSSLContext(server, module, sockclients, key, 
				Ns_SetGet(sockclients, key), "sockclient");
	}

	return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCreate --
 *
 *       Create a new Ns_OpenSSLContext structure
 *
 * Results:
 *       Pointer to resulting struct or NULL on error
 *
 * Side effects:
 *       Memory may be allocated
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLContext *
Ns_OpenSSLContextCreate (char *server, char *module, char *name, char *desc, char *type)
{
    Ns_OpenSSLContext *context = NULL;
    int connType = -1;

    /*
     * The name of an SSL context must be unique within a virtual server.
     */

    if (OpenSSLContextNameCheck (server, module, name)) {
	    Ns_Log(Error, "%s: SSL context with name %s already defined",
			    MODULE_NAME, name);
	    return NULL;
    }

    /*
     * Set the connection type: "server" is driven by the core nsd HTTP
     * process; sockservers and sockclients are driven by the nsopenssl C and
     * Tcl APIs.
     */

    if (STREQ (type, "server")) {
	    conntype = CONNTYPE_SERVER;
    } elseif (STREQ (type, "sockserver")) {
	    conntype = CONNTYPE_SOCKSERVER;
    } elseif (STREQ (type, "sockclient")) {
	    conntype = CONNTYPE_SOCKCLIENT;
    } else {
	    Ns_Log (Error, "%s: SSL context type %s is invalid",
			    MODULE_NAME, type);
	    return NULL;
    }

    /*
     * Allocate the SSL context.
     */

    context = (Ns_OpenSSLContext *) ns_calloc (1, sizeof *context);

    if (context == NULL) {
	    Ns_Log(Error, "%s: Failed to create SSL context named %s", 
			    MODULE_NAME, name);
	    return NULL;
    }

    Ns_MutexLock(&context->lock);
    /* XXX make mutex name unique to this struct instance */
    Ns_MutexSetName2(&context->lock, MODULE_NAME, "context");

    /*
     * Set most important fields here
     */

    context->server     = server;
    context->module     = module;
    context->name       = strdup (key);
    context->desc       = strdup (desc);
    context->conntype   = conntype;

    /*
     * All contexts get a session cache id even if they don't turn on session caching.
     */

    context->sessioncacheid = SessionCacheIdGetNext(void);

    /*
     * Insert the context into the linked list. Instead of wasting time looking
     * for the end of the list, we'll insert it at the front.
     */

    /* XXX should there be locking of firstSSLContext? */

    if (firstSSLContext != NULL) {
	    /* There are already other contexts */
	    context->next = firstSSLContext;
	    firstSSLContext = context;
    } else {
	    /* We're the first context created */
	    context->next = NULL;
	    firstSSLContext = context;
    }

    Ns_MutexUnlock(&context->lock);

    return context;
}


/*
 *----------------------------------------------------------------------
 *
 * ConfigLoadSSLContext --
 *
 *       Load values for a given SSL context from the configuration file.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Memory may be allocated
 *
 *----------------------------------------------------------------------
 */

static Ns_OpenSSLContext *
ConfigLoadSSLContext (char *server, char *module, char *name, char *desc, char *type)
{
    Ns_OpenSSLContext *context = NULL;
    char *configPath = Ns_ConfigGetPath(server, module, name, NULL);
    char *moduleDir = NULL;
    int conntype = -1;
    Ns_DString ds;

    context = Ns_OpenSSLContextCreate (server, module, name, desc, type);

    if (context == NULL)
	    return NULL;

    /*
     * Create a default directory path in which to find certs, keys and such.
     */

    Ns_DStringInit (&ds);
    Ns_HomePath (&ds, "servers", server, "modules", module, NULL);
    moduleDir = Ns_DStringExport (&ds);
    Ns_DStringFree (&ds);

    /*
     * See if a module directory path is set in the config file; if not, then
     * use default
     */

    context->moduledir = ConfigGetPathDefault (configPath, "moduledir", 
		    NULL, moduleDir);

    /*
     * SSL clients don't require certificates, but SSL servers do.
     */

    if (context->conntype == CONNTYPE_SOCKCLIENT) {
	    context->certfile = ConfigGetPathValue (configPath, 
			    "certfile", moduleDir);
	    context->keyfile = ConfigGetPathValue (configPath, 
			    "keyfile",  moduleDir);
    } else {
	    context->certfile = ConfigGetPathValueRequired (configPath, 
			    "certfile", moduleDir);
	    context->keyfile = ConfigGetPathValueRequired (configPath, 
			    "keyfile",  moduleDir);
    }

    /*
     * Protocols and CipherSuite will default
     */

    context->protocols = ConfigGetStringDefault (configPath, 
		    "protocols", DEFAULT_PROTOCOLS);

    context->ciphersuite = ConfigGetStringDefault (configPath, 
		    "ciphersuite", DEFAULT_CIPHERSUITE);

    /*
     * The CA file/dir isn't really necessary unless you actually intend use
     * cert verification.
     */

    context->cafile = ConfigGetPathValue (configPath, 
		    "cafile",  moduleDir, DEFAULT_CAFILE);

    context->cadir = ConfigGetPathDefault (configPath, 
		    "cadir",  moduleDir, DEFAULT_CADIR);

    context->crlfile = NULL;

    context->crldir  = NULL;

    context->peerverifyon = ConfigGetBoolDefault (configPath, 
		    "peerverifyon", DEFAULT_PEERVERIFYON);

    context->peerverifydepth = (int) ConfigGetIntDefault (configPath, 
		    "peerverifydepth", DEFAULT_PEERVERIFYDEPTH);

    context->peerabortoninvalid = 0;

    context->peerabortproc = NULL;

    context->sessioncacheon = ConfigGetBoolDefault (configPath, 
		    "sessioncacheon", DEFAULT_SESSIONCACHEON);

    context->sessioncacheid = (int) ConfigGetIntDefault (configPath, 
		    "sessioncacheid", NsSessionIdGenerate());

    context->sessioncachesize = ConfigGetIntDefault (configPath, 
		    "sessioncachesize", DEFAULT_SESSIONCACHESIZE);

    context->sessioncachetimeout = (long) ConfigGetIntDefault (configPath, 
		    "sessioncachetimeout", DEFAULT_SESSIONCACHETIMEOUT);

    context->trace = ConfigGetBoolDefault (configPath, 
		    "trace", DEFAULT_TRACE);

    context->sslctx = NULL;

    Ns_Free (defaultDir);

    return context;
}



/*
 *----------------------------------------------------------------------
 *
 * InitSSLContext --
 *
 *       Create a new SSL context for the specified NsOpenSSLContext.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
InitSSLContext (Ns_OpenSSLContext *context)
{
    /* XXX lock struct */

	/* XXX handle SSL_v2/v3 methods??? */
	/* XXX handle server vs client */
    context->sslctx = SSL_CTX_new (SSLv23_server_method ());

    if (context->sslctx == NULL) {
	Ns_Log (Error, "%s: error creating SSL context", MODULE_NAME);
	/* XXX unlock struct */
	return NS_ERROR;
    }

    /*
     * If we have the ssl struct, we can get the pointer to the
     * NsOpenSSLContext.
     */
    
    SSL_CTX_set_app_data (context->sslctx, context);

    /*
     * Enable SSL bug compatibility.
     * XXX expand this so user can configure what bug handling options they
     * want
     */

    SSL_CTX_set_options (context->sslctx, SSL_OP_ALL);

    /*
     * This apparently prevents some sort of DH attack.
     */

    SSL_CTX_set_options (context->sslctx, SSL_OP_SINGLE_DH_USE);

    /*
     * Temporary key callback required for 40-bit export browsers
     */

    SSL_CTX_set_tmp_rsa_callback (context->sslctx, IssueTmpRSAKey);

    /*
     * Set peer verify and verify depth
     */

    if (context->peerVerify) {
	SSL_CTX_set_verify (context->sslctx,
			(SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE),
			PeerVerifyCallback);
	SSL_CTX_set_verify_depth (context->sslctx, context->verifyDepth);
    } else {
	SSL_CTX_set_verify (context->sslctx, SSL_VERIFY_NONE, NULL);
    }

    /*
     * Set SSL handshake and connection tracing
     */

    if (context->trace) {
	SSL_CTX_set_info_callback (context->sslctx, NsOpenSSLTrace);
    }

    /*
     * Set protocols
     */

    if (SetProtocols (context->module, context->sslctx, protocols) != NS_OK)
	return NS_ERROR;

    /*
     * Set cipher suite
     */

    cipherSuite = ConfigStringDefault (context->module, context->configPath,
				       CONFIG_SERVER_CIPHERSUITE,
				       DEFAULT_SERVER_CIPHERSUITE);

    if (SetCipherSuite (context->module, context->sslctx, cipherSuite) != NS_OK)
	/* XXX unlock struct */
	return NS_ERROR;

    /*
     * Load certificate
     */

    if (LoadCertificate (context->module, context->sslctx, context->certFile) != NS_OK)
	/* XXX unlock struct */
	return NS_ERROR;

    /*
     * Load the key that unlocks the certificate
     */

    if (LoadKey (context->module, context->sslctx, context->keyFile) != NS_OK)
	/* XXX unlock struct */
	return NS_ERROR;

    /*
     * Check the key against the certificate
     */

    if (CheckKey (context->module, context->sslctx) != NS_OK)
	/* XXX unlock struct */
	return NS_ERROR;

    /*
     * Load CA certificates
     */

    if (LoadCACerts (context->module, context->sslctx, 
			    context->caFile, context->caDir) != NS_OK)
	/* XXX unlock struct */
	return NS_ERROR;

    /*
     * Initialize the session cache
     */

    if (context->cache) {

	SSL_CTX_set_session_cache_mode (context->sslctx, SSL_SESS_CACHE_SERVER);

	SSL_CTX_set_session_id_context (context->sslctx,
			(void *) &context->sessionCacheId, 
			sizeof (context->sessionCacheId));

	SSL_CTX_set_timeout (context->sslctx, context->sessionCacheTimeout);

	SSL_CTX_sess_set_cache_size (context->sslctx, context->sessionCacheSize);

    } else {

	SSL_CTX_set_session_cache_mode (context->sslctx, SSL_SESS_CACHE_OFF);
    }

    /* XXX unlock struct */
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SetProtocols --
 *
 *       Set the protocols for given SSL context as requested.
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
SetProtocols (Ns_OpenSSLContext *context)
{
    int bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    char *protocols = NULL;

    if (context->protocols == NULL) {
	Ns_Log (Notice, "%s: Protocol string not set; using all protocols: SSLv2, SSLv3 and TLSv1",
	bits = 1;
		MODULE_NAME);
    } else {
	    protocols = ns_strdup (context->protocols);
	    protocols = Ns_StrToLower (protocols);

	    if (strstr (protocols, "all") != NULL) {
		    bits = 1;
		    Ns_Log (Notice, "%s: using all protocols: SSLv2, SSLv3 and TLSv1",
				    module);
	    } else {
		    if (strstr (protocols, "sslv2") != NULL) {
			    bits &= ~SSL_OP_NO_SSLv2;
			    Ns_Log (Notice, "%s: Using SSLv2 protocol", MODULE_NAME);
		    }
		    if (strstr (protocols, "sslv3") != NULL) {
			    bits &= ~SSL_OP_NO_SSLv3;
			    Ns_Log (Notice, "%s: Using SSLv3 protocol", MODULE_NAME);
		    }
		    if (strstr (protocols, "tlsv1") != NULL) {
			    bits &= ~SSL_OP_NO_TLSv1;
			    Ns_Log (Notice, "%s: Using TLSv1 protocol", MODULE_NAME);
		    }
	    }

	    Ns_Free (protocols);
    }

    /* 
     * XXX add check to see if bits is meaningless, indicating that the
     * protocol config param exists but is garbage 
     */

    SSL_CTX_set_options (context->sslctx, bits);

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

    Ns_Free (certFile);

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

    Ns_Free (keyFile);

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
	Ns_Free (caFile);
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

	Ns_Free (caDir);
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
	Ns_Free (caFile);
    if (caDir != NULL)
	Ns_Free (caDir);

    return status;
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
InitLocation (NsOpenSSLDriver * driver)
{
    char *hostname;
    char *lookupHostname;
    Ns_DString ds;

    driver->bindaddr = ConfigStringDefault (driver->module, driver->configPath,
					   "ServerAddress", NULL);

    hostname = ConfigStringDefault (driver->module, driver->configPath,
				    "ServerHostname", NULL);

    if (driver->bindaddr == NULL) {
	lookupHostname = (hostname != NULL) ? hostname : Ns_InfoHostname ();
	Ns_DStringInit (&ds);
	if (Ns_GetAddrByHost (&ds, lookupHostname) == NS_ERROR) {
	    Ns_Log (Error, "%s: failed to resolve '%s': %s",
		    driver->module, lookupHostname, strerror (errno));
	    return NS_ERROR;
	}

	driver->address = Ns_DStringExport (&ds);
    } else {
	driver->address = ns_strdup (driver->bindaddr);
    }

    if (hostname == NULL) {
	Ns_DStringInit (&ds);
	if (Ns_GetHostByAddr (&ds, driver->address) == NS_ERROR) {
	    Ns_Log (Warning, "%s: failed to reverse resolve '%s': %s",
		    driver->module, driver->address, strerror (errno));
	    hostname = ns_strdup (driver->address);
	} else {
	    hostname = Ns_DStringExport (&ds);
	}
    }

    driver->port = ConfigIntDefault (driver->module, driver->configPath,
				    "ServerPort", DEFAULT_PORT);

    driver->location = ConfigStringDefault (driver->module, driver->configPath,
					   "ServerLocation", NULL);
    if (driver->location != NULL) {
	driver->location = ns_strdup (driver->location);
    } else {
	Ns_DStringInit (&ds);
	Ns_DStringVarAppend (&ds, DEFAULT_PROTOCOL "://", hostname, NULL);
	if (driver->port != DEFAULT_PORT) {
	    Ns_DStringPrintf (&ds, ":%d", driver->port);
	}
	driver->location = Ns_DStringExport (&ds);
    }
    Ns_Log (Notice, "%s: location %s", driver->module, driver->location);

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
 * GetModuleDir --
 *
 *       Get the absolute path of the module's directory.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       May create the directory on disk
 *
 *----------------------------------------------------------------------
 */

static char *
GetModuleDir (char *server, char *module)
{
    char *path;
    Ns_DString ds;

    Ns_DStringInit (&ds);

    path = Ns_ConfigGetValue (Ns_ConfigGetPath(server, module, NULL), 
			    CONFIG_MODULE_DIR);

    /* Path not set in config; create default path */
    
    if (path == NULL) {
	Ns_ModulePath (&ds, server, module, NULL);
	path = Ns_DStringExport (&ds);
    } elseif (! Ns_PathIsAbsolute (path)) {
	Ns_DStringVarAppend (&ds, path, value, NULL);
	path = Ns_DStringExport (&ds);
    }

    Ns_Log (Notice, "Module directory defaults to %s", path);

    /*
     * Attempt to create the directory if it doesn't already exist
     */

    if (mkdir (path, 0755) != 0 && errno != EEXIST) {
        Ns_Log (Error, "mkdir(%s) failed: %s", path, strerror (errno));
    }

    Ns_DStringFree (&ds);

    return path;
}


/*
 *----------------------------------------------------------------------
 *
 * ConfigGetStringDefault --
 *
 *       Get the config value requested, or return the default
 *       specified.
 *
 * Results:
 *       Config value as a string.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static char *
ConfigGetStringDefault (char *path, char *name, char *def)
{
    char *value = Ns_ConfigGetValue (path, name);

    if (value == NULL) {
	value = def;
    }

    Ns_Log (Notice, "%s: %s = %s", MODULE_NAME, name, value ? value : "(null)");

    return value;
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigBoolDefault --
 *
 *       Get the config value requested, or return the default
 *       specified.
 *
 * Results:
 *       Config value as a boolean.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
ConfigGetBoolDefault (char *path, char *name, int def)
{
    int value;

    if (Ns_ConfigGetBool (path, name, &value) == NS_FALSE) {
	value = def;
    }

    Ns_Log (Notice, "%s: %s = %d", MODULE_NAME, name, value);

    return value;
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigIntDefault --
 *
 *       Get the config value requested, or return the default
 *       specified.
 *
  Results:
 *       Config value as an int.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
ConfigGetIntDefault (char *path, char *name, int def)
{
    int value;

    if (Ns_ConfigGetInt (path, name, &value) == NS_FALSE) {
	value = def;
    }

    Ns_Log (Notice, "%s: %s = %d", MODULE_NAME, name, value);

    return value;
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigPath --
 *
 *       Get the config value requested, or return the default
 *       specified.  If the value is not an absolute path, make
 *       it one (relative to the specified directory).
 *
 * Results:
 *       Config value as a string. The default can be NULL.
 *
 * Side effects:
 *       Caller is responsible for freeing the returned value (unlike
 *       ConfigStringDefault).
 *
 *----------------------------------------------------------------------
 */

static char *
ConfigGetPathValueRequired (char *path, char *name, char *dir)
{
	return ConfigGetPath (path, name, dir, NULL, 1);
}

static char *
ConfigGetPathValue (char *path, char *name, char *dir)
{
	return ConfigGetPath (path, name, dir, NULL, 0);
}


static char *
ConfigGetPathValueDefault (char *path, char *name, char *dir, char *def)
{
	return ConfigGetPath (path, name, dir, def, 0);
}

static char *
ConfigGetPath (char *path, char *name, char *dir, char *def, int required)
{
    char *value = NULL;
    Ns_DString ds;

    value = Ns_ConfigGetValue (path, name);

    /*
     * Fail if a config value is required but is not set
     */

    if (value == NULL && required) {
	    Ns_Fatal("%s: Required parameter %s in section %s is not set",
			    MODULE_NAME, name, path);
	    return NULL;
    }

    /*
     * If there is no path value defined in config nor a default path value
     * passed in, then we return NULL
     */
    
    if (value == NULL && def == NULL)
	    return NULL;

    value = def;

    if (Ns_PathIsAbsolute (value)) {
	value = ns_strdup (value);
    } else {
	Ns_DStringInit (&ds);
	Ns_MakePath (&ds, dir, value, NULL);
	Ns_DStringVarAppend (&ds, dir, value, NULL);
	value = Ns_DStringExport (&ds);
	Ns_DStringFree (&ds);
    }

    Ns_Log (Notice, "%s: %s = %s", MODULE_NAME, name, value);

    return value;
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

    sprintf (module, "-%s-", MODULE_NAME);
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
	Ns_Log (Notice, MODULE_NAME ":  exiting: triggering shutdown");
	if (send (trigPipe[1], "", 1, 0) != 1) {
	    Ns_Fatal ("trigger send() failed: %s",
		      ns_sockstrerror (ns_sockerrno));
	}
	Ns_ThreadJoin (&sockThread, NULL);
	sockThread = NULL;
	Ns_Log (Notice, MODULE_NAME ":  exiting: shutdown complete");
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
 *	MODULE_NAME.
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

    return MODULE_NAME;
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
    Ns_Log(Debug, "%s: SockInit: enter", MODULE_NAME);
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
    Ns_Log(Debug, "%s: SockInit: leave", MODULE_NAME);
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

