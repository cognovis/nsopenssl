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

/*
 * OpenSSL library initialization
 */
 
static int InitOpenSSL (void);
static int SeedPRNG (void);
static Ns_Mutex *locks;
static void LockCallback (int mode, int n, const char *file, int line);
static unsigned long IdCallback (Ns_OpenSSLContext *contextid);
static struct CRYPTO_dynlock_value *DynlockCreateCallback (char *file,
		int line);
static void DynlockLockCallback (int mode,
		struct CRYPTO_dynlock_value *dynlock,
		const char *file, int line);
static void DynlockDestroyCallback (struct CRYPTO_dynlock_value *dynlock,
		const char *file, int line);
		
/*
 * Get information from the config file
 */
 
static int ConfigGetSSLContexts (char *server, char *module);
static Ns_OpenSSLContext *ConfigGetSSLContext (char *server, char *module, 
	char *name, char *desc, char *type);
	
/*
 * Initialize SSL Contexts
 */

static int InitSSLContexts ();
static int SetProtocols (Ns_OpenSSLContext *context);
static int SetCipherSuite (Ns_OpenSSLContext *context);
static int LoadCertificate (char *module, SSL_CTX *context, char *certFile);
static int LoadKey (char *module, SSL_CTX *context, char *keyFile);
static int CheckKey (char *module, SSL_CTX *context);
static int LoadCACerts (char *module, SSL_CTX *context, char *caFile, char *caDir);
static int InitLocation (NsOpenSSLDriver *driver);
static int PeerVerifyCallback (int preverify_ok, X509_STORE_CTX *x509_ctx);
static char *GetModuleDir (char *server, char *module);
static int SessionCacheIdGetNext (void);

/*
 * Driver initialization/destruction
 */
 
static NsOpenSSLDriver *NsOpenSSLDriverCreate (char *server, char *module);
static void NsOpenSSLDriverFree (NsOpenSSLDriver *driver);

/*
 * SSL Operations on active connections
 */
 
static Ns_DriverProc OpenSSLProc;
static RSA *IssueTmpRSAKey (SSL *ssl, int export, int keylen);	

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
    static int globalInit = 0;

    /*
     * Some things are initialized once and affect all virtual servers, so we
     * initialize these global things once the first time the module
     * initialization routine is run.
     */

    if (!globalInit) {

        /*
         * Initialize the OpenSSL library
         */

        if (InitOpenSSL () == NS_ERROR) {
	        Ns_Log(Error, MODULE, ": OpenSSL failed to initialize");
	        return NS_ERROR;
        }

        /*
         * Create the nsopenssl Tcl API
         */
    
        if (Ns_TclInitInterps (server, NsOpenSSLCreateCmds, NULL) != NS_OK) {
	        return NS_ERROR;
        }
    }
    globalInit = 1;
   
    /*
     * Load and initialize this virtual server's pre-defined SSL context
     * structures as defined in nsd.tcl
     */
     
    if (ConfigGetSSLContexts(server, module) == NS_ERROR) {
	    Ns_Log(Error, MODULE, ": Failed to load the SSL Contexts");
	    return NS_ERROR;
    }

    if (InitSSLContexts(server, module) == NS_ERROR) {
	    Ns_Log(Error, MODULE, ": Failed to initialize the SSL Contexts");
	    return NS_ERROR;
    }

    /*
     * Create the actual driver
     */

    /* XXX how do we set up to listen on multiple ports within the same virtual server? */

    if ((driver = NsOpenSSLDriverCreate (server, module)) == NULL) {
	    return NS_ERROR;
    }

    /*
     * Maintain the drivers in a single linked-list. You can find out what
     * server a particular driver serves by looking at driver->server.
     */
    
    driver->next = firstSSLDriver;
    firstSSLDriver = driver;

    /*
     * Register the driver with AOLserver.
     */

    if (Ns_DriverInit (server, module, MODULE, OpenSSLProc, driver, NS_DRIVER_SSL)
		    != NS_OK) {
	    Ns_Log(Error, MODULE, ": driver for server %s failed to initialize",
		    server);
            return NS_ERROR;
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDriverCreate --
 *
 *       Create an SSL driver. There will be one driver for each virtual
 *       server/port comibination.
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
NsOpenSSLDriverCreate (char *server, char *module)
{
    NsOpenSSLDriver *driver = NULL;

    driver = (NsOpenSSLDriver *) ns_calloc (1, sizeof *driver);

    if (driver == NULL) {
	    Ns_Log(Error, "%s: Failed to create driver structure", module);
	    return NULL;
    }

    /* XXX need to initialize some items? */

    driver->server     = server;
    driver->module     = module;
    driver->configPath = Ns_ConfigGetPath(server, module, NULL);

    Ns_MutexSetName(&driver->lock, module);

    if (SetModuleDir (driver) == NS_ERROR || InitLocation (driver) == NS_ERROR) {
	NsOpenSSLDriverFree (driver);
	return NULL;
    }

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
    Ns_OpenSSLConn *conn;

    if (driver == NULL)
	    return;

    Ns_Log (Debug, "%s: freeing(%p)",
	    driver == NULL ? MODULE : driver->module, driver);

    /* 
     * Free all of the conn structures associated with this driver, if any.
     */

    while ((conn = driver->firstFreeConn) != NULL) {
	    driver->firstFreeConn = conn->next;
	    /* XXX doesn't this need to have it's contents free'd? */
	    Ns_Free (conn);
    }

    Ns_MutexDestroy (&driver->lock);
    
    if (driver->context != NULL) {
	    Ns_OpenSSLContextFree(driver->context);
	    driver->context = NULL;
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

    Ns_Free (driver);

    return;
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

    Ns_Log (Debug, "%s: NsOpenSSLSockConnect -- enter", MODULE);

    if (timeout < 0) {
	sock = Ns_SockConnect (host, port);
    } else {
	sock = Ns_SockTimedConnect (host, port, timeout);
    }

    if (sock == INVALID_SOCKET) {
	return NULL;
    }

    if ((conn = NsOpenSSLCreateConn(sock, firstSSLDriver, 
             ROLE_SSL_CLIENT, CONNTYPE_SSL_SOCK)) == NULL) {
	return NULL;
    }

    /*
     * We leave the socket blocking until after the handshake.
     */

    if (async)
	Ns_SockSetNonBlocking (conn->sock);

    SSL_set_app_data (conn->ssl, conn);

    Ns_Log (Debug, "%s: NsOpenSSLSockConnect -- leave", MODULE);

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
    if ((conn = NsOpenSSLCreateConn(sock, firstSSLDriver, 
	ROLE_SSL_SERVER, CONNTYPE_SSL_SOCK)) == NULL) {
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
    return MODULE;
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
	    Ns_Log (Warning, MODULE
		    ": could not set OpenSSL memory callbacks to use AOLserver memory allocation");
	}

	num_locks = CRYPTO_num_locks ();
	locks = Ns_Calloc (num_locks, sizeof *locks);
	for (i = 0; i < num_locks; i++) {
	    sprintf (buf, "openssl-%d", i);
	    Ns_MutexSetName2 (locks + i, MODULE, buf);
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
	    Ns_Log (Notice, MODULE, ": Seeding OpenSSL's PRNG");
	    SeedPRNG ();
    }

    if (! RAND_status ()) {
	    Ns_Log (Warning, MODULE, 
			    ": OpenSSL PRNG fails to have enough entropy after %d tries", 
			    seedcnt);
    } else {
	    Ns_Log (Notice, MODULE, ": OpenSSL's PRNG is seeded properly"); 
    }

    /*
     * Initialize the session cache id number generator.
     */

    nextSessionCacheId = (SessionCacheId *) ns_calloc (1, sizeof *nextSessionCacheId);

    if (nextSessionCacheId == NULL) {
	    Ns_Log (Error, MODULE,
			    ": Failed to allocate memory for session id generator");
	    return NS_ERROR;
    }

    Ns_MutexLock(&nextSessionCacheId->lock);
    Ns_MutexSetName2(&nextSessionCacheId->lock, MODULE, "sessioncacheid");
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

    Ns_MutexSetName2 (lock, MODULE, Ns_DStringValue (&ds));

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

static int
SeedPRNG (void)
{
    int i;
    double *buf_ptr = NULL;
    double *bufoffset_ptr = NULL;
    size_t size;
    int seedBytes;
    int readBytes;

    if (RAND_status ()) 
	return NS_TRUE;

    Ns_Log (Notice, MODULE, ": Seeding OpenSSL's PRNG");

    if (Ns_ConfigGetInt(path, "seedBytes", &seedBytes) == NS_FALSE) {
	    seedBytes = DEFAULT_SEEDBYTES;
    }

    /*
     * Try to use the file specified by the user.
     */

    if (randomFile != NULL && access (randomFile, F_OK) == 0) {
	if ((readBytes = RAND_load_file (randomFile, maxbytes))) {
	    Ns_Log (Notice, MODULE, ": Obtained %d random bytes from %s",
		    readBytes, randomFile);
	} else {
	    Ns_Log (Warning, MODULE, ": Unable to retrieve any random data from %s",
		    randomFile);
	}
    }

    if (RAND_status ()) 
	return NS_TRUE;

    Ns_Log (Notice, MODULE, ": Seeding PRNG from file failed; let's try Ns_DRand()");

    /*
     * Use Ns_DRand(); I have no idea how to measure the amount of entropy, so for
     * now I just pass seedBytes as the 2nd arg to RAND_add. Not all of the
     * buffer is used. It's on my list of research topics.
     */

    size          = sizeof (double) * seedBytes;
    buf_ptr       = Ns_Malloc (size);
    bufoffset_ptr = buf_ptr;

    for (i = 0; i < seedBytes; i++) {
       *bufoffset_ptr = Ns_DRand ();
	bufoffset_ptr++;
    }

    RAND_add (buf_ptr, seedBytes, (long) seedBytes);
    Ns_Free (buf_ptr);

    if (RAND_status ()) {
        Ns_Log (Notice, MODULE, ": Successfully seeded PRNG with %d bytes from Ns_DRand",
	    seedBytes);
    } else {
        Ns_Log (Warning, MODULE, ": Failed to seed PRNG with Ns_DRand");
        return NS_FALSE;
    }

    return NS_TRUE;
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
		MODULE);
	return NULL;
    }
}


/*
 *----------------------------------------------------------------------
 *
 * ConfigGetSSLContexts --
 *
 *      Load SSL Contexts that are defined in the configuration file
 *      for a given virtual server.
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
ConfigGetSSLContexts(char *server, char *module)
{
	Ns_Set *contexts;
	Ns_Set *sockclients;
	char *key = NULL;
	int i = 0;

	/*
	 * Each virtual server can have multiple named SSL contexts. Each
	 * context defines the characteristics for SSL connections that use the
	 * context.
	 */

	contexts = Ns_ConfigGetSection(
			Ns_ConfigGetPath(server, module, "contexts", NULL));

	if (contexts != NULL) {
	    for (i = 0; i < Ns_SetSize(contexts); ++i) {
		/*
		 * The "key" is the name of the context. The value is the text
		 * description of that named "context"
		 */
		key = Ns_SetKey(contexts, i);
		ConfigGetSSLContext(server, module, key, 
				Ns_SetGet(contexts, key), "server");
	    }
	} else {
	    Ns_Log (Notice, MODULE, ": No SSL contexts defined for server %s", server);
	}

	return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * ConfigGetSSLContexts --
 *
 *      Load SSL Contexts that are defined in the configuration file
 *      for a given virtual server.
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
BLOWConfigGetSSLContexts(char *server, char *module)
{
	Ns_Set *drivers;
	Ns_Set *sockservers;
	Ns_Set *sockclients;
	char *key = NULL;
	int i = 0;

	/*
	 * Load server contexts. Each virtual server can have multiple named "drivers". Each
	 * "driver" defines a port to listen on and an SSL context to use. We loop through
	 * the list of defined "drivers" and load each of the SSL contexts individually.
	 */

	servers = Ns_ConfigGetSection(
			Ns_ConfigGetPath(server, module, "drivers", NULL));

	if (servers != NULL) {
	    for (i = 0; i < Ns_SetSize(servers); ++i) {
		/*
		 * The key is the named "server". The value is the text
		 * description of that named "server"
		 */
		key = Ns_SetKey(servers, i);
		ConfigGetSSLContext(server, module, key, 
				Ns_SetGet(servers, key), "server");
	    }
	} else {
	    Ns_Log (Notice, MODULE, ": No SSL servers defined for server %s", server);
	    Ns_Log (Notice, MODULE, ": This server will not be able to accept incoming HTTPS requests");
	}

	/*
	 * Load sockserver contexts
	 */

	sockservers = Ns_ConfigGetSection(
			Ns_ConfigGetPath(server, module, "sockservers", NULL));

	if (servers != NULL) {
	    for (i = 0; i < Ns_SetSize(sockservers); ++i) {
		key = Ns_SetKey(sockservers, i);
		ConfigGetSSLContext(server, module, sockservers, key, 
				Ns_SetGet(sockservers, key), "sockserver");
	    }
	} else {
	    Ns_Log (Notice, MODULE, ": No SSL sockservers defined for server %s", server);
	    Ns_Log (Notice, MODULE, ": Tcl sockserver API will not be available for this server");
	}

	/*
	 * Load sockclient contexts
	 */

	sockclients = Ns_ConfigGetSection(
			Ns_ConfigGetPath(server, module, "sockclients", NULL));

	if (sockclients != NULL) {
	    for (i = 0; i < Ns_SetSize(sockclients); ++i) {
		key = Ns_SetKey(sockclients, i);
		ConfigGetSSLContext(server, module, sockclients, key, 
				Ns_SetGet(sockclients, key), "sockclient");
	    }
	} else {
	    Ns_Log (Notice, MODULE, ": No SSL sockclients defined for server %s", server);
	    Ns_Log (Notice, MODULE, ": Tcl sockclient API will not be available for this server");
	}

	return NS_OK;
}



/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextModuleDirGet --
 *
 *       Get the module directory for a particular SSL context
 *
 * Results:
 *       String pointer; might be NULL
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

char *
Ns_OpenSSLContextModuleDirGet(server, module, context) {
    return context->moduledir;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextModuleDirSet --
 *
 *       Set the module directory for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextModuleDirSet(server, module, context, moduleDir)
{
    /* XXX lock struct */
    /* XXX validate that directory exists and is readable */
    context->moduledir = moduleDir;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCertFileSet --
 *
 *       Set the certificate pathname for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextCertFileSet(server, module, context, certFile)
{
    /* XXX lock struct */
    /* XXX validate file exists and is readable */
    context->certfile = certFile;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCertFileGet --
 *
 *       Get the certificate pathname for a particular SSL context
 *
 * Results:
 *       String pointer; might be NULL
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

char *
Ns_OpenSSLContextCertFileGet(server, module, context) {
    return context->certFile;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextKeyFileSet --
 *
 *       Set the key pathname for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextKeyFileSet(server, module, context, keyFile)
{
    /* XXX lock struct */
    /* XXX validate key file exists and is readable */
    context->keyFile = keyFile;
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextKeyFileGet --
 *
 *       Get the key pathname for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

char *
Ns_OpenSSLContextKeyFileGet(server, module, context) {
    return context->keyFile;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextProtocolsSet --
 *
 *       Set the protocols for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextProtocolSet(server, module, context, protocols)
{
    /* XXX validate protocols? */
    context->protocols = protocols;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextProtocolsGet --
 *
 *       Get the protocols for a particular SSL context
 *
 * Results:
 *       ????
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

char *
Ns_OpenSSLContextProtocolGet(server, module, context, protocols)
{
    return context->protocols;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCAFileSet --
 *
 *       Set the CA file for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextCAFileSet(server, module, context, CAFile)
{
    /* XXX validate file exists and is readable */
    /* XXX lock struct */
    context->CAFile = CAFile;

    return NS_OK;

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCAFileGet --
 *
 *       Get the CA file for a particular SSL context
 *
 * Results:
 *       String pointer; might be NULL
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

char *
Ns_OpenSSLContextCAFileGet(server, module, context)
{
    return context->CAFile;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCADirSet --
 *
 *       Set the CA directory for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextCADirSet(server, module, context, CADir)
{
    /* XXX validate dir exists and is readable */
    /* XXX lock struct */
    context->CADir = CADir;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCADirGet --
 *
 *       Get the CA directory for a particular SSL context
 *
 * Results:
 *       String pointer, might be NULL
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

char *
Ns_OpenSSLContextCADirGet(server, module, context)
{
    return context->CADir;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextPeerVerifySet --
 *
 *       Set whether peer verify is on or off for a particular SSL
 *       context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextPeerVerifySet(server, module, context, peerVerify)
{
    /* XXX lock struct */
    /* XXX handle default case where peerVerify is NULL */
    context->peerVerify = peerVerify;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextPeerVerifyGet --
 *
 *       Get whether peer verify is on or off for a particular SSL
 *       context
 *
 * Results:
 *       NS_TRUE or NS_FALSE
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextPeerVerifyGet(server, module, context)
{
    return context->peerVerify;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextPeerVerifyDepthSet --
 *
 *       Set the depth that a peer certificate can be chained for
 *       validation purposes for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextPeerVerifyDepthSet(server, module, context, peerVerifyDepth)
{
    /* XXX lock struct */
    /* XXX how do I handle the default case? with varargs in func call? */
    /* XXX ah, no, preset all the default values in Ns_OpenSSLContextCreate */
    context->peerVerifyDepth = peerVerifyDepth;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextPeerVerifyDepthGet --
 *
 *       Get the depth that a peer certificate can be chained for
 *       validation purposes for a particular SSL context
 *
 * Results:
 *       Integer
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextPeerVerifyDepthGet(server, module, context)
{
    return context->peerVerifyDepth;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextSessionCacheSet --
 *
 *       Set whether session caching is on or off for a particular SSL
 *       context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextSessionCacheSet(server, module, context, sessionCache)
{
    /* XXX lock struct */
    context->sessionCache = sessionCache;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextSessionCacheGet --
 *
 *       Get whether session caching is on or off for a particular SSL
 *       context
 *
 * Results:
 *       NS_TRUE or NS_FALSE
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

/* XXX should I be managing these function calls by passing the name */
/* XXX of the context rather than a pointer to the context itself? */
int
Ns_OpenSSLContextSessionCacheGet(server, module, context)
{
    return context->sessionCache;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextSessionCacheSizeSet --
 *
 *       Set the size of a session cache for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextSessionCacheSizeSet(server, module, context, sessionCacheSize)
{
    /* XXX lock struct */
    context->sessionCacheSize = sessionCacheSize;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextSessionCacheSizeGet --
 *
 *       Get the size of a session cache for a particular SSL context
 *
 * Results:
 *       Integer
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

/* XXX should session cache size be limited to size int? */
int
Ns_OpenSSLContextSessionCacheSizeSet(server, module, context, sessionCacheSize)
{
    return context->sessionCacheSize;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextSessionCacheTimeoutSet --
 *
 *       Set the timeout for cache entries for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextSessionCacheSizeSet(server, module, context, sessionCacheSize)
{
    /* XXX lock struct */
    context->sessionCacheSize = sessionCacheSize;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextSessionCacheTimeoutGet --
 *
 *       Get the timeout for cache entries for a particular SSL context
 *
 * Results:
 *       Integer
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextSessionCacheTimeoutSet(server, module, context, sessionCacheTimeout)
{
    /* XXX lock struct */
    context->sessionCacheTimeout = sessionCacheTimeout;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextTraceSet --
 *
 *       Set SSL handshake tracing for a particular SSL context
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextTraceSet(server, module, context, trace)
{
    /* XXX lock struct */
    context->trace = trace;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextTraceGet --
 *
 *       Get SSL handshake tracing for a particular SSL context
 *
 * Results:
 *       NS_TRUE or NS_FALSE
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextSessionCacheSizeSet(server, module, context, sessionCacheSize)
{
    return context->trace;
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
 *       Memory is allocated. All structure values are set to defaults.
 *       These defaults can be overridden by calls to the
 *       Ns_OpenSSLContext* functions.
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLContext *
Ns_OpenSSLContextCreate (char *server, char *module, char *name, char *desc, char *role)
{
    Ns_OpenSSLContext *context = NULL;
    Ns_DString ds;

    /*
     * The name of an SSL context must be unique within a virtual server.
     */

#if 0
    /* XXX turn this on */
    if (SSLContextNameCheck (server, module, name)) {
	    Ns_Log(Error, "%s: SSL context with name %s already defined",
			    MODULE, name);
	    return NULL;
    }
#endif

    /*
     * Set the connection type: "server" is driven by the core nsd HTTP
     * process; sockservers and sockclients are driven by the nsopenssl C and
     * Tcl APIs.
     */

    if (STREQ(role, "server")) {
        context->role = SERVER_ROLE;
    } else if (STREQ(role, "client")) {
        context->role = CLIENT_ROLE;
    } else {
        Ns_Log(Error, MODULE, ": SSL context %s has an invalid role", name);
	/* XXX need to ditch here: use goto? */
    }

    Ns_Log(Debug, MODULE, ": %s: %s: %s: %s", type, name, desc, role);

    /*
     * Allocate memory to hold the context.
     */

    context = (Ns_OpenSSLContext *) ns_calloc (1, sizeof *context);

    if (context == NULL) {
        Ns_Log(Error, MODULE, ": Failed to create SSL context named %s", name);
        return NULL;
    }

    /*
     * Lock around the structure while changing it
     */

    Ns_MutexLock(&context->lock);

    /* XXX make mutex name unique to this struct instance */
    Ns_MutexSetName2(&context->lock, MODULE, "context");

    context->server = server;
    context->module = module;
    context->name   = strdup(key);
    context->desc   = strdup(desc);

    /*
     * Set sane default for module directory
     */

    Ns_DStringInit (&ds);
    Ns_HomePath (&ds, "servers", server, "modules", module, NULL);
    context->moduleDir = Ns_DStringExport (&ds);
    Ns_DStringFree (&ds);
   
    /* XXX set default cert file and key file paths */
    /* XXX should validate here -- set to null if non-existent? */
    /* XXX should do a check in InitSSLContext to ensure a key/cert is available */

    context->certFile            = NULL; /* XXX DEFAULT_CERTFILE??? */
    context->keyFile             = NULL; /* XXX DEFAULT_KEYFILE??? */
    context->CAFile              = NULL; /* XXX DEFAULT_CAFILE??? */
    context->CADir               = NULL; /* XXX DEFAULT_CADIR??? */
    context->CRLFile             = NULL; /* XXX not supported yet */
    context->CRLDir              = NULL; /* XXX not supported yet */
    context->peerVerify          = DEFAULT_PEER_VERIFY;
    context->peerVerifyDepth     = DEFAULT_PEER_VERIFY_DEPTH;
    context->peerAbortOnInvalid  = 0;    /* XXX not supported yet */
    context->peerAbortProc       = NULL; /* XXX not supported yet */
    context->protocols           = DEFAULT_PROTOCOLS;
    context->cipherSuite         = SSL_DEFAULT_CIPHER_LIST;
    context->sessionCache        = DEFAULT_SESSION_CACHE;
    context->sessionCacheSize    = DEFAULT_SESSION_CACHE_SIZE;
    context->sessionCacheTimeout = DEFAULT_SESSION_CACHE_TIMEOUT;
    context->sessionCacheId      = NsSessionIdGenerate(); /* Always gets an id */
    context->trace               = DEFAULT_TRACE;

    /*
     * Insert the context into the linked list. Instead of wasting time looking
     * for the end of the list, we'll insert it at the front.
     */

    /* XXX lock firstSSLContext before modifying. SSL Contexts can be created at any time */
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
 * ConfigGetSSLContext --
 *
 *       Load values for a given SSL context from the configuration file.
 *
 * Results:
 *       Pointer to SSL Context or NULL
 *
 * Side effects:
 *       Memory may be allocated
 *
 *----------------------------------------------------------------------
 */

static Ns_OpenSSLContext *
ConfigGetSSLContext (char *server, char *module, char *name, char *desc)
{
    Ns_OpenSSLContext *context = NULL;
    char *path = NULL;
    char *role = NULL;
    char *moduleDir = NULL;
    char *certFile = NULL;
    char *keyFile = NULL;
    char *protocols = NULL;
    char *cipherSuite = NULL;
    char *caFile = NULL;
    char *caDir = NULL;
    int   peerVerify;
    int   peerVerifyDepth;
    int   sessionCache;
    int   sessionCacheSize;
    int   sessionCacheTimeout;
    int   trace;
    Ns_DString ds;
    /* XXX need to check all of the above vars and delete those not used */

    path = Ns_ConfigGetPath(server, module, name, NULL);

    /*
     * An SSL instance must be defined as either "server" or "client"
     */

    role = Ns_ConfigGetValue(path, "role");

    context = Ns_OpenSSLContextCreate(server, module, name, desc, role);

    if (context == NULL) {
        Ns_Log(Error, MODULE, ": SSL context came back NULL in ConfigGetSSLContext");
	    return NULL;
    }

    /*
     * A default module directory is already set in the context, but you can
     * override in the config file.
     */

    moduleDir = Ns_ConfigGetValue(path, "moduledir");
    if (moduleDir != NULL)
        Ns_OpenSSLContextModuleDirSet(server, module, context, moduleDir);

    /*
     * SSL clients don't require certificates, but SSL servers do. If certfile
     * or keyfile are NULL, are not found, are not accessible, we'll fail
     * later when we try to instantiate the SSL Context. Probably ought to do
     * the checks here and fail here.
     */

    /* XXX need to prepend path if not absolute */
    /* XXX use AOLserver core Ns_Path* functions */
    /* XXX can i determine a reasonable default ??? */
    /* XXX this setting is MANDATORY */
    certFile = Ns_ConfigGetValue(path, "certfile");
    Ns_OpenSSLContextCertFileSet(server, module, context, certFile);

    /* XXX need to prepend path if not absolute */
    /* XXX use AOLserver core Ns_Path* functions */
    /* XXX can i determine a reasonable default ??? */
    /* XXX this setting is MANDATORY */
    keyFile  = Ns_ConfigGetValue(path, "keyfile");
    Ns_OpenSSLContextKeyFileSet(server, module, context, keyFile);

    /*
     * The default protocols and ciphersuites are good for general use.
     */

    protocols = Ns_ConfigGetValue(path, "protocols");
    if (protocols != NULL)
        Ns_OpenSSLContextProtocolsSet(server, module, context, protocols);

    cipherSuite = Ns_ConfigGetValue(path, "ciphersuite");
    if (cipherSuite != NULL)
        Ns_OpenSSLContextCipherSuiteSet(server, module, context, cipherSuite);

    /*
     * The CA file/dir isn't necessary unless you actually use cert
     * verification. The CA file is simply a bunch of PEM-format CA
     * certificates concatenated together.
     */

    /* XXX need to make sure default moduledir is set before this */
    /* XXX because we'll need to build the absolute path if caDir is relative */
    /* XXX need to perform checks somewhere to ensure a caFile/caDir are set */
    /* XXX if peerverify is set; if ca* isn't set, all cert checks will be invalid */
    caFile = Ns_ConfigGetValue(path, "cafile");
    if (caFile != NULL)
        Ns_OpenSSLContextCAFileSet(server, module, context, caFile);

    /* XXX need to make sure default moduledir is set before this */
    /* XXX because we'll need to build the absolute path if caDir is relative */
    caDir = Ns_ConfigGetValue(path, "cadir");
    if (caDir != NULL)
        Ns_OpenSSLContextCADirSet(server, module, context, caDir);

    /*
     * Peer verification will cause the server to request a client certificate.
     * It defaults to being off. Only turn it on if you want to verify client
     * certificates.
     */

    if (Ns_ConfigGetBool(path, "peerverify", &peerVerify) == NS_TRUE)
        Ns_OpenSSLContextPeerVerifySet(server, module, context, peerVerify);

    /*
     * A certificate may be at the bottom of a chain. The verify depth
     * determines how many levels from the root cert you're willing to allow.
     */

    if (Ns_ConfigGetInt(path, "peerverifydepth", &peerVerifyDepth) == NS_TRUE)
        Ns_OpenSSLContextPeerVerifyDepthSet(server, module, context, peerVerifyDepth);

    /*
     * Session caching defaults to on, and should always be on if you
     * have web browsers connecting. Some versions of MSIE and Netscape will
     * fail if you don't have session caching on. You can turn it off if you're
     * doing your own special aolserver-to-aolserver connections.
     */

    if (Ns_ConfigGetBool(path, "sessioncache", &sessionCache) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheSet(server, module, context, sessionCache);

    if (Ns_ConfigGetInt(path, "sessioncachesize", &sessionsCacheSize) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheSizeSet(server, module, context, sessionCacheSize);

    if (Ns_ConfigGetInt(path, "sessioncachetimeout", sessionCacheTimeout) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheTimeoutSet(server, module, context, sessionCacheTimeout);

    if (Ns_ConfigGetBool(path, "trace", &trace) == NS_TRUE)
        Ns_OpenSSLContextTraceSet(server, module, context, trace);

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
	Ns_Log (Error, "%s: error creating SSL context", MODULE);
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

    cipherSuite = Ns_ConfigGetValue (path, "ciphersuite");
    if (cipherSuite == NULL)
        cipherSuite = DEFAULT_SERVER_CIPHERSUITE;

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
		MODULE);
	bits = 1;
    } else {
	    protocols = ns_strdup (context->protocols);
	    protocols = Ns_StrToLower (protocols);

	    if (strstr (protocols, "all") != NULL) {
		    bits = 1;
		    Ns_Log (Notice, "%s: using all protocols: SSLv2, SSLv3 and TLSv1",
				    MODULE);
	    } else {
		    if (strstr (protocols, "sslv2") != NULL) {
			    bits &= ~SSL_OP_NO_SSLv2;
			    Ns_Log (Notice, "%s: Using SSLv2 protocol", MODULE);
		    }
		    if (strstr (protocols, "sslv3") != NULL) {
			    bits &= ~SSL_OP_NO_SSLv3;
			    Ns_Log (Notice, "%s: Using SSLv3 protocol", MODULE);
		    }
		    if (strstr (protocols, "tlsv1") != NULL) {
			    bits &= ~SSL_OP_NO_TLSv1;
			    Ns_Log (Notice, "%s: Using TLSv1 protocol", MODULE);
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

    driver->bindaddr = ConfigGetStringDefault (driver->module, driver->configPath,
					   "ServerAddress", NULL);

    hostname = ConfigGetStringDefault (driver->module, driver->configPath,
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

    /* XXX - handle multiple ports */
    driver->port = ConfigGetIntDefault (driver->module, driver->configPath,
				    "ServerPort", DEFAULT_PORT);

    driver->location = ConfigGetStringDefault (driver->module, driver->configPath,
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
    } else if (! Ns_PathIsAbsolute (path)) {
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

    Ns_Log (Notice, "%s: %s = %s", MODULE, name, value ? value : "(null)");

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
 *       ConfigGetStringDefault).
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
			    MODULE, name, path);
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

    Ns_Log (Notice, "%s: %s = %s", MODULE, name, value);

    return value;
}


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
OpenSSLProc (Ns_DriverCmd cmd, Ns_Sock *sock, struct iovec *bufs, int nbufs)
{
    Ns_Driver *driver = sock->driver;
    Ns_OpenSSLConn *conn;
    int n, total;

    switch (cmd) {
    case DriverRecv:
    case DriverSend:

	/*          
	 * On first I/O, initialize the connection context.
	 */

	if (sock->arg == NULL) {
	    n = driver->recvwait;
	    if (n > driver->sendwait) {
		n = driver->sendwait;
	    }
	    sock->arg = NsOpenSSLCreateConn(sock->sock, n, driver->arg);
	    if (sock->arg == NULL) {
		return -1;
	    }
        }

#if 0 /* XXX */
	conn = sock->arg;
	if (conn == NULL) {
	    conn = ns_calloc (1, sizeof (*conn));

	    if (conn == NULL) {
	       Ns_Log(Error, MODULE, ":unable to allocate memory");
	       return NS_ERROR;
	    }
	    
	    conn->driver   = driver->arg;
	    conn->conntype = CONNTYPE_SERVER;
	    conn->refcnt   = 0;	/* always 0 for nsdserver conns */
	    conn->sock     = sock->sock;
	    sock->arg      = conn;

	    if (NsOpenSSLCreateConn ((Ns_OpenSSLConn *) conn) != NS_OK) {
		return NS_ERROR;
	    }
	}
#endif


	/*
	 * Process each buffer one at a time.
	 */

	total = 0;
	do {
	    if (cmd == DriverSend) {
		n = NsOpenSSLSend (sock->arg, bufs->iov_base, bufs->iov_len);
	    } else {
		n = NsOpenSSLRecv (sock->arg, bufs->iov_base, bufs->iov_len);
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
	if (sock->arg != NULL && NsOpenSSLFlush(sock->arg) == NS_OK) {
	    n = 0;
	} else {
	    n = -1;
	}
	break;

    case DriverClose:
	if (sock->arg != NULL) {
	    (void) NsOpenSSLFlush (sock->arg);
	    NsOpenSSLDestroyConn (sock->arg);
	    sock->arg = NULL;
	}
	n = 0;
	break;

    default:
	Ns_Log(Error, MODULE, ": Unsupported driver command encountered");
	n = -1;
	break;
    }
    return n;
}
