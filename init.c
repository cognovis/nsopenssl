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

#include "nsopenssl.h"


static int InitOpenSSL (void);
static int SeedPRNG (void);
static Ns_Mutex *locks;
static void ThreadLockCallback (int mode, int n, const char *file, int line);
static unsigned long ThreadIdCallback (void);
static struct CRYPTO_dynlock_value *ThreadDynlockCreateCallback (char *file,
        int line);
static void ThreadDynlockLockCallback (int mode,
        struct CRYPTO_dynlock_value *dynlock, const char *file, int line);
static void ThreadDynlockDestroyCallback (struct CRYPTO_dynlock_value *dynlock,
        const char *file, int line);
static Ns_Callback ServerShutdown;
static Ns_OpenSSLContext *LoadSSLContext(char *server, char *module, char *name);
static int OpenSSLDriverInit(char *server, char *module, NsOpenSSLDriver *ssldriver);
static void OpenSSLDriverDestroy(NsOpenSSLDriver *ssldriver);

/* XXX put into NsOpenSSLVirtualServerTable */
static NsOpenSSLDriver    *firstNsOpenSSLDriver;

static Ns_DriverProc OpenSSLProc;

/* XXX These are global definitions here */

Tcl_HashTable NsOpenSSLServers;
NsOpenSSLSessionCacheId *nextSessionCacheId;


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLModuleInit --
 *
 *     nsopenssl module initialization.
 *
 * Results:
 *     NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLModuleInit (char *server, char *module)
{
    Ns_OpenSSLContext *sslcontext = NULL;
    NsOpenSSLDriver *ssldriver;
    Ns_Set *ssldrivers, *sslcontexts;
    Tcl_HashEntry *hPtr;
    Server *thisServer;
    char *name, *path, *sslcontextname;
    int i, new;
    static int globalInit = 0;

    /* Initialize one-time global stuff */

    if (!globalInit) {
        if (InitOpenSSL() == NS_ERROR) {
            Ns_Log(Error, "%s: OpenSSL failed to initialize", MODULE);
            return NS_ERROR;
        }
        Tcl_InitHashTable(&NsOpenSSLServers, TCL_STRING_KEYS);
        globalInit = 1;
    }
 
    /* Initialize this virtual server's hash table */
   
    thisServer = ns_malloc(sizeof(Server));
    thisServer->server = server;
    Ns_MutexInit(&thisServer->lock);
    hPtr = Tcl_CreateHashEntry(&NsOpenSSLServers, server, &new);
    Tcl_SetHashValue(hPtr, thisServer);
    Tcl_InitHashTable(&thisServer->sslcontexts, TCL_STRING_KEYS);
    Tcl_InitHashTable(&thisServer->ssldrivers, TCL_STRING_KEYS);

    /* Create the Tcl commands for this virtual server's interps */

    if (Ns_TclInitInterps (server, NsOpenSSLCreateCmds, NULL) != NS_OK)
	    return NS_ERROR;

    /* 
     * Load the virtual server's SSL contexts from the configuration file 
     */

    path = Ns_ConfigGetPath(server, module, "sslcontexts", NULL);
    sslcontexts = Ns_ConfigGetSection(path);

    /* It's ok if no SSL contexts are defined, but no drivers will be started */

    if (sslcontexts == NULL) {
        Ns_Log (Notice, "%s: %s: no SSL contexts defined for this server", 
                server, MODULE);
        return NS_OK;
    } 

    for (i = 0; i < Ns_SetSize(sslcontexts); ++i) {
        name = Ns_SetKey(sslcontexts, i);
        Ns_Log(Notice, "%s: %s: loading SSL context '%s'", server, MODULE,
                name);
        sslcontext = LoadSSLContext(server, module, name);
        if (sslcontext == NULL) {
            continue;
        }

        hPtr = Tcl_CreateHashEntry(&thisServer->sslcontexts, name, &new);
        if (!new) {
            Ns_Log(Error, "%s: %s: duplicate SSL context name: %s",
                    server, MODULE, name);
            Ns_OpenSSLContextDestroy(server, module, sslcontext);
        } else {
            Tcl_SetHashValue(hPtr, sslcontext);
        }

        if (Ns_OpenSSLContextInit(server, module, sslcontext) == NS_ERROR) {
            Ns_Log(Error, "%s: %s: SSL context '%s' left uninitialized",
                    server, MODULE, sslcontext->name);
        }
    }

    /*
     * Load and start the driver(s) for this virtual server.  A driver manages
     * one SSL port; for a virtual server to use more than one port, you must
     * define a driver for each port.  A driver must be associated with a named
     * SSL context.
     */

    path = Ns_ConfigGetPath(server, module, "ssldrivers", NULL);
    ssldrivers = Ns_ConfigGetSection(path);

    if (ssldrivers == NULL) {
        Ns_Log (Notice, "%s: %s: no SSL drivers defined for this server", 
                server, MODULE);
        return NS_OK;
    }

    for (i = 0; i < Ns_SetSize(ssldrivers); ++i) {
        name = Ns_SetKey(ssldrivers, i);
        Ns_Log(Notice, "%s: %s: loading '%s' SSL driver", server, MODULE, name);
        path = Ns_ConfigGetPath(server, module, "ssldriver", name, NULL);
        if (path == NULL) {
            Ns_Log(Error, "%s: %s: SSL driver '%s' not defined in configuration file",
                    server, MODULE, name);
            continue;
        }
        sslcontextname = Ns_ConfigGetValue(path, "sslcontext");
        if (sslcontextname == NULL) {
            Ns_Log(Error, "%s: %s: 'sslcontext' parameter not defined for driver '%s'",
                    server, MODULE, name);
            continue;
        }

        Ns_MutexLock(&thisServer->lock);
        hPtr = Tcl_FindHashEntry(&thisServer->sslcontexts, name);
        if (hPtr != NULL) {
            sslcontext = (Ns_OpenSSLContext *) Tcl_GetHashValue(hPtr);
        }
        Ns_MutexUnlock(&thisServer->lock);

        if (hPtr == NULL) {
            Ns_Log(Error, "%s: %s: SSL context '%s' needed by driver '%s' not found",
                    server, MODULE, sslcontextname, name);
            continue;
        }

        hPtr = Tcl_CreateHashEntry(&thisServer->ssldrivers, name, &new);
        if (!new) {
            Ns_Log(Error, "%s: %s: duplicate SSL driver: %s", server, MODULE, name);
            continue;
        } else {
            ssldriver = ns_calloc(1, sizeof(NsOpenSSLDriver));
            ssldriver->server = server;
            ssldriver->module = module;
            ssldriver->sslcontext = sslcontext;
            ssldriver->name = name;
            ssldriver->path = path;
            ssldriver->refcnt = 0;
            Tcl_SetHashValue(hPtr, ssldriver);
        }

        if (OpenSSLDriverInit(server, module, ssldriver) != NS_OK) {
            Ns_Log(Error, "%s: %s: initialization of '%s' driver failed",
                    server, MODULE, name);
        }
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * OpenSSLDriverInit --
 *
 *       Initialize an SSL driver.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Registers driver with AOLserver core.
 *
 *----------------------------------------------------------------------
 */

static int
OpenSSLDriverInit(char *server, char *module, NsOpenSSLDriver *ssldriver)
{
    Ns_DriverInitData init;

    /* Set up for call to AOLserver API that will initialize driver */

    init.version = NS_DRIVER_VERSION_1;
    init.name = MODULE;
    init.proc = OpenSSLProc;
    init.opts = NS_DRIVER_SSL;
    init.arg = ssldriver;
    init.path = ssldriver->path;

    if (Ns_DriverInit(server, module, &init) == NS_ERROR) {
        Ns_Log(Error, "%s: %s: driver '%s' failed to initialize",
                server, MODULE, ssldriver->name);
        return NS_ERROR;
    }

    /* XXX FIX to be in the per-server hash */
    if (firstNsOpenSSLDriver != NULL) {
            /* There are already other drivers */
            ssldriver->next = firstNsOpenSSLDriver;
            firstNsOpenSSLDriver = ssldriver;
    } else {
            /* We're the first driver created */
            ssldriver->next = NULL;
            firstNsOpenSSLDriver = ssldriver;
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * OpenSSLDriverDestroy --
 *
 *      Destroy an SSL driver.
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
OpenSSLDriverDestroy(NsOpenSSLDriver *ssldriver)
{
    Ns_OpenSSLConn *sslconn;

    Ns_Log(Notice, "%s: %s: shutting down driver '%s'", MODULE, 
            ssldriver->server, ssldriver->name);

    if (ssldriver == NULL)
        return;

    /*
     * Remove driver from driver linked list.
     */



    /*
     * Destroy connections that are still tied to this driver.
     */

    /* XXX need to lock around refcnt and firstFreeConn here */
    /* XXX race condition if new conn comes in while we're doing this part ??? */
    if (ssldriver->refcnt > 0) {
        while ((sslconn = ssldriver->firstFreeConn) != NULL) {
            ssldriver->firstFreeConn = sslconn->next;
            /* XXX doesn't this need to have it's contents free'd? */
            Ns_Free (sslconn);
        }
    }

    Ns_MutexDestroy (&ssldriver->lock);

    /* XXX should an SSL context be deallocated when it's refcnt reaches 0 ??? */
    if (ssldriver->sslcontext != NULL) 
        ssldriver->sslcontext->refcnt--;
  
    Ns_Free (ssldriver);

    return;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerShutdown --
 *
 *      Runs at server shutdown time to free all data.
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
ServerShutdown(void *arg)
{
#if 0
    for each vserver
        for each vserver.driver
            for each vserver.driver.conn
                close, free
            endfor
            free vserver.driver
        endfor
        free vserver
    endfor
#endif
}


/*
 *----------------------------------------------------------------------
 *
 * LoadSSLContext --
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
LoadSSLContext(char *server, char *module, char *name)
{
    Ns_OpenSSLContext *sslcontext;
    char *path;
    char *tmp;
    char *role;
    char *moduleDir;
    char *certFile;
    char *keyFile;
    char *protocols;
    char *cipherSuite;
    char *caFile;
    char *caDir;
    int   peerVerify;
    int   peerVerifyDepth;
    int   sessionCache;
    int   sessionCacheSize;
    int   sessionCacheTimeout;
    int   trace;

    path = Ns_ConfigGetPath(server, module, "sslcontext", name, NULL);
    if (path == NULL) {
        Ns_Log(Error, "%s: %s: failed to find SSL context '%s' in nsd.tcl",
                server, MODULE, name);
        return NULL;
    }

    role = Ns_ConfigGetValue(path, "role");
    if (role == NULL) {
        Ns_Log(Error, "%s: %s: role parameter is not defined for SSL context '%s'",
                server, MODULE, name);
        return NULL;
    }

    sslcontext = Ns_OpenSSLContextCreate(server, module);
    if (sslcontext == NULL) {
        Ns_Log(Error, "%s: %s: SSL context came back NULL in ConfigSSLContextLoad",
                server, MODULE);
        return NULL;
    }
    sslcontext->name = ns_strdup(name);

    sslcontext->role = role;
   
    /*
     * A default module directory is automatically set when the SSL context was
     * created, but you can override in the config file.
     */

    moduleDir = Ns_ConfigGetValue(path, "moduledir");
    if (moduleDir != NULL)
        Ns_OpenSSLContextModuleDirSet(server, module, sslcontext, moduleDir);

    /*
     * SSL clients don't require certificates, but SSL servers do. If certfile
     * or keyfile are NULL, are not found, or are not accessible, we'll fail
     * later when we try to instantiate the SSL context.
     */

    certFile = Ns_ConfigGetValue(path, "certfile");
    if (certFile != NULL) 
        Ns_OpenSSLContextCertFileSet(server, module, sslcontext, certFile);
    Ns_Log(Debug, "*** CERTFILE: %s", certFile);

    keyFile = Ns_ConfigGetValue(path, "keyfile");
    if (keyFile != NULL) 
        Ns_OpenSSLContextKeyFileSet(server, module, sslcontext, keyFile);

    /*
     * The default protocols and ciphersuites are good for general use.
     */

    protocols = Ns_ConfigGetValue(path, "protocols");
    if (protocols != NULL)
        Ns_OpenSSLContextProtocolsSet(server, module, sslcontext, protocols);

    cipherSuite = Ns_ConfigGetValue(path, "ciphersuite");
    if (cipherSuite != NULL)
        Ns_OpenSSLContextCipherSuiteSet(server, module, sslcontext, cipherSuite);

    /*
     * The CA file/dir isn't necessary unless you actually do cert
     * verification. The CA file is simply a bunch of PEM-format CA
     * certificates concatenated together.
     */

    caFile = Ns_ConfigGetValue(path, "cafile");
    if (caFile != NULL)
        Ns_OpenSSLContextCAFileSet(server, module, sslcontext, caFile);

    caDir = Ns_ConfigGetValue(path, "cadir");
    if (caDir != NULL)
        Ns_OpenSSLContextCADirSet(server, module, sslcontext, caDir);

    /*
     * Peer verification will cause the server to request a client certificate.
     * It defaults to being off. If you aren't sure whether to turn it on or
     * not, leave it off!
     */

    if (Ns_ConfigGetBool(path, "peerverify", &peerVerify) == NS_TRUE)
        Ns_OpenSSLContextPeerVerifySet(server, module, sslcontext, peerVerify);

    /*
     * A certificate may be at the bottom of a chain. Verify depth determines
     * how many levels down from the root cert you're willing to trust..
     */

    if (Ns_ConfigGetInt(path, "peerverifydepth", &peerVerifyDepth) == NS_TRUE)
        Ns_OpenSSLContextPeerVerifyDepthSet(server, module, sslcontext, peerVerifyDepth);

    /*
     * Session caching defaults to on, and should always be on if you
     * have web browsers connecting. Some versions of MSIE and Netscape will
     * fail if you don't have session caching on.
     */

    if (Ns_ConfigGetBool(path, "sessioncache", &sessionCache) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheSet(server, module, sslcontext, sessionCache);

    if (Ns_ConfigGetInt(path, "sessioncachesize", &sessionCacheSize) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheSizeSet(server, module, sslcontext, sessionCacheSize);

    if (Ns_ConfigGetInt(path, "sessioncachetimeout", &sessionCacheTimeout) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheTimeoutSet(server, module, sslcontext, sessionCacheTimeout);

    if (Ns_ConfigGetBool(path, "trace", &trace) == NS_TRUE) {
        Ns_OpenSSLContextTraceSet(server, module, sslcontext, 1);
    } else {
        Ns_OpenSSLContextTraceSet(server, module, sslcontext, 0);
    }

    return sslcontext;
}


/*
 *----------------------------------------------------------------------
 *
 * InitOpenSSL --
 *
 *       Initialize the OpenSSL library.
 *
 * Results:
 *       NS_OK
 *
 * Side effects:
 *       Sets OpenSSL threading callbacks, seeds the pseudo random number
 *       generator, initializes SSL session caching id generation.
 *
 *----------------------------------------------------------------------
 */

static int
InitOpenSSL (void)
{
    int i, seedcnt = 0;
    size_t num_locks;
    char buf[100];

    /*
     * Initialize OpenSSL callbacks
     */

    if (CRYPTO_set_mem_functions (Ns_Malloc, Ns_Realloc, Ns_Free) == 0)
        Ns_Log (Warning, "%s: OpenSSL memory callbacks failed in InitOpenSSL",
                MODULE);

    num_locks = CRYPTO_num_locks ();
    locks = Ns_Calloc (num_locks, sizeof(*locks));
    for (i = 0; i < num_locks; i++) {
        sprintf (buf, "openssl-%d", i);
        Ns_MutexSetName2 (locks + i, MODULE, buf);
    }

    CRYPTO_set_locking_callback (ThreadLockCallback);
    CRYPTO_set_id_callback (ThreadIdCallback);

    /*
     * Initialize the OpenSSL library itself
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
	    Ns_Log (Notice, "%s: Seeding OpenSSL's PRNG", MODULE);
	    SeedPRNG ();
    }

    if (! RAND_status ()) {
        Ns_Log (Warning, "%s: PRNG fails to have enough entropy after %d tries", 
                MODULE, seedcnt);
    }

    /*
     * Initialize the session cache id number generator.
     */

    nextSessionCacheId = ns_calloc (1, sizeof(NsOpenSSLSessionCacheId));
    Ns_MutexLock(&nextSessionCacheId->lock);
    Ns_MutexSetName2(&nextSessionCacheId->lock, MODULE, "nsopensslsessioncacheid");
    nextSessionCacheId->id = 1;
    Ns_MutexUnlock(&nextSessionCacheId->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SeedPRNG --
 *
 *       Seed OpenSSL's PRNG. OpenSSL will seed the PRNG transparently if
 *       /dev/urandom is available.
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
    char *path, *randomFile;
    size_t size;
    int seedBytes, readBytes, maxBytes;

    if (RAND_status ()) 
	return NS_TRUE;

    Ns_Log (Notice, "%s: Seeding OpenSSL's PRNG", MODULE);

    path = Ns_ConfigGetPath(MODULE, NULL);

    if (Ns_ConfigGetInt(path, "seedbytes", &seedBytes) == NS_FALSE) 
	    seedBytes = DEFAULT_SEEDBYTES;

    if (Ns_ConfigGetInt(path, "maxbytes", &maxBytes) == NS_FALSE) 
	    maxBytes = DEFAULT_MAXBYTES;

    randomFile = Ns_ConfigGetValue(path, "randomfile");

    /*
     * Try to use the file specified by the user. If PRNG fails to seed here,
     * you might try increasing the seedBytes parameter in nsd.tcl.
     */

    if (randomFile != NULL && access (randomFile, F_OK) == 0) {
    	if ((readBytes = RAND_load_file (randomFile, maxBytes))) {
	        Ns_Log (Notice, "%s: Obtained %d random bytes from %s",
		        MODULE, readBytes, randomFile);
	    } else {
	        Ns_Log (Warning, "%s: Unable to retrieve any random data from %s",
		        MODULE, randomFile);
	    }
    } else {
        Ns_Log(Warning, "%s: No randomFile set and/or found", MODULE);
    }

    if (RAND_status ()) 
	    return NS_TRUE;

    Ns_Log (Notice, "%s: PRNG seeding from file failed; let's try Ns_DRand()",
            MODULE);

    /*
     * Use Ns_DRand(); I have no idea how to measure the amount of entropy, so for
     * now I just pass seedBytes as the 2nd arg to RAND_add. Not all of the
     * buffer is used. It's on my list of research topics.
     */

    size          = sizeof(double) * seedBytes;
    buf_ptr       = Ns_Malloc (size);
    bufoffset_ptr = buf_ptr;

    for (i = 0; i < seedBytes; i++) {
       *bufoffset_ptr = Ns_DRand ();
	bufoffset_ptr++;
    }

    RAND_add (buf_ptr, seedBytes, (double) seedBytes);
    Ns_Free (buf_ptr);

    if (RAND_status ()) {
        Ns_Log (Notice, "%s: PRNG successfully seeded with %d bytes from Ns_DRand",
	    MODULE, seedBytes);
    } else {
        Ns_Log (Warning, "%s: PRNG failed to be seeded with Ns_DRand", MODULE);
        return NS_FALSE;
    }

    return NS_TRUE;
}


/*
 *----------------------------------------------------------------------
 *
 * ThreadLockCallback --
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
ThreadLockCallback (int mode, int n, const char *file, int line)
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
 * ThreadIdCallback --
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
ThreadIdCallback (void)
{
    return (unsigned long) Ns_ThreadId ();
}


/*
 *----------------------------------------------------------------------
 *
 * ThreadDynlockCreateCallback --
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
ThreadDynlockCreateCallback (char *file, int line)
{
    Ns_Mutex *lock;
    Ns_DString ds;

    lock = ns_calloc (1, sizeof(*lock));
    Ns_DStringInit (&ds);
    Ns_DStringVarAppend (&ds, "openssl: ", file, ": ");
    Ns_DStringPrintf (&ds, "%d", line);
    Ns_MutexSetName2 (lock, MODULE, Ns_DStringValue (&ds));

    return (struct CRYPTO_dynlock_value *) lock;
}


/*
 *----------------------------------------------------------------------
 *
 * ThreadDynlockLockCallback --
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
ThreadDynlockLockCallback (int mode, struct CRYPTO_dynlock_value *dynlock,
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
 * ThreadDynlockDestroyCallback --
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
ThreadDynlockDestroyCallback (struct CRYPTO_dynlock_value *dynlock,
			const char *file, int line)
{
    Ns_MutexDestroy ((Ns_Mutex *) dynlock);
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
    Ns_Driver *driver = (Ns_Driver *) sock->driver;
    NsOpenSSLDriver *ssldriver;
    Ns_OpenSSLContext *sslcontext;
    int n, total;

    ssldriver = (NsOpenSSLDriver *) driver->arg;
    sslcontext = (Ns_OpenSSLContext *) ssldriver->sslcontext;

    switch (cmd) {
    case DriverRecv:
    case DriverSend:

	/* On first I/O, initialize the connection context */

	if (sock->arg == NULL) {
            Ns_Log(Debug, "%s: NEW CONN", MODULE);
	    n = driver->recvwait;
	    if (n > driver->sendwait) 
    		n = driver->sendwait;

            /* XXX WARNING: ssldriver->driver is NULL until the first connection */
            ssldriver->driver = driver;

#if 0
	    sock->arg = NsOpenSSLCreateConn(sock->sock, n, driver->arg);
#endif
	    sock->arg = NsOpenSSLConnCreate(sock->sock, ssldriver, sslcontext);
	    if (sock->arg == NULL) {
                Ns_Log(Notice, "*** sock->arg is null");
    		return -1;
	    }
    }

#if 0 /* XXX */
	sslconn = sock->arg;
	if (sslconn == NULL) {
	    sslconn = ns_calloc (1, sizeof (*sslconn));
	    sslconn->driver   = driver->arg;
	    sslconn->conntype = CONNTYPE_SERVER;
	    sslconn->refcnt   = 0;	/* always 0 for nsdserver conns */
	    sslconn->sock     = sock->sock;
	    sock->arg      = sslconn;

	    if (NsOpenSSLCreateConn ((Ns_OpenSSLConn *) sslconn) != NS_OK) {
		return NS_ERROR;
	    }
	}
#endif

	/* Process each buffer one at a time */

	total = 0;
	do {
	    if (cmd == DriverSend) {
		n = NsOpenSSLSend (sock->arg, bufs->iov_base, (int) bufs->iov_len);
	    } else {
		n = NsOpenSSLRecv (sock->arg, bufs->iov_base, (int) bufs->iov_len);
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
	        NsOpenSSLConnDestroy (sock->arg);
	        sock->arg = NULL;
	    }
	    n = 0;
	    break;

    default:
    	Ns_Log(Error, "%s: Unsupported driver command encountered", MODULE);
	    n = -1;
	    break;
    }
    return n;
}

