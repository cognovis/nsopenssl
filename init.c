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
 * init.c --
 *
 *       nsopenssl initialization.
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

/*
 * OpenSSL threading callbacks
 */

static void ThreadLockCallback (int mode, int n, const char *file, int line);
static unsigned long ThreadIdCallback (void);
static struct CRYPTO_dynlock_value *ThreadDynlockCreateCallback (char *file,
		int line);
static void ThreadDynlockLockCallback (int mode,
		struct CRYPTO_dynlock_value *dynlock,
		const char *file, int line);
static void ThreadDynlockDestroyCallback (struct CRYPTO_dynlock_value *dynlock,
		const char *file, int line);
		
/*
 * Get information from the config file
 */
 
static void ConfigSSLContextLoad (char *server, char *module, char *name);


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
 *     Calls Ns_RegisterLocation as specified by this instance
 *     in the config file.
 *
 *----------------------------------------------------------------------
 */

extern int
NsOpenSSLModuleInit (char *server, char *module)
{
    NsOpenSSLDriver *driver;
    static int globalInit = 0;
    Ns_Set *drivers;
    Ns_Set *contexts;
    int i = 0;

    /*
     * Things to initialize first time this module is loaded
     */

    if (!globalInit) {
        if (InitOpenSSL() == NS_ERROR) {
            Ns_Log(Error, "%s: OpenSSL failed to initialize", MODULE);
            return NS_ERROR;
        }
        globalInit = 1;
    }
 
   /*
    * Each virtual server can define multiple, named SSL contexts. Each
    * context defines the characteristics for connections that use the
    * context.
    */

    contexts = Ns_ConfigGetSection(Ns_ConfigGetPath(server, module, "contexts", NULL));
    if (contexts != NULL) {
        for (i = 0; i < Ns_SetSize(contexts); ++i) {
            Ns_Log(Notice, "%s: %s: Loading SSL context '%s'", MODULE, server, 
                    Ns_SetKey(contexts, i));
	    ConfigSSLContextLoad(server, module, Ns_SetKey(contexts, i));
        }
    } else {
        Ns_Log (Notice, "%s: No SSL contexts defined for server %s", MODULE, server);
    }

    /*
     * Start up the driver(s) for this virtual server.  Each driver is tied to
     * a specific, named SSL context.  A driver manages one SSL port; to get
     * multiple SSL ports in one virtual server, you define a driver for each
     * port in the virtual server's config area.
     */

    drivers = Ns_ConfigGetSection(Ns_ConfigGetPath(server, module, "drivers", NULL));
    if (drivers != NULL) {
        for (i = 0; i < Ns_SetSize(drivers); ++i) {
            if (NsOpenSSLDriverInit(server, module, Ns_SetKey(drivers, i)) != NS_OK) {
                Ns_Log(Error, "%s: %s: driver initialization failed",
                        MODULE, server);
            }
        }
    } else {
        Ns_Log (Notice, "%s: %s: No SSL drivers defined", MODULE, server);
    }
              
#if 0
    /* XXX test: destroy all drivers immediately */
    NsOpenSSLDriversDestroy();
#endif

#if 0
    /* XXX loop through defined drivers and initialize them */
    if drivers exist
        foreach driver:
            NsOpenSSLDriverCreate;
            NsOpenSSLDriverInit;
            if error
                NsOpenSSLDriverDestroy;

    if ((driver = NsOpenSSLDriverCreate (server, module)) == NULL)
        return NS_ERROR;
#endif

    /*
     * Create the Tcl commands for this virtual server's interps
     */

    if (Ns_TclInitInterps (server, NsOpenSSLCreateCmds, NULL) != NS_OK)
	    return NS_ERROR;

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigSSLContextLoad --
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

static void
ConfigSSLContextLoad (char *server, char *module, char *name)
{
    Ns_OpenSSLContext *context = NULL;
    char *path         = NULL;
    char *role         = NULL;
    char *moduleDir    = NULL;
    char *certFile     = NULL;
    char *keyFile      = NULL;
    char *protocols    = NULL;
    char *cipherSuite  = NULL;
    char *caFile       = NULL;
    char *caDir        = NULL;
    int   peerVerify;
    int   peerVerifyDepth;
    int   sessionCache;
    int   sessionCacheSize;
    int   sessionCacheTimeout;
    int   trace;

    path = Ns_ConfigGetPath(server, module, "context", name, NULL);
    if (path == NULL) {
        Ns_Log(Error, "%s: %s: Failed to find SSL context '%s' in nsd.tcl",
                MODULE, server, name);
        return;
    }

    role = Ns_ConfigGetValue(path, "role");
    if (role == NULL) {
        Ns_Log(Error, "%s: %s: role parameter is not defined for SSL context '%s'",
                MODULE, server, name);
        return;
    }

    context = Ns_OpenSSLContextCreate(server, module);
    if (context == NULL) {
        Ns_Log(Error, "%s: %s: SSL context came back NULL in ConfigSSLContextLoad",
                MODULE, server);
	    return;
    }

    if (STREQ(role, "server")) {
        context->role = ROLE_SERVER;
    } else if (STREQ(role, "client")) {
        context->role = ROLE_CLIENT;
    } else {
        Ns_Log(Error, "%s: %s: role parameter must be 'client' or 'server' for SSL context '%s'",
                MODULE, server, name);
        Ns_OpenSSLContextDestroy(context);
        return;
    }
   
    context->name = name;

    /*
     * A default module directory is automatically set when the SSL context was
     * created, but you can override in the config file.
     */

    moduleDir = Ns_ConfigGetValue(path, "moduledir");
    if (moduleDir != NULL)
        Ns_OpenSSLContextModuleDirSet(server, module, context, moduleDir);

    /*
     * SSL clients don't require certificates, but SSL servers do. If certfile
     * or keyfile are NULL, are not found, or are not accessible, we'll fail
     * later when we try to instantiate the SSL context.
     */

    certFile = Ns_ConfigGetValue(path, "certfile");
    Ns_OpenSSLContextCertFileSet(server, module, context, certFile);

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
     * The CA file/dir isn't necessary unless you actually do cert
     * verification. The CA file is simply a bunch of PEM-format CA
     * certificates concatenated together.
     */

    caFile = Ns_ConfigGetValue(path, "cafile");
    if (caFile != NULL)
        Ns_OpenSSLContextCAFileSet(server, module, context, caFile);

    caDir = Ns_ConfigGetValue(path, "cadir");
    if (caDir != NULL)
        Ns_OpenSSLContextCADirSet(server, module, context, caDir);

    /*
     * Peer verification will cause the server to request a client certificate.
     * It defaults to being off. If you aren't sure whether to turn it on or
     * not, leave it off!
     */

    if (Ns_ConfigGetBool(path, "peerverify", &peerVerify) == NS_TRUE)
        Ns_OpenSSLContextPeerVerifySet(server, module, context, peerVerify);

    /*
     * A certificate may be at the bottom of a chain. Verify depth determines
     * how many levels down from the root cert you're willing to allow.
     */

    if (Ns_ConfigGetInt(path, "peerverifydepth", &peerVerifyDepth) == NS_TRUE)
        Ns_OpenSSLContextPeerVerifyDepthSet(server, module, context, peerVerifyDepth);

    /*
     * Session caching defaults to on, and should always be on if you
     * have web browsers connecting. Some versions of MSIE and Netscape will
     * fail if you don't have session caching on. Only turn off session caching
     * if you know what you're doing.
     */

    if (Ns_ConfigGetBool(path, "sessioncache", &sessionCache) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheSet(server, module, context, sessionCache);

    if (Ns_ConfigGetInt(path, "sessioncachesize", &sessionCacheSize) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheSizeSet(server, module, context, sessionCacheSize);

    if (Ns_ConfigGetInt(path, "sessioncachetimeout", &sessionCacheTimeout) == NS_TRUE)
        Ns_OpenSSLContextSessionCacheTimeoutSet(server, module, context, sessionCacheTimeout);

    if (Ns_ConfigGetBool(path, "trace", &trace) == NS_TRUE)
        Ns_OpenSSLContextTraceSet(server, module, context, trace);

    return;
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

    if (NsOpenSSLSessionCacheInit() == NS_ERROR) { 
        Ns_Log (Error, "%s: Failed to allocate memory for session id generator",
                MODULE);
        /* XXX need to turn off session caching here if this failed, but */
        /* XXX let the server continue to run */
        return NS_ERROR;
    }

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
     * Try to use the file specified by the user.
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
