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
     * Create any drivers defined for this virtual server. A driver manages one
     * SSL port; to get multiple SSL ports in one virtual server, you define
     * multiple drivers for each port in the virtual server's config area.
     */

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

    return NS_OK;
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
