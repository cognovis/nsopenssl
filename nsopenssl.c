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
 *
 * Module originally written by Stefan Arentz. Early contributions made by
 * Freddie Mendoze and Rob Mayoff.
 *
 */

/*
 * nsopenssl.c --
 *
 *    Implements SSLv2, SSLv3 and TLSv1 module using OpenSSL.
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include "nsopenssl.h"

/*
 * Globals defined in this file
 */

extern Tcl_HashTable
NsOpenSSLServers;

extern void
NsOpenSSLDriversLoad(char *server);

/*
 * Local functions defined in this file.
 */

static int
InitOpenSSL(void);

static void
InitServerState(char *server);

static int
SeedPRNG(void);

static Ns_Mutex
*locks;

static void
ThreadLockCallback(int mode, int n, const char *file, int line);

static unsigned long
ThreadIdCallback(void);

static struct
CRYPTO_dynlock_value *ThreadDynlockCreateCallback(char *file, int line);

static void 
ThreadDynlockLockCallback(int mode, struct CRYPTO_dynlock_value *dynlock, const char *file, int line);

static void
ThreadDynlockDestroyCallback(struct CRYPTO_dynlock_value *dynlock, const char *file, int line);

static void
ServerShutdown(void *arg);

static void 
LoadSSLContexts(char *server);

static NsOpenSSLContext *
LoadSSLContext(char *server, char *name);

static int
InitSSLDriver(char *server, NsOpenSSLDriver *ssldriver);

static void
LoadSSLDrivers(char *server);

#if 0
static void
OpenSSLDriverDestroy(NsOpenSSLDriver *ssldriver);
#endif

static Ns_DriverProc
OpenSSLProc;

NS_EXPORT int 
Ns_ModuleVersion = 1;


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
 *
 *----------------------------------------------------------------------
 */

extern int
Ns_ModuleInit(char *server, char *module)
{
    static int globalInit = 0;

    /* 
     * Initialize one-time global stuff.
     */

    if (!globalInit) {
        if (!STREQ(module, MODULE)) {
            Ns_Log(Fatal, "Module '%s' should be named '%s'", module, MODULE);
        }
        if (InitOpenSSL() == NS_ERROR) {
            Ns_Log(Error, "%s: OpenSSL failed to initialize", MODULE);
            return NS_ERROR;
        }
        Tcl_InitHashTable(&NsOpenSSLServers, TCL_STRING_KEYS);
        globalInit = 1;
    }

    /* 
     * Initialize this virtual server's state information 
     */

    InitServerState(server);

    /* 
     * Load this virtual server's SSL contexts from the configuration file.
     */

    LoadSSLContexts(server);

    /*
     * Load and start the driver(s) for this virtual server.  A driver manages
     * one SSL port; for a virtual server to use more than one port, you must
     * define a driver for each port.  A driver must be associated with a named
     * SSL context.
     */

    LoadSSLDrivers(server);

    /* 
     * Create the nsopenssl Tcl commands for this virtual server's interps.
     */

    NsOpenSSLTclInit(server);

    /*
     * Register a cleanup function to run at server shutdown time.
     */

    Ns_RegisterAtShutdown(ServerShutdown, (void *) server);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDebug --
 *
 *    Write message to log file. When not in debug mode, no logging is done,
 *    function just returns.
 *
 *----------------------------------------------------------------------
 */

#if 0
extern void
NsOpenSSLDebug(char *fmt, ...)
{
    va_list ap;
    Ns_LogSeverity severity = "Debug";
    char buf[1000];

    //va_start(ap, fmt);
    sprintf(&buf, fmt, ap);
    Ns_Log(severity, &buf);
    //va_end(ap);

}
#endif



/*
 *----------------------------------------------------------------------
 *
 * InitServerState --
 *
 *     Initialize a virtual server's state storage. This holds pointers to SSL
 *     contexts stored by name, as well as default client and server SSL
 *     contexts to use in cases where the programmer didn't explicitly name one
 *     to use.
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
InitServerState(char *server)
{
    Server        *thisServer = NULL;
    Tcl_HashEntry *hPtr       = NULL;
    int            new        = 0;
    Ns_DString     ds;
    char          *lockName   = NULL;

    Ns_DStringInit(&ds);
    thisServer = ns_malloc(sizeof(Server));
    if (thisServer == NULL) {
	Ns_Log(Fatal, "%s (%s): memory allocation failed");
    }
    thisServer->server = server;
    thisServer->defaultservercontext = NULL;
    thisServer->defaultclientcontext = NULL;
    thisServer->nextSessionCacheId = 1;
    Ns_MutexInit(&thisServer->lock);
    Ns_DStringPrintf(&ds, "server:%s", server);
    lockName = Ns_DStringExport(&ds);
    Ns_MutexSetName2(&thisServer->lock, MODULE_SHORT, lockName);
    Ns_DStringTrunc(&ds, 0);
    ns_free(lockName);
    lockName = NULL;
    hPtr = Tcl_CreateHashEntry(&NsOpenSSLServers, server, &new);
    Tcl_SetHashValue(hPtr, thisServer);
    Tcl_InitHashTable(&thisServer->sslcontexts, TCL_STRING_KEYS);
    Tcl_InitHashTable(&thisServer->ssldrivers, TCL_STRING_KEYS);

    return;
}


/*
 *----------------------------------------------------------------------
 *
 * LoadSSLContexts --
 *
 *       Load the SSL context for a virtual server.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Registers driver with AOLserver core.
 *
 *----------------------------------------------------------------------
 */

static void
LoadSSLContexts(char *server)
{
    Server           *thisServer  = NsOpenSSLServerGet(server);
    NsOpenSSLContext *sslcontext  = NULL;
    Ns_Set           *sslcontexts = NULL;
    Ns_Set           *defaults    = NULL;
    char             *path        = NULL;
    char             *name        = NULL;
    char             *value       = NULL;
    int               i           = 0;

    path = Ns_ConfigGetPath(server, MODULE, "sslcontexts", NULL);
    sslcontexts = Ns_ConfigGetSection(path);

    /* 
     * If no SSL contexts are defined for this virtual server, we won't start
     * any drivers for it, and we won't be able to use SSL at all. I'll soon be
     * adding the capability to build SSL contexts with the Tcl API dynamically
     * so it will make sense to do this at some point in the future if you want
     * to manage SSL conns but not through the AOLserver comm API.
     */

    if (sslcontexts == NULL) {
        Ns_Log(Notice, "%s (%s): no SSL contexts defined for this server", 
                server, MODULE);
        return;
    }
    for (i = 0; i < Ns_SetSize(sslcontexts); ++i) {
        name = Ns_SetKey(sslcontexts, i);
        Ns_Log(Notice, "%s (%s): loading SSL context '%s'", MODULE, server, name);
        sslcontext = LoadSSLContext(server, name);
        NsOpenSSLContextAdd(server, sslcontext);
        if (NsOpenSSLContextInit(server, sslcontext) == NS_ERROR) {
            Ns_Log(Error, "%s (%s): SSL context '%s' left uninitialized",
                    MODULE, server, name);
        }
    }

    /*
     * Set default server SSL client and server contexts. These are used in
     * cases where the C or Tcl programmer does not specify what named SSL
     * context to use.
     */

    path = Ns_ConfigGetPath(server, MODULE, "defaults", NULL);
    defaults = Ns_ConfigGetSection(path);
    if (defaults == NULL) {
        Ns_Log(Notice, "%s (%s): no default SSL contexts defined for this server", 
                MODULE, server);
        return;
    }
    for (i = 0; i < Ns_SetSize(defaults); ++i) {
        name = Ns_SetKey(defaults, i);
        value = Ns_ConfigGetValue(path, name);
        sslcontext = Ns_OpenSSLServerSSLContextGet(server, value);
        if (sslcontext != NULL) {
            Ns_Log(Notice, "%s (%s): default SSL context for %s is %s", MODULE, server, name, value);
            if (STRIEQ(name, "server")) {
                thisServer->defaultservercontext = value;
                Ns_Log(Notice, "default server SSL context: %s", thisServer->defaultservercontext);
            } else if (STRIEQ(name, "client")) {
                thisServer->defaultclientcontext = value;
                Ns_Log(Notice, "default client SSL context: %s", thisServer->defaultclientcontext);
            } else {
                Ns_Log(Error, "%s (%s): bad parameter '%s' for default contexts",
                        MODULE, server, name);
            }
        } else {
            Ns_Log(Error, "%s (%s): SSL context '%s' doesn't exist; can't use it as a default",
                    MODULE, server, value);
        }
    }
}


/*
 *----------------------------------------------------------------------
 *
 * LoadSSLContext --
 *
 *     Load values for a given SSL context from the configuration file.
 *
 * Results:
 *     Pointer to SSL Context or NULL
 *
 * Side effects:
 *     Memory may be allocated
 *
 *----------------------------------------------------------------------
 */

static NsOpenSSLContext *
LoadSSLContext(char *server, char *name)
{
    NsOpenSSLContext *sslcontext           = NULL;
    char             *role                 = NULL;
    char             *path                 = NULL;
    char             *moduleDir            = NULL;
    char             *certFile             = NULL;
    char             *keyFile              = NULL;
    char             *caFile               = NULL;
    char             *caDir                = NULL;
    char             *protocols            = NULL;
    char             *cipherSuite          = NULL;
    int               sessionCache         = DEFAULT_SESSION_CACHE;
    int               sessionCacheSize     = DEFAULT_SESSION_CACHE_SIZE;
    int               sessionCacheTimeout  = DEFAULT_SESSION_CACHE_TIMEOUT;
    int               peerVerify           = DEFAULT_PEER_VERIFY;
    int               peerVerifyDepth      = DEFAULT_PEER_VERIFY_DEPTH;
    int               trace                = DEFAULT_TRACE;

    path = Ns_ConfigGetPath(server, MODULE, "sslcontext", name, NULL);
    if (path == NULL) {
        Ns_Log(Error, "%s (%s): failed to find SSL context '%s' in configuration file",
                MODULE, server, name);
        return NULL;
    }
    sslcontext = NsOpenSSLContextCreate(server, name);

    /*
     * Must be "client" or "server"
     */

    role = Ns_ConfigGetValue(path, "role");
    if (role != NULL) {
        NsOpenSSLContextRoleSet(server, sslcontext, role);
    }

    /*
     * A default module directory is automatically set when the SSL context was
     * created, but you can override in the config file.
     */

    moduleDir = Ns_ConfigGetValue(path, "moduledir");
    if (moduleDir != NULL) {
        NsOpenSSLContextModuleDirSet(server, sslcontext, moduleDir);
    }

    /*
     * SSL clients don't require certificates, but SSL servers do. If certfile
     * or keyfile are NULL, are not found, or are not accessible, we'll fail
     * later when we try to instantiate the SSL context.
     */

    certFile = Ns_ConfigGetValue(path, "certfile");
    if (certFile != NULL) {
        NsOpenSSLContextCertFileSet(server, sslcontext, certFile);
    }
    keyFile = Ns_ConfigGetValue(path, "keyfile");
    if (keyFile != NULL) {
        NsOpenSSLContextKeyFileSet(server, sslcontext, keyFile);
    }

    /*
     * The default protocols and ciphersuites are good for general use.
     */

    protocols = Ns_ConfigGetValue(path, "protocols");
    if (protocols != NULL) {
        NsOpenSSLContextProtocolsSet(server, sslcontext, protocols);
    }
    cipherSuite = Ns_ConfigGetValue(path, "ciphersuite");
    if (cipherSuite != NULL) {
        NsOpenSSLContextCipherSuiteSet(server, sslcontext, cipherSuite);
    }

    /*
     * The CA file/dir isn't necessary unless you actually do cert
     * verification. The CA file is simply a bunch of PEM-format CA
     * certificates concatenated together.
     */

    caFile = Ns_ConfigGetValue(path, "cafile");
    if (caFile != NULL) {
        NsOpenSSLContextCAFileSet(server, sslcontext, caFile);
    }
    caDir = Ns_ConfigGetValue(path, "cadir");
    if (caDir != NULL) {
        NsOpenSSLContextCADirSet(server, sslcontext, caDir);
    }

    /*
     * Peer verification will cause the server to request a client certificate.
     * If you aren't sure whether to turn it on or not, leave it off!
     */

    if (Ns_ConfigGetBool(path, "peerverify", &peerVerify) == NS_TRUE) {
        NsOpenSSLContextPeerVerifySet(server, sslcontext, peerVerify);
    }

    /*
     * A certificate may be at the bottom of a chain. Verify depth determines
     * how many levels down from the root cert you're willing to trust..
     */

    if (Ns_ConfigGetInt(path, "peerverifydepth", &peerVerifyDepth) == NS_TRUE) {
        NsOpenSSLContextPeerVerifyDepthSet(server, sslcontext, peerVerifyDepth);
    }

    /*
     * Session caching defaults to on, and should always be on if you
     * have web browsers connecting. Some versions of MSIE and Netscape will
     * fail if you don't have session caching on.
     */

    Ns_ConfigGetBool(path, "sessioncache", &sessionCache);
    if (sessionCache == NS_TRUE) {
        NsOpenSSLContextSessionCacheSet(server, sslcontext, sessionCache);
    }
    if (Ns_ConfigGetInt(path, "sessioncachesize", &sessionCacheSize) == NS_TRUE) {
        NsOpenSSLContextSessionCacheSizeSet(server, sslcontext, sessionCacheSize);
    }
    if (Ns_ConfigGetInt(path, "sessioncachetimeout", &sessionCacheTimeout) == NS_TRUE) {
        NsOpenSSLContextSessionCacheTimeoutSet(server, sslcontext, sessionCacheTimeout);
    }

    /*
     * Trace SSL handshake.
     */

    Ns_ConfigGetBool(path, "trace", &trace);
    if (trace == NS_TRUE) {
        NsOpenSSLContextTraceSet(server, sslcontext, 1);
    } else {
        NsOpenSSLContextTraceSet(server, sslcontext, 0);
    }

    return sslcontext;
}


/*
 *----------------------------------------------------------------------
 *
 * ServerShutdown --
 *
 *      Cleanup function to run at server shutdown.
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
    char *server = (char *) arg;

    Ns_Log(Notice, "Shutdown called for server %s", server);

    /*
     *   for each vserver.driver
     *       for each vserver.driver.conn
     *           close, free
     *       endfor
     *       free vserver.driver
     *   endfor
     *   free vserver
     */

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
InitOpenSSL(void)
{
    int        i         = 0;
    int        seedcnt   = 0;
    size_t     num_locks = 0;
    char      *lockName  = NULL;
    Ns_DString ds;

    Ns_DStringInit(&ds);

    /*
     * Initialize OpenSSL callbacks
     */

    if (CRYPTO_set_mem_functions(ns_malloc, ns_realloc, ns_free) == 0)
        Ns_Log(Warning, "%s: OpenSSL memory callbacks failed in InitOpenSSL",
                MODULE);
    num_locks = CRYPTO_num_locks();
    locks = ns_calloc(num_locks, sizeof(*locks));
    for (i = 0; i < num_locks; i++) {
	Ns_DStringPrintf(&ds, "crypto:%d", i);
	lockName = Ns_DStringExport(&ds);
        Ns_MutexSetName2(locks + i, MODULE_SHORT, lockName);
	Ns_DStringTrunc(&ds, 0);
	ns_free(lockName);
	lockName = NULL;
    }
    Ns_DStringFree(&ds);
    CRYPTO_set_locking_callback(ThreadLockCallback);
    CRYPTO_set_id_callback(ThreadIdCallback);

    /*
     * Initialize the OpenSSL library itself
     */

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_library_init();
    X509V3_add_standard_extensions();

    /*
     * Seed the OpenSSL Pseudo-Random Number Generator.
     */

    while (! RAND_status() && seedcnt < 3) {
        seedcnt++;
        Ns_Log(Notice, "%s: Seeding OpenSSL's PRNG", MODULE);
        SeedPRNG();
    }
    if (! RAND_status()) {
        Ns_Log(Warning, "%s: PRNG fails to have enough entropy after %d tries", 
                MODULE, seedcnt);
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
SeedPRNG(void)
{
    double *buf_ptr       = NULL;
    double *bufoffset_ptr = NULL;
    char   *path          = NULL;
    char   *randomFile    = NULL;
    size_t  size          = 0;
    int     i             = 0;
    int     seedBytes     = 0;
    int     readBytes     = 0;
    int     maxBytes      = 0;

    if (RAND_status()) {
        return NS_TRUE;
    } 
    path = Ns_ConfigGetPath(MODULE, NULL);
    if (Ns_ConfigGetInt(path, "seedbytes", &seedBytes) == NS_FALSE) {
        seedBytes = DEFAULT_SEEDBYTES;
    }
    if (Ns_ConfigGetInt(path, "maxbytes", &maxBytes) == NS_FALSE) {
        maxBytes = DEFAULT_MAXBYTES;
    }

    /*
     * Try to use the file specified by the user. If PRNG fails to seed here,
     * you might try increasing the seedBytes parameter in nsd.tcl.
     */

    randomFile = Ns_ConfigGetValue(path, "randomfile");
    if (randomFile != NULL && access(randomFile, F_OK) == 0) {
        if ((readBytes = RAND_load_file(randomFile, maxBytes))) {
            Ns_Log(Notice, "%s: Obtained %d random bytes from %s",
                    MODULE, readBytes, randomFile);
        } else {
            Ns_Log(Warning, "%s: Unable to retrieve any random data from %s",
                    MODULE, randomFile);
        }
    } else {
        Ns_Log(Warning, "%s: No randomFile set and/or found", MODULE);
    }
    if (RAND_status()) {
        return NS_TRUE;
    }

    /*
     * Use Ns_DRand(), passing it seedBytes as the second argument to RAND_add.
     */

    size = sizeof(double) * seedBytes;
    buf_ptr = Ns_Malloc(size);
    bufoffset_ptr = buf_ptr;
    for (i = 0; i < seedBytes; i++) {
        *bufoffset_ptr = Ns_DRand();
        bufoffset_ptr++;
    }
    RAND_add(buf_ptr, seedBytes, (double) seedBytes);
    ns_free(buf_ptr);
    if (!RAND_status()) {
        Ns_Log(Warning, "%s: failed to seed PRNG", MODULE);
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
ThreadLockCallback(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        Ns_MutexLock(locks + n);
    } else {
        Ns_MutexUnlock(locks + n);
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
ThreadIdCallback(void)
{
    return (unsigned long) Ns_ThreadId();
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
ThreadDynlockCreateCallback(char *file, int line)
{
    Ns_Mutex   *lock = NULL;
    Ns_DString  ds;

    Ns_DStringInit(&ds);
    lock = ns_calloc(1, sizeof(*lock));
    Ns_DStringVarAppend(&ds, "openssl: ", file, ": ");
    Ns_DStringPrintf(&ds, "%d", line);
    Ns_MutexSetName2(lock, MODULE, Ns_DStringValue(&ds));

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
ThreadDynlockLockCallback(int mode, struct CRYPTO_dynlock_value *dynlock,
        const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        Ns_MutexLock((Ns_Mutex *) dynlock);
    } else {
        Ns_MutexUnlock((Ns_Mutex *) dynlock);
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
ThreadDynlockDestroyCallback(struct CRYPTO_dynlock_value *dynlock,
        const char *file, int line)
{
    Ns_MutexDestroy((Ns_Mutex *) dynlock);
}


/*
 *----------------------------------------------------------------------
 *
 * LoadSSLDrivers --
 *
 *       Load the SSL drivers for a virtual server.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Registers driver with AOLserver core.
 *
 *----------------------------------------------------------------------
 */

static void
LoadSSLDrivers(char *server)
{
    NsOpenSSLContext *sslcontext     = NULL;
    NsOpenSSLDriver  *ssldriver      = NULL;
    Ns_Set           *ssldrivers     = NULL;
    char             *path           = NULL;
    char             *name           = NULL; 
    char             *sslcontextname = NULL;
    int               i              = 0;

    path = Ns_ConfigGetPath(server, MODULE, "ssldrivers", NULL);
    ssldrivers = Ns_ConfigGetSection(path);
    if (ssldrivers == NULL) {
        Ns_Log(Notice, "%s (%s): no SSL drivers defined for this server", 
                MODULE, server);
        return;
    }
    for (i = 0; i < Ns_SetSize(ssldrivers); ++i) {
        name = Ns_SetKey(ssldrivers, i);
        Ns_Log(Notice, "%s (%s): loading '%s' SSL driver", MODULE, server, name);
        path = Ns_ConfigGetPath(server, MODULE, "ssldriver", name, NULL);
        if (path == NULL) {
            Ns_Log(Error, "%s (%s): SSL driver '%s' not defined in configuration file",
                    MODULE, server, name);
            continue;
        }
        sslcontextname = Ns_ConfigGetValue(path, "sslcontext");
        if (sslcontextname == NULL) {
            Ns_Log(Error, "%s (%s): 'sslcontext' parameter not defined for driver '%s'",
                    MODULE, server, name);
            continue;
        }
        sslcontext = Ns_OpenSSLServerSSLContextGet(server, sslcontextname);
        if (sslcontext == NULL) {
            Ns_Log(Error, "%s (%s): SSL context '%s' needed by driver '%s' not found",
                    MODULE, server, sslcontextname, name);
            continue;
        }

        /*
         * Create the driver.
         */

        ssldriver = ns_calloc(1, sizeof(NsOpenSSLDriver));
        ssldriver->server     = server;
        ssldriver->sslcontext = sslcontext;
        ssldriver->name       = name;
        ssldriver->path       = path;
        ssldriver->refcnt     = 0;
        if (!Ns_ConfigGetInt(path, "port", &ssldriver->port)) {
            ssldriver->port = 443;
        }

        /*
         * Crank up the driver
         */

        if (InitSSLDriver(server, ssldriver) != NS_OK) { 

        }
    }
}


/*
 *----------------------------------------------------------------------
 *
 * InitSSLDriver --
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
InitSSLDriver(char *server, NsOpenSSLDriver *ssldriver)
{
    Ns_DriverInitData  init;
    Server            *thisServer = NULL;
    Tcl_HashEntry     *hPtr       = NULL;
    int                new        = 0;

    /*
     * Register the driver with AOLserver.
     */

    init.version = NS_DRIVER_VERSION_1;
    init.name    = MODULE;
    init.proc    = OpenSSLProc;
    init.opts    = NS_DRIVER_SSL;
    init.arg     = ssldriver;
    init.path    = ssldriver->path;

    if (Ns_DriverInit(server, MODULE, &init) != NS_ERROR) {
        return NS_ERROR;
    }

    /*
     * Add the driver to the virtual server's state info.
     */

    thisServer = NsOpenSSLServerGet(server);
    Ns_MutexLock(&thisServer->lock);
    hPtr = Tcl_CreateHashEntry(&thisServer->ssldrivers, ssldriver->name, &new);
    if (new) {
        Tcl_SetHashValue(hPtr, ssldriver);
    } else {
        Ns_Log(Error, "%s (%s): duplicate SSL driver name: %s",
                MODULE, server, ssldriver->name);
        return NS_ERROR;
    }
    Ns_MutexUnlock(&thisServer->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * DestroySSLDriver --
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

#if 0
static void
DestroySSLDriver(NsOpenSSLDriver *ssldriver)
{
    NsOpenSSLConn *sslconn;

    if (ssldriver == NULL) {
        return;
    }

    Ns_Log(Notice, "%s (%s): shutting down driver '%s'", MODULE, 
            ssldriver->server, ssldriver->name);

    /*
     * Destroy connections that are still tied to this driver. We need to lock
     * the driver struct, set a flag that denotes it as no longer usable so new
     * conns that come in before we've free'd it will be refused.
     */

    /* XXX lock */
    if (ssldriver->refcnt > 0) {
        while ((sslconn = ssldriver->firstFreeConn) != NULL) {
            ssldriver->firstFreeConn = sslconn->next;
            /* XXX doesn't this need to have it's contents free'd? */
            ns_free(sslconn);
        }
    }

    Ns_MutexDestroy(&ssldriver->lock);

    /* XXX should an SSL context be deallocated when it's refcnt reaches 0 ??? */
    if (ssldriver->sslcontext != NULL) 
        ssldriver->sslcontext->refcnt--;

    ns_free(ssldriver);

    /*
     * Remove driver from server state linked list.
     */

    return;
}
#endif


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
OpenSSLProc(Ns_DriverCmd cmd, Ns_Sock *sock, struct iovec *bufs, int nbufs)
{
    NsOpenSSLDriver *ssldriver = (NsOpenSSLDriver *) sock->driver->arg;
    NsOpenSSLConn   *sslconn   = (NsOpenSSLConn *)   sock->arg;
    int              n         = 0;
    int              total     = 0;

    switch (cmd) {
        case DriverRecv:
        case DriverSend:

            /* 
             * Create the SSL layer on first I/O and run SSL handshake.
             */

            if (sslconn == NULL) {

#if 0
                if (setsockopt(sock->sock, IPPROTO_TCP, TCP_NODELAY, (void *) 1, sizeof(int)) == -1) {
                    Ns_Log(Warning, "%s (%s): unable to turn off Nagle algorithm");
                }
#endif

#if 0
                /* XXX core driver socket handles this, no? */
                /* XXX look at interaction issues - when driver sock dies, how do I handle it? */
                n = sock->driver->recvwait;
                if (n > sock->driver->sendwait) 
                    n = sock->driver->sendwait;
#endif

                sslconn = NsOpenSSLConnCreate(sock->sock, ssldriver->sslcontext);
                if (sslconn == NULL) {
                    return NS_ERROR;
                }
                sslconn->refcnt++;
                sslconn->peerport  = ssldriver->port;
                sslconn->recvwait  = sock->driver->recvwait;
                sslconn->sendwait  = sock->driver->sendwait;
                sock->arg          = (void *) sslconn;
            }

            /* 
             * Process each buffer one at a time 
             */

            total = 0;
            do {
                if (cmd == DriverSend) {
                  //  n = NsOpenSSLConnSend(sslconn->ssl, bufs->iov_base, (int) bufs->iov_len);
                    n = NsOpenSSLConnOp(sslconn->ssl, bufs->iov_base, (int) bufs->iov_len, NSOPENSSL_SEND);
                } else {
                  //  n = NsOpenSSLConnRecv(sslconn->ssl, bufs->iov_base, (int) bufs->iov_len);
                    n = NsOpenSSLConnOp(sslconn->ssl, bufs->iov_base, (int) bufs->iov_len, NSOPENSSL_RECV);
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
            if (sslconn != NULL && NsOpenSSLConnFlush(sslconn) == NS_OK) {
                n = 0;
            } else {
                n = -1;
            }
            break;
        case DriverClose:
            if (sslconn != NULL) {
                (void) NsOpenSSLConnFlush(sslconn);
                NsOpenSSLConnDestroy(sslconn);
                sock->arg = NULL;
            }
            n = 0;
            break;
        default:
            Ns_Log(Error, "%s (%s): Unsupported driver command encountered", 
                    MODULE, ssldriver->server);
            n = -1;
            break;
    }

    return n;
}

