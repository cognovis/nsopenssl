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
 */

/*
 * sslcontext.c --
 *
 *       Manages SSL context state structures.
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include "nsopenssl.h"

Tcl_HashTable
NsOpenSSLServers;

static RSA *
IssueTmpRSAKey(SSL *ssl, int export, int keylen);

static char *
SSLContextSessionCacheIdNew(char *server);

static void
OpenSSLTrace(SSL *ssl, int where, int rc);

static void
SSLContextCAFileInit(NsOpenSSLContext *sslcontext);

static void
SSLContextCADirInit(NsOpenSSLContext *sslcontext);

static int 
SSLContextCiphersInit(NsOpenSSLContext *sslcontext);

static int
SSLContextProtocolsInit(NsOpenSSLContext *sslcontext);

static int
SSLContextCertFileInit(NsOpenSSLContext *sslcontext);

static int
SSLContextKeyFileInit(NsOpenSSLContext *sslcontext);

static int
SSLContextValidateCertKey(NsOpenSSLContext *sslcontext);

static void
SSLContextPeerVerifyInit(NsOpenSSLContext *sslcontext);

static void
SSLContextPeerVerifyDepthInit(NsOpenSSLContext *sslcontext);

static void
SSLContextSessionCacheInit(NsOpenSSLContext *sslcontext);

static void
SSLContextTraceInit(NsOpenSSLContext *sslcontext);

static int
PeerVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCreate --
 *
 *       Create a new NsOpenSSLContext structure
 *
 * Results:
 *       Pointer to resulting struct or NULL on error
 *
 * Side effects:
 *       Memory is allocated. All structure values are set to defaults.
 *       These defaults can be overridden by calls to the
 *       NsOpenSSLContext* functions.
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLContext *
NsOpenSSLContextCreate(char *server, char *name)
{
    NsOpenSSLContext *sslcontext = NULL;
    Ns_DString        ds;
    char             *lockName   = NULL;

    Ns_DStringInit(&ds);

    /*
     * Check to see if the context name is already in use. The name of an SSL
     * context must be unique within a virtual server.
     */

    if (Ns_OpenSSLServerSSLContextGet(server, name) != NULL) {
        Ns_Log(Error, "%s (%s): SSL context with name %s already defined",
                MODULE, server, name);
        return NULL;
    }

    /*
     * Create the SSL context.
     */

    sslcontext = ns_calloc(1, sizeof(*sslcontext));
    Ns_MutexInit(&sslcontext->lock);
    Ns_DStringPrintf(&ds, "ctx:%s", name);
    lockName = Ns_DStringExport(&ds);
    Ns_MutexSetName2(&sslcontext->lock, MODULE_SHORT, lockName);
    Ns_DStringTrunc(&ds, 0);
    ns_free(lockName);
    lockName = NULL;

    /*
     * Set SSL context initial values.
     */

    sslcontext->server              = server;
    sslcontext->name                = name;
    sslcontext->initialized         = NS_FALSE;
    sslcontext->refcnt              = 0;
    sslcontext->peerVerify          = DEFAULT_PEER_VERIFY;
    sslcontext->peerVerifyDepth     = DEFAULT_PEER_VERIFY_DEPTH;
    sslcontext->protocols           = DEFAULT_PROTOCOLS;
    sslcontext->cipherSuite         = DEFAULT_CIPHER_LIST;
    sslcontext->sessionCache        = DEFAULT_SESSION_CACHE;
    sslcontext->sessionCacheSize    = DEFAULT_SESSION_CACHE_SIZE;
    sslcontext->sessionCacheTimeout = DEFAULT_SESSION_CACHE_TIMEOUT;
    sslcontext->trace               = DEFAULT_TRACE;
    sslcontext->bufsize             = DEFAULT_BUFFER_SIZE;
    sslcontext->timeout             = DEFAULT_TIMEOUT;
    sslcontext->sessionCacheId      = SSLContextSessionCacheIdNew(server);
    Ns_HomePath(&ds, "servers", server, "modules", MODULE, NULL);
    sslcontext->moduleDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);
    Ns_HomePath(&ds, "servers", server, "modules", MODULE, DEFAULT_CERT_FILE, NULL);
    sslcontext->certFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);
    Ns_HomePath(&ds, "servers", server, "modules", MODULE, DEFAULT_KEY_FILE, NULL);
    sslcontext->keyFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);
    Ns_HomePath(&ds, "servers", server, "modules", MODULE, DEFAULT_CA_FILE, NULL);
    sslcontext->caFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);
    Ns_HomePath(&ds, "servers", server, "modules", MODULE, DEFAULT_CA_DIR, NULL);
    sslcontext->caDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);
    Ns_DStringFree(&ds);

    return sslcontext;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextDestroy --
 *
 *       Destroy an NsOpenSSLContext structure
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Memory is deallocated.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLContextDestroy(char *server, NsOpenSSLContext *sslcontext)
{
    ns_free(sslcontext->certFile);
    ns_free(sslcontext->keyFile);
    ns_free(sslcontext->caFile);
    ns_free(sslcontext->caDir);
    ns_free(sslcontext);

#if 0
    /* XXX REMOVE THE CONTEXT FROM THE SERVER STATE */
    Ns_OpenSSLServerContextRemove();
#endif

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextInit --
 *
 *       Initialize an SSL Context. This runs all of the SSL_CTX calls to
 *       create the SSL instance template. This template is used to create the
 *       SSL objects for each connection.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Marks the SSL Context as 'read-only'; no changes can be made to the
 *       SSL Context after this point unless you explicitly call
 *       NsOpenSSLContextRelease.
 *
 *----------------------------------------------------------------------
 */

/* XXX move most critical stuff to top of this func (i.e. cert doesn't load,
 * XXX doesn't matter what else is done */
int
NsOpenSSLContextInit(char *server, NsOpenSSLContext *sslcontext)
{
    if (sslcontext == NULL) {
        Ns_Log(Error, "%s (%s): SSL context is NULL", MODULE, server);
        return NS_ERROR;
    }
    if (!STREQ(server, sslcontext->server)) {
        Ns_Log(Error, "%s (%s): SSL context server field (%s) does not match the virtual server name",
                MODULE, server, sslcontext->server);
        return NS_ERROR;
    }

    /*
     * Initialize the SSL_CTX based on the role this context will play.
     */

    if (sslcontext->role) {
        sslcontext->sslctx = SSL_CTX_new(SSLv23_server_method());
    } else {
        sslcontext->sslctx = SSL_CTX_new(SSLv23_client_method());
    }

    if (sslcontext->sslctx == NULL) {
        /* XXX FAILURE: clean up and then free the struct */
        Ns_Log(Error, "%s (%s): OpenSSL failed to create new SSL_CTX structure",
                MODULE, server);
        return NS_ERROR;
    }

    /* XXX this is always over-ridden by SSL_set_app_data */
#if 0
    /* Allows us to get context struct from within OpenSSL callbacks */
    SSL_CTX_set_app_data(sslcontext->sslctx, sslcontext);
#endif

    /* Enable SSL bug compatibility */
    SSL_CTX_set_options(sslcontext->sslctx, SSL_OP_ALL);

    /* This apparently prevents some sort of DH attack */
    SSL_CTX_set_options(sslcontext->sslctx, SSL_OP_SINGLE_DH_USE);

    /* Temporary key callback required for 40-bit export browsers */
    SSL_CTX_set_tmp_rsa_callback(sslcontext->sslctx, IssueTmpRSAKey);

    /*
     * Failure in one of these will cause SSL context to be left uninitialized.
     */

    /*
     * WARNING!: InitKeyFile *must* be called before InitCertFile; not doing so
     * will cause subsequent calls to InitCertFile to fail with File Not Found
     * error if you're using the same certificate and key for multiple driver
     * instances. I believe this is a bug in OpenSSL, as the error returned
     * comes from that library after the SSL_CTX_use_certificate_chain_file
     * call.
     */

    if ( SSLContextCiphersInit(sslcontext)           == NS_ERROR
            || SSLContextProtocolsInit(sslcontext)   == NS_ERROR
            || SSLContextKeyFileInit(sslcontext)     == NS_ERROR
            || SSLContextCertFileInit(sslcontext)    == NS_ERROR
            || SSLContextValidateCertKey(sslcontext) == NS_ERROR
       ) {
        return NS_ERROR;
    }

    /*
     * Peer verify initialization must come before CA file and directory
     * initialization.
     */

    SSLContextPeerVerifyDepthInit(sslcontext);
    SSLContextPeerVerifyInit(sslcontext);
    SSLContextCAFileInit(sslcontext);
    SSLContextCADirInit(sslcontext);
    SSLContextSessionCacheInit(sslcontext);
    SSLContextTraceInit(sslcontext);

    /*
     * We succeeded in initializing the context. We now have an OpenSSL SSL_CTX
     * structure we can use to create SSL connections.
     */

    sslcontext->initialized = 1;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextRelease --
 *
 *       Release an SSL Context so you can modify it.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       An SSL Context that has a refcnt > 0 won't be released because refcnt
 *       conns are currently using the structure. Once released, the SSL
 *       Context can't be used for connections again until
 *       NsOpenSSLContextInit() is called to (re-)initialize the SSL_CTX
 *       structure inside of it: this would be bad if you release the context
 *       used for incoming conns to your site.
 *
 *----------------------------------------------------------------------
 */

#if 0
int
NsOpenSSLContextRelease(char *server, NsOpenSSLContext *sslcontext)
{
    if (sslcontext->readonly) {
        Ns_Log(Error, "%s (%s): attempting to modify a read-only SSL context",
            MODULE, server);
        return NS_ERROR;
    }

    /* XXX lock */
    if (sslcontext->refcnt > 0) {
        Ns_Log(Error, "%s (%s): attempted to release SSL context '%s' while still in use by active connections", 
                MODULE, server, sslcontext->name);
        return NS_ERROR;
    }

    Ns_Log(Warning, "%s (%s): releasing SSL context '%s' to be writeable",
            MODULE, server, sslcontext->name);
    sslcontext->readonly = NS_FALSE;
    /* XXX unlock */

    return NS_OK;
}
#endif 


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextRoleSet --
 *
 *       Set the role (either client or server)
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
NsOpenSSLContextRoleSet(char *server, NsOpenSSLContext *sslcontext, 
        char *role)
{
    Ns_MutexLock(&sslcontext->lock);
    if (STREQ(role, "client")) {
        sslcontext->role = 0;
    } else if (STREQ(role, "server")) {
        sslcontext->role = 1;
    } else {
        Ns_Log(Error, "%s (%s): illegal SSL context role: '%s'", MODULE,
                server, role);
        return NS_ERROR;
    }
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextRoleGet --
 *
 *       Get the role (either client or server)
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
NsOpenSSLContextRoleGet(char *server, NsOpenSSLContext *sslcontext)
{
    Ns_MutexLock(&sslcontext->lock);
    if (sslcontext->role == 0) {
        return "client";
    } else if (sslcontext->role == 1) {
        return "server";
    } else {
        return "undefined";
    }
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextModuleDirSet --
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
NsOpenSSLContextModuleDirSet(char *server, NsOpenSSLContext *sslcontext, 
        char *moduleDir)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->moduleDir = moduleDir;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextModuleDirGet --
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
NsOpenSSLContextModuleDirGet(char *server, NsOpenSSLContext *sslcontext) {
    return sslcontext->moduleDir;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCertFileSet --
 *
 *       Sets and loads the specified certificate for the given SSL context.
 *       You MUST load the certificate before you attempt to load the private
 *       key.  The certificate must be in PEM format.  You can put the
 *       certificate chain in the same file: simply append the CA certs to the
 *       end of your certificate file and they'll be passed to the client at
 *       connection time. If no certs are appended, no cert chain will be
 *       passed to the client.
 *
 *       Warning: you should have already set the context's moduleDir if you
 *       don't want the default. Alternatively, the certFile can be an absolute
 *       path. If it is a relative path, that path will be prepended by the
 *       whatever the moduleDir parameter is set to in your nsd.tcl file, or by
 *       the default moduleDir path.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Note that moduleDir must already be set before this call. It is
 *       guaranteed to be set to the default location already.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLContextCertFileSet(char *server, NsOpenSSLContext *sslcontext, 
        char *certFile)
{
    Ns_DString ds;

    Ns_DStringInit(&ds);
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->certFile = ns_strdup(certFile);
    if (!Ns_PathIsAbsolute(sslcontext->certFile)) {
        Ns_MakePath(&ds, sslcontext->moduleDir, sslcontext->certFile, NULL);
        sslcontext->certFile = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCertFileGet --
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
NsOpenSSLContextCertFileGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->certFile;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextKeyFileSet --
 *
 *       Set the private key pathname for a particular SSL context, 
 *       load the key and validate that it works with the certificate.
 *       The key MUST NOT be passphrase-protected.
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
NsOpenSSLContextKeyFileSet(char *server, NsOpenSSLContext *sslcontext,
        char *keyFile)
{
    Ns_DString ds;

    Ns_DStringInit(&ds);
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->keyFile = ns_strdup(keyFile);
    if (!Ns_PathIsAbsolute(sslcontext->keyFile)) {
        Ns_MakePath(&ds, sslcontext->moduleDir, sslcontext->keyFile, NULL);
        sslcontext->keyFile = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextKeyFileGet --
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
NsOpenSSLContextKeyFileGet(char *server, NsOpenSSLContext *sslcontext) 
{
    return sslcontext->keyFile;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCipherSuiteSet --
 *
 *       Set the cipher suite for a particular SSL context
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
NsOpenSSLContextCipherSuiteSet(char *server, NsOpenSSLContext *sslcontext,
        char *cipherSuite)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->cipherSuite = cipherSuite;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCipherSuiteGet --
 *
 *       Get the cipher suite string for a particular SSL context
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
NsOpenSSLContextCipherSuiteGet(char *server, NsOpenSSLContext *sslcontext) 
{
    return sslcontext->cipherSuite;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextProtocolsSet --
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
NsOpenSSLContextProtocolsSet(char *server, NsOpenSSLContext *sslcontext,
        char *protocols)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->protocols = protocols;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextProtocolsGet --
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
NsOpenSSLContextProtocolsGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->protocols;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCAFileSet --
 *
 *       Set the CA file for a particular SSL context and load it.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None
 *
 *----------------------------------------------------------------------
 */

/* XXX change all these to return voids */
int
NsOpenSSLContextCAFileSet(char *server, NsOpenSSLContext *sslcontext,
        char *caFile)
{
    Ns_DString ds;

    Ns_DStringInit(&ds);
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->caFile = ns_strdup(caFile);
    if (!Ns_PathIsAbsolute(sslcontext->caFile)) {
        Ns_MakePath(&ds, sslcontext->moduleDir, sslcontext->caFile, NULL);
        sslcontext->caFile = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCAFileGet --
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
NsOpenSSLContextCAFileGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->caFile;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCADirSet --
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
NsOpenSSLContextCADirSet(char *server, NsOpenSSLContext *sslcontext,
        char *caDir)
{
    Ns_DString ds;

    Ns_DStringInit(&ds);
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->caDir = ns_strdup(caDir);
    if (!Ns_PathIsAbsolute(sslcontext->caDir)) {
        Ns_MakePath(&ds, sslcontext->moduleDir, sslcontext->caDir, NULL);
        sslcontext->caDir = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextCADirGet --
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
NsOpenSSLContextCADirGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->caDir;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextPeerVerifySet --
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
NsOpenSSLContextPeerVerifySet(char *server, NsOpenSSLContext *sslcontext,
        int peerVerify)
{
    /* XXX handle default case where peerVerify is NULL */
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->peerVerify = peerVerify;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextPeerVerifyGet --
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
NsOpenSSLContextPeerVerifyGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->peerVerify;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextPeerVerifyDepthSet --
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
NsOpenSSLContextPeerVerifyDepthSet(char *server, NsOpenSSLContext *sslcontext,
        int peerVerifyDepth)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->peerVerifyDepth = peerVerifyDepth;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextPeerVerifyDepthGet --
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
NsOpenSSLContextPeerVerifyDepthGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->peerVerifyDepth;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSessionCacheSet --
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
NsOpenSSLContextSessionCacheSet(char *server, NsOpenSSLContext *sslcontext, 
        int sessionCache)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->sessionCache = sessionCache;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSessionCacheGet --
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
NsOpenSSLContextSessionCacheGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->sessionCache;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSessionCacheSizeSet --
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
NsOpenSSLContextSessionCacheSizeSet(char *server, NsOpenSSLContext *sslcontext,
        int sessionCacheSize)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->sessionCacheSize = sessionCacheSize;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSessionCacheSizeGet --
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
NsOpenSSLContextSessionCacheSizeGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->sessionCacheSize;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSessionCacheTimeoutSet --
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
NsOpenSSLContextSessionCacheTimeoutSet(char *server, NsOpenSSLContext *sslcontext,
        int sessionCacheTimeout)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->sessionCacheTimeout = sessionCacheTimeout;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSessionCacheTimeoutGet --
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
NsOpenSSLContextSessionCacheTimeoutGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->sessionCacheTimeout;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextTraceSet --
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
NsOpenSSLContextTraceSet(char *server, NsOpenSSLContext *sslcontext,
        int trace)
{
    Ns_MutexLock(&sslcontext->lock);
    sslcontext->trace = trace;
    Ns_MutexUnlock(&sslcontext->lock);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextTraceGet --
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
NsOpenSSLContextTraceGet(char *server, NsOpenSSLContext *sslcontext)
{
    return sslcontext->trace;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLServerGet --
 *
 *       Return the named virtual server's state structure.
 *
 * Results:
 *       A pointer to Server struct.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

Server *
NsOpenSSLServerGet(char *server)
{
    Server        *thisServer = NULL;
    Tcl_HashEntry *hPtr       = NULL;

    /* XXX lock */
    hPtr = Tcl_FindHashEntry(&NsOpenSSLServers, server);
    if (hPtr != NULL) {
        thisServer = Tcl_GetHashValue(hPtr);
    }
    /* XXX unlock */

    return thisServer;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextAdd --
 *
 *       Add an SSL context to a server state info
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

void
NsOpenSSLContextAdd(char *server, NsOpenSSLContext *sslcontext)
{
    Server        *thisServer = NULL;
    Tcl_HashEntry *hPtr       = NULL;
    int            new        = 0;

    if (sslcontext == NULL) {
        Ns_Log(Warning, "%s (%s): attempt to add SSL context to server failed",
                MODULE, server);
    } else {
        thisServer = NsOpenSSLServerGet(server);
        Ns_MutexLock(&thisServer->lock);
        hPtr = Tcl_CreateHashEntry(&thisServer->sslcontexts, sslcontext->name, &new);
        if (new) {
            Tcl_SetHashValue(hPtr, sslcontext);
        } else {
            Ns_Log(Error, "%s (%s): duplicate SSL context name: %s",
                    MODULE, server, sslcontext->name);
        }
        Ns_MutexUnlock(&thisServer->lock);
    }

    return;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextRemove --
 *
 *       Remove an SSL context from server state info
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

void
NsOpenSSLContextRemove(char *server, NsOpenSSLContext *sslcontext)
{
    Server        *thisServer = NULL;
    Tcl_HashEntry *hPtr       = NULL;

    if (sslcontext == NULL) {
        return;
    }
    thisServer = NsOpenSSLServerGet(server);
    Ns_MutexLock(&thisServer->lock);
    hPtr = Tcl_FindHashEntry(&thisServer->sslcontexts, sslcontext->name);
    if (hPtr != NULL) {
        Tcl_DeleteHashEntry(hPtr);
    }
    Ns_MutexUnlock(&thisServer->lock);

    return;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLServerSSLContextGet --
 *
 *       Get an SSL context from server state info
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLContext *
Ns_OpenSSLServerSSLContextGet(char *server, char *name)
{
    NsOpenSSLContext *sslcontext = NULL;
    Server           *thisServer = NULL;
    Tcl_HashEntry    *hPtr       = NULL;

    if (name == NULL) {
        Ns_Log(Error, "%s (%s): attempt to get SSL context with NULL name",
                MODULE, server);
        return NULL;
    }
    thisServer = NsOpenSSLServerGet(server);
    Ns_MutexLock(&thisServer->lock);
    hPtr = Tcl_FindHashEntry(&thisServer->sslcontexts, name);
    if (hPtr != NULL) {
        sslcontext = Tcl_GetHashValue(hPtr);
    }
    Ns_MutexUnlock(&thisServer->lock);

    return sslcontext;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextServerDefaultGet --
 *
 *    Return the virtual server's default server SSL context. 
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLContext *
NsOpenSSLContextServerDefaultGet(char *server)
{
    Server *thisServer = NsOpenSSLServerGet(server);

    return Ns_OpenSSLServerSSLContextGet(server, thisServer->defaultservercontext);
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextClientDefaultGet --
 *
 *    Return the virtual server's default client SSL context. 
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLContext *
NsOpenSSLContextClientDefaultGet(char *server)
{
    Server *thisServer = NsOpenSSLServerGet(server);

    return Ns_OpenSSLServerSSLContextGet(server, thisServer->defaultclientcontext);
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
 *       None
 *
 *----------------------------------------------------------------------
 */

static RSA *
IssueTmpRSAKey(SSL *ssl, int export, int keylen)
{
    NsOpenSSLConn *sslconn = NULL;
    static RSA    *rsa_tmp = NULL;

    sslconn = (NsOpenSSLConn *) SSL_get_app_data(ssl);
    rsa_tmp = RSA_generate_key(keylen, RSA_F4, NULL, NULL);
    if (rsa_tmp == NULL) {
        Ns_Log(Error, "%s (%s): Temporary RSA key generation failed",
                MODULE, sslconn->ssldriver->server);
    } else {
        Ns_Log(Notice, "%s (%s): Generated %d-bit temporary RSA key",
                MODULE, sslconn->ssldriver->server, keylen);
    }

    return rsa_tmp;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSessionCacheIdNew --
 *
 *    Generate and return a new session cache id. Because we need each session
 *    cache to have a unique id across the entire application, we prefix the
 *    number with the module name and the name of the virtual server.  We check
 *    to ensure that the generated cache id is not greater than
 *    SSL_MAX_SSL_SESSION_ID_LENGTH, which at the time of this writing is 32
 *    bytes. 
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static char *
SSLContextSessionCacheIdNew(char *server)
{
    Server      *thisServer     = NsOpenSSLServerGet(server);
    Ns_DString   ds;
    char        *sessionCacheId = NULL;
    int          id             = 0;

    Ns_DStringInit(&ds);
    Ns_MutexLock(&thisServer->lock);
    id = thisServer->nextSessionCacheId;
    thisServer->nextSessionCacheId++;
    Ns_MutexUnlock(&thisServer->lock);
    Ns_DStringPrintf(&ds, "%s:%s:%d", MODULE, server, id);
    if (Ns_DStringLength(&ds) > SSL_MAX_SSL_SESSION_ID_LENGTH) {
        Ns_Log(Error, "%s (%s): session cache id generated is too big; truncating",
                MODULE, server);
        Ns_DStringTrunc(&ds, 0);
        Ns_DStringPrintf(&ds, "%s:%d", server, id);
    }
    sessionCacheId = Ns_DStringExport(&ds);
    Ns_DStringFree(&ds);

    return sessionCacheId;
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextCertFileInit --
 *
 *       Load SSL context's certificate
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
SSLContextCertFileInit(NsOpenSSLContext *sslcontext)
{
    if (sslcontext->certFile == NULL ||
            SSL_CTX_use_certificate_chain_file(sslcontext->sslctx, sslcontext->certFile) == 0
       ) {
        Ns_Log(Error, "%s (%s): error loading certificate '%s'",
                MODULE, sslcontext->server, sslcontext->certFile);
        if ((access(sslcontext->certFile, F_OK) != 0) || (access(sslcontext->certFile, R_OK) != 0))
            Ns_Log(Error, "%s (%s): '%s' certificate file is not readable or does not exist", 
                    MODULE, sslcontext->server, sslcontext->name);
        return NS_ERROR;
    }
    Ns_Log(Notice, "%s (%s): '%s' certificate loaded successfully", 
            MODULE, sslcontext->server, sslcontext->name);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextKeyFileInit --
 *
 *       Load SSL context's key file
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
SSLContextKeyFileInit(NsOpenSSLContext *sslcontext)
{
    if (sslcontext->keyFile == NULL ||
            SSL_CTX_use_PrivateKey_file(sslcontext->sslctx, sslcontext->keyFile,
                SSL_FILETYPE_PEM) == 0) {
        Ns_Log(Error, "%s (%s): error loading key file '%s'",
                MODULE, sslcontext->server, sslcontext->keyFile);
        if ((access(sslcontext->keyFile, F_OK) != 0) || (access(sslcontext->keyFile, R_OK) != 0))
            Ns_Log(Error, "%s (%s): '%s' key file is not readable or does not exist", 
                    MODULE, sslcontext->server, sslcontext->name);
        return NS_ERROR;
    }
    Ns_Log(Notice, "%s (%s): '%s' key loaded successfully", 
            MODULE, sslcontext->server, sslcontext->name);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextValidateCertKey --
 *
 *       Validates that the certificate and key matches
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
SSLContextValidateCertKey(NsOpenSSLContext *sslcontext)
{
    if (SSL_CTX_check_private_key(sslcontext->sslctx) == 0) {
        Ns_Log(Error, "%s (%s): '%s' private key does not match certificate",
                MODULE, sslcontext->server, sslcontext->name);
        return NS_ERROR;
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextCAFileInit --
 *
 *       Loads SSL context's CA file
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
SSLContextCAFileInit(NsOpenSSLContext *sslcontext)
{
    if (sslcontext->caFile == NULL ||
            SSL_CTX_load_verify_locations(sslcontext->sslctx, sslcontext->caFile, NULL) == 0) {
        Ns_Log(Notice, "%s (%s): '%s' failed to load CA certificate file '%s'",
                MODULE, sslcontext->server, sslcontext->name, sslcontext->caFile);
        if (sslcontext->peerVerify)
            Ns_Log(Error, "%s (%s): '%s' is set to verify peers; CA \
                    certificates are required to perform peer verification",
                    MODULE, sslcontext->server, sslcontext->name);
        if ((access(sslcontext->caFile, F_OK) != 0) || (access(sslcontext->caFile, R_OK) != 0))
            Ns_Log(Error, "%s (%s): '%s' CA certificate file is not readable or does not exist", 
                    MODULE, sslcontext->server, sslcontext->name);
    } else {
        Ns_Log(Notice, "%s (%s): '%s' CA file loaded successfully", 
                MODULE, sslcontext->server, sslcontext->name);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextCADirInit --
 *
 *       Initializes SSL context's CA directory
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
SSLContextCADirInit(NsOpenSSLContext *sslcontext)
{
    DIR *dirfp = NULL;

    if (sslcontext->caDir == NULL ||
            SSL_CTX_load_verify_locations(sslcontext->sslctx, NULL, sslcontext->caDir) == 0) {
        Ns_Log(Warning, "%s (%s): '%s' error using CA directory '%s'",
                MODULE, sslcontext->server, sslcontext->name, sslcontext->caDir);
        dirfp = opendir(sslcontext->caDir);
        if (dirfp == NULL) {
            Ns_Log(Warning, "%s (%s): '%s' cannot open CA certificate directory",
                    MODULE, sslcontext->server, sslcontext->name);
        }
        closedir(dirfp);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextCiphersInit --
 *
 *       Initialize cipher suite for an SSL context.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
SSLContextCiphersInit(NsOpenSSLContext *sslcontext)
{
    if (SSL_CTX_set_cipher_list(sslcontext->sslctx, sslcontext->cipherSuite) == 0) {
        Ns_Log(Error, "%s (%s): '%s' error setting cipher suite to '%s'",
                MODULE, sslcontext->server, sslcontext->name, sslcontext->cipherSuite);
        return NS_ERROR;
    }
    Ns_Log(Notice, "%s (%s): '%s' ciphers loaded successfully",
            MODULE, sslcontext->server, sslcontext->name);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextPeerVerifyInit --
 *
 *       Initialize peer veification.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
SSLContextPeerVerifyInit(NsOpenSSLContext *sslcontext)
{
    if (sslcontext->peerVerify) {
        SSL_CTX_set_verify(sslcontext->sslctx, (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE),
                PeerVerifyCallback);
    } else {
        SSL_CTX_set_verify(sslcontext->sslctx, SSL_VERIFY_NONE, NULL);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextPeerVerifyDepthInit --
 *
 *       Initialize peer verification depth. A '0' value indicates infitite
 *       depth.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
SSLContextPeerVerifyDepthInit(NsOpenSSLContext *sslcontext)
{
    if (sslcontext->peerVerifyDepth == 0) {
        Ns_Log(Warning, "%s (%s): '%s' peer verify depth set to infinite",
                MODULE, sslcontext->server, sslcontext->name);
    }
    if (sslcontext->peerVerifyDepth >= 0) {
        SSL_CTX_set_verify_depth(sslcontext->sslctx, sslcontext->peerVerifyDepth);
    } else {
        Ns_Log(Warning, "%s (%s): '%s' peer verify parameter invalid; defaulting to %d",
                MODULE, sslcontext->server, sslcontext->name, DEFAULT_PEER_VERIFY_DEPTH);
        SSL_CTX_set_verify_depth(sslcontext->sslctx, DEFAULT_PEER_VERIFY_DEPTH);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextSessionCacheInit --
 *
 *       Initialize the per-SSL context session cache. We use OpenSSL's
 *       internal cache for storage and let it do the work. 
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
SSLContextSessionCacheInit(NsOpenSSLContext *sslcontext)
{
    if (sslcontext->sessionCache) {

        /*
         * Turn on session caching for this SSL context.
         */

        if (sslcontext->role == SERVER_ROLE) {
            SSL_CTX_set_session_cache_mode(sslcontext->sslctx, SSL_SESS_CACHE_SERVER);
        } else {
            SSL_CTX_set_session_cache_mode(sslcontext->sslctx, SSL_SESS_CACHE_CLIENT);
        }

        /*
         * Create the session cache context id which must be unique to each SSL
         * context across the entire OpenSSL library. This means we need to
         * make it unique enough that another AOLserver module won't
         * inadvertently use the same session cache context id.
         */

        SSL_CTX_set_session_id_context(
            sslcontext->sslctx,
            (void *) &sslcontext->sessionCacheId,
            sizeof(sslcontext->sessionCacheId)
        );

        /*
         * Set the time to live for a session in this session cache. After this
         * time, a session will have expired. It will be flushed automatically
         * by OpenSSL sometime after expiration. If a session has expired and a
         * new connection comes in using that session before the session cache
         * has been flushed, this session in the cache is flushed immediately
         * and a new session cache is created. (XXX need to confirm this)
         */

        SSL_CTX_set_timeout(sslcontext->sslctx, sslcontext->sessionCacheTimeout);

        /*
         * Set how many sessions can be cached in this session cache.
         */

        SSL_CTX_sess_set_cache_size(sslcontext->sslctx, sslcontext->sessionCacheSize);
        Ns_Log(Notice, "%s (%s): session cache is turned on for sslcontext '%s'",
            sslcontext->name, MODULE, sslcontext->server);
    } else {
        SSL_CTX_set_session_cache_mode(sslcontext->sslctx, SSL_SESS_CACHE_OFF);
        Ns_Log(Notice, "%s (%s): session cache is turned off for sslcontext '%s'",
            sslcontext->name, MODULE, sslcontext->server);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextTraceInit --
 *
 *       Initialize handshake tracing.
 *
 * Results:
 *
 * Side effects:
 *       SSL handshake information may show up in the server log. You don't
 *       want this to happen in normal production service.
 *
 *----------------------------------------------------------------------
 */

static void
SSLContextTraceInit(NsOpenSSLContext *sslcontext)
{
    /* XXX lock */
    if (sslcontext->trace) {
        SSL_CTX_set_info_callback(sslcontext->sslctx, (void *) OpenSSLTrace);
    } else {
        SSL_CTX_set_info_callback(sslcontext->sslctx, NULL);
    }
    /* XXX unlock */
}


/*
 *----------------------------------------------------------------------
 *
 * SSLContextProtocolsInit --
 *
 *       Initialize protocols for an SSL context.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
SSLContextProtocolsInit(NsOpenSSLContext *sslcontext)
{
    int   bits       = 0;
    char *lprotocols = NULL;

    bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    if (sslcontext->protocols == NULL) {
        Ns_Log(Notice, "%s (%s): '%s' protocol parameter not set; using all protocols: SSLv2, SSLv3 and TLSv1",
                MODULE, sslcontext->server, sslcontext->name);
        bits &= ~bits;
    } else {
        lprotocols = ns_strdup(sslcontext->protocols);
        lprotocols = Ns_StrToLower(lprotocols);
        if (strstr(lprotocols, "all") != NULL) {
            Ns_Log(Notice, "%s (%s): '%s' using all protocols: SSLv2, SSLv3 and TLSv1",
                    MODULE, sslcontext->server, sslcontext->name);
            bits &= ~bits;
        } else {
            if (strstr(lprotocols, "sslv2") != NULL) {
                Ns_Log(Notice, "%s (%s): '%s' using SSLv2 protocol", MODULE, sslcontext->server, sslcontext->name);
                bits &= ~SSL_OP_NO_SSLv2;
            }
            if (strstr(lprotocols, "sslv3") != NULL) {
                Ns_Log(Notice, "%s (%s): '%s' using SSLv3 protocol", MODULE, sslcontext->server, sslcontext->name);
                bits &= ~SSL_OP_NO_SSLv3;
            }
            if (strstr(lprotocols, "tlsv1") != NULL) {
                Ns_Log(Notice, "%s (%s): '%s' using TLSv1 protocol",
                        MODULE, sslcontext->server, sslcontext->name);
                bits &= ~SSL_OP_NO_TLSv1;
            }
        }
        ns_free(lprotocols);
    }
    if (SSL_CTX_set_options(sslcontext->sslctx, bits) == 0) {
        Ns_Log(Error, "%s (%s): protocol initialization failed",
                MODULE, sslcontext->server);
        return NS_ERROR;
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * OpenSSLTrace --
 *
 *	Log the progress of an SSL connection.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Server log output.
 *
 *----------------------------------------------------------------------
 */

static void
OpenSSLTrace(SSL *ssl, int where, int rc)
{
    NsOpenSSLConn *sslconn         = (NsOpenSSLConn *) SSL_get_app_data(ssl);
    char          *alertTypePrefix = NULL;
    char          *alertType       = NULL;
    char          *alertDescPrefix = NULL;
    char          *alertDesc       = NULL;
    struct timeval previoustime;
    unsigned long  seconds;
    unsigned long  microseconds;

    if (where & SSL_CB_ALERT) {
        alertTypePrefix = "; alert type = ";
        alertType = (char *) SSL_alert_type_string_long(rc);
        alertDescPrefix = "; alert desc = ";
        alertDesc = (char *) SSL_alert_desc_string_long(rc);
    } else {
        alertTypePrefix = alertType = "";
        alertDescPrefix = alertDesc = "";
    }

    /* Get time since last timer update */
    previoustime = sslconn->timer;

    /* Update the timer */
    gettimeofday(&sslconn->timer, NULL);

    /* Find the difference in seconds */
    seconds = sslconn->timer.tv_sec - previoustime.tv_sec;

    /* Find the difference in microseconds */
    microseconds = sslconn->timer.tv_usec - previoustime.tv_usec;

    /* Convert the difference in seconds to microseconds and add */
    microseconds = microseconds + (seconds * 1000000);

    Ns_Log(Notice, "%s (%s): trace (%p): %8ld secs: %s%s%s%s%s",
            MODULE, sslconn->server,
            sslconn,
            microseconds,
            SSL_state_string_long(ssl),
            alertTypePrefix, alertType, alertDescPrefix, alertDesc
    );
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
PeerVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{   
    return 1;
}   

