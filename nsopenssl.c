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

extern Tcl_HashTable NsOpenSSLServers;
extern NsOpenSSLSessionCacheId *nextSessionCacheId;

static int PeerVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
static RSA *IssueTmpRSAKey(SSL *ssl, int export, int keylen);
static void OpenSSLTrace(SSL *ssl, int where, int rc);

static int InitCiphers(Ns_OpenSSLContext *sslcontext);
static int InitProtocols(Ns_OpenSSLContext *sslcontext);
static int InitCertFile(Ns_OpenSSLContext *sslcontext);
static int InitKeyFile(Ns_OpenSSLContext *sslcontext);
static int ValidateCertKey(Ns_OpenSSLContext *sslcontext);

static void InitCAFile(Ns_OpenSSLContext *sslcontext);
static void InitCADir(Ns_OpenSSLContext *sslcontext);
static void InitPeerVerify(Ns_OpenSSLContext *sslcontext);
static void InitPeerVerifyDepth(Ns_OpenSSLContext *sslcontext);
static void InitSessionCache(Ns_OpenSSLContext *sslcontext);
static void InitTrace(Ns_OpenSSLContext *sslcontext);

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
Ns_ModuleInit(char *server, char *module)
{
    return NsOpenSSLModuleInit(server, module);
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
Ns_OpenSSLContextModuleDirSet(char *server, char *module, Ns_OpenSSLContext *sslcontext, 
        char *moduleDir)
{
    //Ns_RWLockWrLock(&sslcontext->serverPtr->lock);
    sslcontext->moduleDir = moduleDir;
    //Ns_RWLockUnlock(&sslcontext->serverPtr->lock);
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
Ns_OpenSSLContextModuleDirGet(char *server, char *module, Ns_OpenSSLContext *sslcontext) {
    /* XXX lock */
    return sslcontext->moduleDir;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCertFileSet --
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
Ns_OpenSSLContextCertFileSet(char *server, char *module, Ns_OpenSSLContext *sslcontext, 
        char *certFile)
{
    Ns_DString ds;

    //Ns_Log(Debug, "*** certFile = %s", certFile);
    sslcontext->certFile = ns_strdup(certFile);
    if (!Ns_PathIsAbsolute(sslcontext->certFile)) {
        Ns_DStringInit(&ds);
        Ns_MakePath(&ds, sslcontext->moduleDir, sslcontext->certFile, NULL);
        sslcontext->certFile = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }
    Ns_Log(Debug, "*** setting cert to = %s", sslcontext->certFile);
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
Ns_OpenSSLContextCertFileGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->certFile;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextKeyFileSet --
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
Ns_OpenSSLContextKeyFileSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        char *keyFile)
{
    Ns_DString ds;

    //Ns_Log(Debug, "*** certFile = %s", certFile);
    sslcontext->keyFile = ns_strdup(keyFile);
    if (!Ns_PathIsAbsolute(sslcontext->keyFile)) {
        Ns_DStringInit(&ds);
        Ns_MakePath(&ds, sslcontext->moduleDir, sslcontext->keyFile, NULL);
        sslcontext->keyFile = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }
    //Ns_Log(Debug, "*** SSLContext->certFile = %s", sslcontext->certFile);
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
Ns_OpenSSLContextKeyFileGet(char *server, char *module, Ns_OpenSSLContext *sslcontext) 
{
    return sslcontext->keyFile;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCipherSuiteSet --
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
Ns_OpenSSLContextCipherSuiteSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        char *cipherSuite)
{
    sslcontext->cipherSuite = cipherSuite;
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCipherSuiteGet --
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
Ns_OpenSSLContextCipherSuiteGet(char *server, char *module, Ns_OpenSSLContext *sslcontext) 
{
    return sslcontext->cipherSuite;
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
Ns_OpenSSLContextProtocolsSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        char *protocols)
{
    sslcontext->protocols = protocols;
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
Ns_OpenSSLContextProtocolsGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->protocols;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCAFileSet --
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
Ns_OpenSSLContextCAFileSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        char *caFile)
{
    Ns_DString ds;

    //Ns_Log(Debug, "*** certFile = %s", certFile);
    sslcontext->caFile = ns_strdup(caFile);
    if (!Ns_PathIsAbsolute(sslcontext->caFile)) {
        Ns_DStringInit(&ds);
        Ns_MakePath(&ds, sslcontext->moduleDir, sslcontext->caFile, NULL);
        sslcontext->caFile = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }
    //Ns_Log(Debug, "*** SSLContext->certFile = %s", sslcontext->certFile);
    return NS_OK;
}


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
Ns_OpenSSLContextCAFileGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->caFile;
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
Ns_OpenSSLContextCADirSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        char *caDir)
{
    sslcontext->caDir = caDir;
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
Ns_OpenSSLContextCADirGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->caDir;
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
Ns_OpenSSLContextPeerVerifySet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        int peerVerify)
{
    /* XXX lock struct */
    /* XXX handle default case where peerVerify is NULL */
    sslcontext->peerVerify = peerVerify;
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
Ns_OpenSSLContextPeerVerifyGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->peerVerify;
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
Ns_OpenSSLContextPeerVerifyDepthSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        int peerVerifyDepth)
{
    /* XXX lock struct */
    /* XXX how do I handle the default case? with varargs in func call? */
    /* XXX ah, no, preset all the default values in Ns_OpenSSLContextCreate */
    sslcontext->peerVerifyDepth = peerVerifyDepth;
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
Ns_OpenSSLContextPeerVerifyDepthGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->peerVerifyDepth;
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
Ns_OpenSSLContextSessionCacheSet(char *server, char *module, Ns_OpenSSLContext *sslcontext, 
        int sessionCache)
{
    /* XXX lock struct */
    sslcontext->sessionCache = sessionCache;
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
Ns_OpenSSLContextSessionCacheGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->sessionCache;
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
Ns_OpenSSLContextSessionCacheSizeSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        int sessionCacheSize)
{
    /* XXX lock struct */
    sslcontext->sessionCacheSize = sessionCacheSize;
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
Ns_OpenSSLContextSessionCacheSizeGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->sessionCacheSize;
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
Ns_OpenSSLContextSessionCacheTimeoutSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        int sessionCacheTimeout)
{
    /* XXX lock struct */
    sslcontext->sessionCacheTimeout = sessionCacheTimeout;
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
Ns_OpenSSLContextSessionCacheTimeoutGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    /* XXX lock struct */
    return sslcontext->sessionCacheTimeout;
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
Ns_OpenSSLContextTraceSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        int trace)
{
    /* XXX lock struct */
    sslcontext->trace = trace;
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
Ns_OpenSSLContextTraceGet(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    return sslcontext->trace;
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
Ns_OpenSSLContextCreate(char *server, char *module)
{
    Ns_OpenSSLContext *sslcontext;
    Ns_DString ds;

#if 0
    /* XXX turn this on */
    /*
     * The name of an SSL context must be unique within a virtual server.
     */

    if (SSLContextNameCheck(server, module, name)) {
	    Ns_Log(Error, "%s: SSL context with name %s already defined",
			    MODULE, name);
	    return NULL;
    }
#endif

    sslcontext = ns_calloc(1, sizeof(*sslcontext));
    sslcontext->server = server;
    sslcontext->module = module;
    sslcontext->readonly = NS_FALSE;
    sslcontext->bufsize = DEFAULT_BUFFER_SIZE;
    sslcontext->timeout = DEFAULT_TIMEOUT;
    sslcontext->peerVerify = DEFAULT_PEER_VERIFY;
    sslcontext->peerVerifyDepth = DEFAULT_PEER_VERIFY_DEPTH;
    sslcontext->protocols = DEFAULT_PROTOCOLS;
    sslcontext->cipherSuite = DEFAULT_CIPHER_LIST;
    sslcontext->sessionCache = DEFAULT_SESSION_CACHE;
    sslcontext->sessionCacheSize = DEFAULT_SESSION_CACHE_SIZE;
    sslcontext->sessionCacheTimeout = DEFAULT_SESSION_CACHE_TIMEOUT;
    sslcontext->trace = DEFAULT_TRACE;

    /* 
     * WARNING: session cache ids are global to the OpenSSL library. This means
     * that if another AOLserver module uses the OpenSSL library for SSL
     * connections that use session caching, some coordination will be
     * necessary so cache ids don't collide.
     */

    /* XXX see if session cache ids can be alpha-numeric */
    /* XXX answer is YES. Make it so. */
    Ns_MutexLock(&nextSessionCacheId->lock);
    sslcontext->sessionCacheId = nextSessionCacheId->id;
    nextSessionCacheId->id++;
    Ns_MutexUnlock(&nextSessionCacheId->lock);

    /*
     * First we set initial default values. These can be overridden in nsd.tcl,
     * C API and Tcl API.
     */

    Ns_DStringInit(&ds);
   
    Ns_HomePath(&ds, "servers", server, "modules", module, NULL);
    sslcontext->moduleDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath(&ds, "servers", server, "modules", module, DEFAULT_CERT_FILE, NULL);
    sslcontext->certFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath(&ds, "servers", server, "modules", module, DEFAULT_KEY_FILE, NULL);
    sslcontext->keyFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath(&ds, "servers", server, "modules", module, DEFAULT_CA_FILE, NULL);
    sslcontext->caFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath(&ds, "servers", server, "modules", module, DEFAULT_CA_DIR, NULL);
    sslcontext->caDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_DStringFree(&ds);
    return sslcontext;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextInit --
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
 *       Ns_OpenSSLContextRelease.
 *
 *----------------------------------------------------------------------
 */

/* XXX move most critical stuff to top of this func (i.e. cert doesn't load,
 * XXX doesn't matter what else is done */
int
Ns_OpenSSLContextInit(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    if (sslcontext == NULL) {
        Ns_Log(Error, "%s: %s: SSL context passed to Ns_OpenSSLContextValidate is NULL",
                server, MODULE);
        return NS_ERROR;
    }

    if (!STREQ(server, sslcontext->server)) {
        Ns_Log(Error, "%s: %s: SSL context server field (%s) does not match the virtual server name",
                server, MODULE, sslcontext->server);
        return NS_ERROR;
    }

    /*
     * Initialize parts of SSL_CTX that are common to all Ns_OpenSSLContexts
     * (i.e. these are not configurable via nsd.tcl or Ns_OpenSSL* calls).
     */

    sslcontext->sslctx = SSL_CTX_new(SSLv23_server_method());

    if (sslcontext->sslctx == NULL) {
        /* XXX FAILURE: clean up and then free the struct */
        return NS_ERROR;
    }

    /* XXX this is always over-ridden by SSL_set_app_data */
    /* Allows us to get context struct from within OpenSSL callbacks */
    SSL_CTX_set_app_data(sslcontext->sslctx, sslcontext);

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
     * XXX I need to research the warning above and find out why that's
     * so.
     * XXX I could store certs in memory and check to see if the same cert
     * is already in memory and use if from there instead.
     */

    if ( 
            InitCiphers(sslcontext)  == NS_ERROR
            || InitProtocols(sslcontext) == NS_ERROR
            || InitKeyFile(sslcontext) == NS_ERROR
            || InitCertFile(sslcontext) == NS_ERROR
            || ValidateCertKey(sslcontext) == NS_ERROR
       ) {
        return NS_ERROR;
    }

    /*
     * Peer verify initialization must come before CA file and directory
     * initialization.
     */

    InitPeerVerifyDepth(sslcontext);
    InitPeerVerify(sslcontext);
    InitCAFile(sslcontext);
    InitCADir(sslcontext);
    InitSessionCache(sslcontext);
    InitTrace(sslcontext);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextRelease --
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
 *       Ns_OpenSSLContextInit() is called to (re-)initialize the SSL_CTX
 *       structure inside of it: this would be bad if you release the context
 *       used for incoming conns to your site.
 *
 *----------------------------------------------------------------------
 */

/* XXX add the ability to wait for the context to be inactive? */
int
Ns_OpenSSLContextRelease(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{

    /* XXX rw lock */
    if (sslcontext->refcnt > 0) {
        Ns_Log(Error, "%s: %s: attempted to release SSL context '%s' while still in use by active connections", 
                server, MODULE, sslcontext->name);
        return NS_ERROR;
    }

    Ns_Log(Warning, "%s: %s: releasing SSL context '%s' to be writeable",
            server, MODULE, sslcontext->name);
    sslcontext->readonly = NS_FALSE;
    /* XXX rw unlock */
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextDestroy --
 *
 *       Destroy an Ns_OpenSSLContext structure
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
Ns_OpenSSLContextDestroy(char *server, char *module, Ns_OpenSSLContext *sslcontext)
{
    /* XXX fill this in */
    /* XXX to free:
       XXX    sslcontext->certFile
       XXX    sslcontext->keyFile
       XXX    sslcontext->caFile
       XXX    anything else that has been strdup'd
     */

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLIsPeerCertValid --
 *
 *      Determine if the peer's certificate is valid.
 *
 * Results:
 *      NS_TRUE or NS_FALSE.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLIsPeerCertValid(Ns_OpenSSLConn *sslconn)
{
    if (SSL_get_verify_result(sslconn->ssl) == X509_V_OK) {
	return NS_TRUE;
    } else {
	return NS_FALSE;
    }

    /* Possible (long) values from SSL_get_verify_result:
       X509_V_OK
       X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
       X509_V_ERR_UNABLE_TO_GET_CRL
       X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE
       X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
       X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
       X509_V_ERR_CERT_SIGNATURE_FAILURE
       X509_V_ERR_CRL_SIGNATURE_FAILURE
       X509_V_ERR_CERT_NOT_YET_VALID
       X509_V_ERR_CERT_HAS_EXPIRED
       X509_V_ERR_CRL_NOT_YET_VALID
       X509_V_ERR_CRL_HAS_EXPIRED
       X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
       X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
       X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
       X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
       X509_V_ERR_OUT_OF_MEM
       X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
       X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
       X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
       X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
       X509_V_ERR_CERT_CHAIN_TOO_LONG
       X509_V_ERR_CERT_REVOKED
       X509_V_ERR_APPLICATION_VERIFICATION
     */
}



/*
 *----------------------------------------------------------------------
 *
 * InitCertFile --
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
InitCertFile(Ns_OpenSSLContext *sslcontext)
{
    char *error;

    if (sslcontext->certFile == NULL ||
            SSL_CTX_use_certificate_chain_file(sslcontext->sslctx, sslcontext->certFile) == 0
       ) {
        Ns_Log(Error, "%s: %s: error loading certificate '%s'",
                sslcontext->server, MODULE, sslcontext->certFile);
        error = ERR_reason_error_string(ERR_get_error());
        Ns_Log(Error, "%s: %s: OpenSSL reports: %s",
                sslcontext->server, MODULE, error);
        if ((access(sslcontext->certFile, F_OK) != 0) || (access(sslcontext->certFile, R_OK) != 0))
            Ns_Log(Error, "%s: %s: '%s' certificate file is not readable or does not exist", 
                    sslcontext->server, MODULE, sslcontext->name);
        return NS_ERROR;
    }
    Ns_Log(Notice, "%s: %s: '%s' certificate loaded successfully", 
            sslcontext->server, MODULE, sslcontext->name);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * InitKeyFile --
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
InitKeyFile(Ns_OpenSSLContext *sslcontext)
{
    /* XXX add ability to read DER etc. file formats? */
    if (sslcontext->keyFile == NULL ||
            SSL_CTX_use_PrivateKey_file(sslcontext->sslctx, sslcontext->keyFile,
                SSL_FILETYPE_PEM) == 0) {
        Ns_Log(Error, "%s: %s: error loading key file '%s'",
                sslcontext->server, MODULE, sslcontext->keyFile);
        if ((access(sslcontext->keyFile, F_OK) != 0) || (access(sslcontext->keyFile, R_OK) != 0))
            Ns_Log(Error, "%s: %s: '%s' key file is not readable or does not exist", 
                    sslcontext->server, MODULE, sslcontext->name);
        return NS_ERROR;
    }
    Ns_Log(Notice, "%s: %s: '%s' key loaded successfully", 
            sslcontext->server, MODULE, sslcontext->name);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * ValidateCertKey --
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
ValidateCertKey(Ns_OpenSSLContext *sslcontext)
{
    if (SSL_CTX_check_private_key(sslcontext->sslctx) == 0) {
        Ns_Log(Error, "%s: %s: '%s' private key does not match certificate",
                sslcontext->server, MODULE, sslcontext->name);
        return NS_ERROR;
    }
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * InitCAFile --
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

/* XXX merge with InitCADir so I can give good error msgs if verify is set to true */
static void
InitCAFile(Ns_OpenSSLContext *sslcontext)
{
    if (sslcontext->caFile == NULL ||
            SSL_CTX_load_verify_locations(sslcontext->sslctx, sslcontext->caFile, NULL) == 0) {
        Ns_Log(Notice, "%s: %s: '%s' failed to load CA certificate file '%s'",
                sslcontext->server, MODULE, sslcontext->name, sslcontext->caFile);
        if (sslcontext->peerVerify)
            Ns_Log(Error, "%s: %s: '%s' is set to verify peers; CA \
                    certificates are required to perform peer verification",
                    sslcontext->server, MODULE, sslcontext->name);
        if ((access(sslcontext->caFile, F_OK) != 0) || (access(sslcontext->caFile, R_OK) != 0))
            Ns_Log(Error, "%s: %s: '%s' CA certificate file is not readable or does not exist", 
                    sslcontext->server, MODULE, sslcontext->name);
    } else {
        Ns_Log(Notice, "%s: %s: '%s' CA file loaded successfully", 
                sslcontext->server, MODULE, sslcontext->name);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * InitCADir --
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
InitCADir(Ns_OpenSSLContext *sslcontext)
{
    DIR *dirfp;

    if (sslcontext->caDir == NULL ||
            SSL_CTX_load_verify_locations(sslcontext->sslctx, NULL, sslcontext->caDir) == 0) {
        Ns_Log(Warning, "%s: %s: '%s' error using CA directory '%s'",
                sslcontext->server, MODULE, sslcontext->name, sslcontext->caDir);
        dirfp = opendir(sslcontext->caDir);
        if (dirfp == NULL) {
            Ns_Log(Warning, "%s: %s: '%s' cannot open CA certificate directory",
                    sslcontext->server, MODULE, sslcontext->name);
        }
        closedir(dirfp);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * InitCiphers --
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
InitCiphers(Ns_OpenSSLContext *sslcontext)
{
    if (SSL_CTX_set_cipher_list(sslcontext->sslctx, sslcontext->cipherSuite == 0)) {
        Ns_Log(Error, "%s: %s: '%s' error setting cipher suite to '%s'",
                sslcontext->server, MODULE, sslcontext->name, sslcontext->cipherSuite);
        return NS_ERROR;
    }
    Ns_Log(Notice, "%s: %s: ciphers loaded successfully for '%s'",
            sslcontext->server, MODULE, sslcontext->name);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * InitPeerVerify --
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
InitPeerVerify(Ns_OpenSSLContext *sslcontext)
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
 * InitPeerVerifyDepth --
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
InitPeerVerifyDepth(Ns_OpenSSLContext *sslcontext)
{
    if (sslcontext->peerVerifyDepth == 0) {
        Ns_Log(Warning, "%s: %s: '%s' peer verify depth set to infinite",
                sslcontext->server, MODULE, sslcontext->name);
    }
    if (sslcontext->peerVerifyDepth >= 0) {
        SSL_CTX_set_verify_depth(sslcontext->sslctx, sslcontext->peerVerifyDepth);
    } else {
        Ns_Log(Warning, "%s: %s: '%s' peer verify parameter invalid; defaulting to %d",
                sslcontext->server, MODULE, sslcontext->name, DEFAULT_PEER_VERIFY_DEPTH);
        SSL_CTX_set_verify_depth(sslcontext->sslctx, DEFAULT_PEER_VERIFY_DEPTH);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * InitSessionCache --
 *
 *       Initialize session cache.
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static void
InitSessionCache(Ns_OpenSSLContext *sslcontext)
{
    /* XXX need to make this work well with Timeout, Size set/get funcs */
    if (sslcontext->sessionCache) {
        SSL_CTX_set_session_cache_mode(sslcontext->sslctx, SSL_SESS_CACHE_SERVER);

        /* XXX fix to prefix with "nsopenssl", "nsopensslclient" etc. */
        SSL_CTX_set_session_id_context(sslcontext->sslctx,
                (void *) &sslcontext->sessionCacheId,
                sizeof(sslcontext->sessionCacheId));

        /* XXX evaluate */
        SSL_CTX_set_timeout(sslcontext->sslctx, sslcontext->sessionCacheTimeout);
        SSL_CTX_sess_set_cache_size(sslcontext->sslctx, sslcontext->sessionCacheSize);
    } else {
        Ns_Log(Warning, "%s: %s: session cache is turned off; this will cause some browsers to fail",
                sslcontext->server, MODULE);
        SSL_CTX_set_session_cache_mode(sslcontext->sslctx, SSL_SESS_CACHE_OFF);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * InitTrace --
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
InitTrace(Ns_OpenSSLContext *sslcontext)
{
    /* XXX lock struct */
    if (sslcontext->trace) {
        SSL_CTX_set_info_callback(sslcontext->sslctx, OpenSSLTrace);
    } else {
        SSL_CTX_set_info_callback(sslcontext->sslctx, NULL);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * InitProtocols --
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
InitProtocols(Ns_OpenSSLContext *sslcontext)
{
    int bits;
    char *lprotocols;

    /* XXX ifdef out the protocols and ciphers that aren't compiled into OpenSSL ??? */
    bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    if (sslcontext->protocols == NULL) {
        Ns_Log(Notice, "%s: %s: '%s' protocol parameter not set; using all protocols: SSLv2, SSLv3 and TLSv1",
                sslcontext->server, MODULE, sslcontext->name);
        bits &= ~bits;
    } else {
        lprotocols = ns_strdup(sslcontext->protocols);
        lprotocols = Ns_StrToLower(lprotocols);
        /* XXX check use of strstr here */
        if (strstr(lprotocols, "all") != NULL) {
            Ns_Log(Notice, "%s: %s: '%s' using all protocols: SSLv2, SSLv3 and TLSv1",
                    sslcontext->server, MODULE, sslcontext->name);
            bits &= ~bits;
        } else {
            if (strstr(lprotocols, "sslv2") != NULL) {
                Ns_Log(Notice, "%s: %s: '%s' using SSLv2 protocol", sslcontext->server, MODULE, sslcontext->name);
                bits &= ~SSL_OP_NO_SSLv2;
            }
            if (strstr(lprotocols, "sslv3") != NULL) {
                Ns_Log(Notice, "%s: %s: '%s' using SSLv3 protocol", sslcontext->server, MODULE, sslcontext->name);
                bits &= ~SSL_OP_NO_SSLv3;
            }
            if (strstr(lprotocols, "tlsv1") != NULL) {
                Ns_Log(Notice, "%s: %s: '%s' using TLSv1 protocol",
                        sslcontext->server, MODULE, sslcontext->name);
                bits &= ~SSL_OP_NO_TLSv1;
            }
        }
        ns_free(lprotocols);
    }
    if (SSL_CTX_set_options(sslcontext->sslctx, bits) == 0) {
        Ns_Log(Error, "%s: %s: protocol initialization failed",
                sslcontext->server, MODULE);
        return NS_ERROR;
    }
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
PeerVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{   
    return 1;
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
    Ns_OpenSSLConn *sslconn;
    static RSA *rsa_tmp;

    sslconn = (Ns_OpenSSLConn *) SSL_get_app_data(ssl);

    rsa_tmp = RSA_generate_key(keylen, RSA_F4, NULL, NULL);
    if (rsa_tmp == NULL) {
        Ns_Log(Error, "%s: %s: Temporary RSA key generation failed",
                MODULE, sslconn->ssldriver->server);
    } else {
        Ns_Log(Notice, "%s: %s: Generated %d-bit temporary RSA key",
                MODULE, sslconn->ssldriver->server, keylen);
    }
    return rsa_tmp;
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

void
OpenSSLTrace(SSL *ssl, int where, int rc)
{
    Ns_OpenSSLConn *sslconn;
    char *alertTypePrefix;
    char *alertType;
    char *alertDescPrefix;
    char *alertDesc;

    Ns_Log(Debug, "*** HERE in TRACE");

    sslconn = (Ns_OpenSSLConn *) SSL_get_app_data(ssl);

    if (where & SSL_CB_ALERT) {
	alertTypePrefix = "; alert type = ";
	alertType = SSL_alert_type_string_long(rc);
	alertDescPrefix = "; alert desc = ";
	alertDesc = SSL_alert_desc_string_long(rc);
    } else {
	alertTypePrefix = alertType = "";
	alertDescPrefix = alertDesc = "";
    }

    Ns_Log(Notice, "%s: trace: %s%s%s%s%s",
	    MODULE,
	    SSL_state_string_long(ssl),
	    alertTypePrefix, alertType, alertDescPrefix, alertDesc);
}
