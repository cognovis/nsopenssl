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
 * Copyright (C) 2000 Freddie Mendoza
 * Copyright (C) 1999 Stefan Arentz
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
#include "config.h"
#include "tclcmds.h"

/*
 * Global symbols
 */

NS_EXPORT int Ns_ModuleVersion = 1;

NS_EXPORT int Ns_ModuleInit (char *server, char *module);

Tcl_HashTable NsOpenSSLServers;

/* Mandatory for export browsers */
static RSA *IssueTmpRSAKey (SSL * ssl, int export, int keylen);


/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *     Sock module init routine.
 *
 * Results:
 *     NS_OK if initialized ok, NS_ERROR otherwise.
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
    NsOpenSSLDriver *sdPtr;

    if (NsOpenSSLInitModule (server, module) != NS_OK) {
        Ns_Log(Error, "%s: %s: initialization failed", MODULE, server);
        return NS_ERROR;
    }

//#ifndef NS_MAJOR_VERSION
//    sdPtr = NsOpenSSLCreateDriver (server, module, sockProcs);
//#else
    sdPtr = NsOpenSSLCreateDriver (server, module);
//#endif

    if (sdPtr == NULL) {
	return NS_ERROR;
    }
//#ifndef NS_MAJOR_VERSION
//    sdPtr->nextPtr = firstSSLDriverPtr;
//    firstSSLDriverPtr = sdPtr;
//
//    return NS_OK;
//#else
//    return Ns_DriverInit (server, module, "nsopenssl", OpenSSLProc, sdPtr,
//			  NS_DRIVER_SSL);
//#endif

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
 *       Memory is allocated. All structure values are set to defaults.
 *       These defaults can be overridden by calls to the
 *       Ns_OpenSSLContext* functions.
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLContext *
Ns_OpenSSLContextCreate (char *server, char *module, char *name)
{
    Ns_OpenSSLContext *sslContext;
    Ns_DString ds;

    /* XXX need to insert the name into the server's hash list */

    /* XXX perform SSL context name collision check here */
#if 0
     /* The name of an SSL context must be unique within a virtual server */

    if (Ns_OpenSSLContextExists (server, module, name)) {
            Ns_Log(Error, "%s: SSL context with name %s already defined",
                            MODULE, name);
            return NULL;
    } else {
        Ns_OpenSSLContextAdd (server, module, name);
    }
#endif

    sslContext = ns_calloc(1, sizeof(*sslContext));
    sslContext->server = server;
    sslContext->module = module;
    sslContext->name = name;

    /* 
     * WARNING: session cache ids are global to the OpenSSL library. This means
     * that if another AOLserver module uses the OpenSSL library for SSL
     * connections that use session caching, some coordination will be
     * necessary so cache ids don't collide.
     */

    //Ns_MutexLock(&nextSessionCacheId->lock);
    //sslContext->sessionCacheId = nextSessionCacheId->id;
    //nextSessionCacheId->id++;
    //Ns_MutexUnlock(&nextSessionCacheId->lock);

    /*
     * Set initial default values that can be overridden in configuration file,
     * C API and Tcl API.
     */

    Ns_DStringInit (&ds);

    Ns_HomePath (&ds, "servers", server, "modules", module, NULL);
    sslContext->moduleDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CERT_FILE, NULL);
    sslContext->certFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_KEY_FILE, NULL);
    sslContext->keyFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CA_FILE, NULL);
    sslContext->caFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CA_DIR, NULL);
    sslContext->caDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_DStringFree (&ds);

    sslContext->peerVerify          = DEFAULT_PEER_VERIFY;
    sslContext->peerVerifyDepth     = DEFAULT_PEER_VERIFY_DEPTH;
    sslContext->protocols           = DEFAULT_PROTOCOLS;
    sslContext->cipherSuite         = DEFAULT_CIPHER_SUITE;
    sslContext->sessionCache        = DEFAULT_SESSION_CACHE;
    sslContext->sessionCacheSize    = DEFAULT_SESSION_CACHE_SIZE;
    sslContext->sessionCacheTimeout = DEFAULT_SESSION_CACHE_TIMEOUT;
    sslContext->trace               = DEFAULT_TRACE;

    /*
     * Insert the context into the linked list. Instead of wasting time looking
     * for the end of the list, we'll insert it at the front.
     */

    /* XXX lock firstSSLContext before modifying */
    //if (firstSSLContext != NULL) {
            /* There are already other contexts */
    //        sslContext->next = firstSSLContext;
    //        firstSSLContext = sslContext;
    //} else {
            /* We're the first context created */
    //        sslContext->next = NULL;
    //        firstSSLContext = sslContext;
    //}

    /* XXX need locking at startup? */
    //Ns_MutexUnlock(&sslcontext->lock);

    return sslContext;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextInit --
 *
 *	Take the information populating an SSL context structure and initialize
 *	the SSL_CTX with that information.
 *
 * Results:
 *	NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextInit (Ns_OpenSSLContext *sslContext) 
{
    /* Check the module directory */
    /* XXX sslContext->moduleDir; (validate it exists, create it) */

    /* Create an SSL_CTX structure */

    if (sslContext->role == ROLE_SSL_SERVER) {
        sslContext->sslctx = SSL_CTX_new (SSLv23_server_method());
    } else {
        sslContext->sslctx = SSL_CTX_new (SSLv23_client_method());
    }

    /* Load the cert file */
    /* XXX sslContext->certFile; */

    /* Load and validate the key file */

    /* Load the CA file (optional) */

    /* Set the CA directory (optional) */


    /* Set the cipher suite */

    /* Set the protocols */

    /* Set peer verify */

    /* Set peer verify depth */

    /* Use session cache? */

    /* Set size of session cache */

    /* Set session cache timeout */

    /* Turn on SSL handshake logging? */

    
    /* So we can get to SSL context pointer in an OpenSSL callback */
    SSL_CTX_set_app_data (sslContext->sslctx, sslContext);

    /* Enable SSL bug compatibility */
    SSL_CTX_set_options (sslContext->sslctx, SSL_OP_ALL);

    /* This apparently prevents some sort of DH attack. */
    SSL_CTX_set_options (sslContext->sslctx, SSL_OP_SINGLE_DH_USE);

    /* Temporary key callback required for 40-bit export browsers */
    SSL_CTX_set_tmp_rsa_callback (sslContext->sslctx, IssueTmpRSAKey);

    return NS_OK;
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
Ns_OpenSSLContextModuleDirSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, char *moduleDir)
{
    /* XXX lock struct */
    /* XXX validate that directory exists and is readable */
    sslContext->moduleDir = moduleDir;
    Ns_Log(Debug, "%s: %s: moduleDir set to %s", MODULE, server, moduleDir);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLContextCertFileSet --
 *
 *       Point to the SSL certificate file.
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
Ns_OpenSSLContextCertFileSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, char *certFile)
{
    sslContext->certFile = certFile;
    Ns_Log(Debug, "%s: %s: certFile set to %s", MODULE, server, certFile);
    return NS_OK;
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

/* XXX merge this with Ns_OpenSSLContextCertFileSet -- most code is duplicated */
int
Ns_OpenSSLContextKeyFileSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, char *keyFile)
{
    Ns_Log(Debug, "%s: %s: keyFile set to %s", MODULE, server, keyFile);
    sslContext->keyFile = keyFile;
    return NS_OK;
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
Ns_OpenSSLContextCipherSuiteSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, char *cipherSuite)
{
    sslContext->cipherSuite = cipherSuite;
    Ns_Log(Debug, "%s: %s: cipherSuite set to %s", MODULE, server, cipherSuite);
    return NS_OK;
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
Ns_OpenSSLContextProtocolsSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, char *protocols)
{
    /* XXX Need to ifdef out the protocols and ciphers that aren't compiled*/
    /* XXX a particular instance of an OpenSSL library */
    sslContext->protocols = protocols;
    Ns_Log(Debug, "%s: %s: protocols set to %s", MODULE, server, protocols);
    return NS_OK;
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

int
Ns_OpenSSLContextCAFileSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, char *caFile)
{
    sslContext->caFile = caFile;
    Ns_Log(Debug, "%s: %s: caFile set to %s", MODULE, server, caFile);
    return NS_OK;
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
Ns_OpenSSLContextCADirSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, char *caDir)
{
    sslContext->caDir = caDir;
    Ns_Log(Debug, "%s: %s: caDir set to %s", MODULE, server, caDir);
    return NS_OK;
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
Ns_OpenSSLContextPeerVerifySet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, int peerVerify)
{
    /* XXX lock struct */
    sslContext->peerVerify = peerVerify;
    Ns_Log(Debug, "%s: %s: peerVerify set to %d", MODULE, server, peerVerify);
    return NS_OK;
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
Ns_OpenSSLContextPeerVerifyDepthSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, int peerVerifyDepth)
{
    /* XXX lock struct */
    sslContext->peerVerifyDepth = peerVerifyDepth;
    Ns_Log(Debug, "%s: %s: peerVerifyDepth set to %d", MODULE, server, peerVerifyDepth);
    return NS_OK;
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
Ns_OpenSSLContextSessionCacheSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, int sessionCache)
{
    /* XXX lock struct */
    sslContext->sessionCache = sessionCache;
    Ns_Log(Debug, "%s: %s: sessionCache set to %d", MODULE, server, sessionCache);
    return NS_OK;
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
Ns_OpenSSLContextSessionCacheSizeSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, int sessionCacheSize)
{
    /* XXX lock struct */
    sslContext->sessionCacheSize = sessionCacheSize;
    Ns_Log(Debug, "%s: %s: sessionCacheSize set to %d", MODULE, server, sessionCacheSize);
    return NS_OK;
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
Ns_OpenSSLContextSessionCacheTimeoutSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, int sessionCacheTimeout)
{
    /* XXX lock struct */
    sslContext->sessionCacheTimeout = sessionCacheTimeout;
    Ns_Log(Debug, "%s: %s: sessionCacheTimeout set to %d", MODULE, server, sessionCacheTimeout);
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
Ns_OpenSSLContextTraceSet(char *server, char *module, 
    Ns_OpenSSLContext *sslContext, int trace)
{
    /* XXX lock struct */
    sslContext->trace = trace;
    Ns_Log(Debug, "%s: %s: trace set to %d", MODULE, server, trace);
    return NS_OK;
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

