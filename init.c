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
 * Copyright (C) 2000-2001 Scott S. Goodwin
 * Copyright (C) 2000 Rob Mayoff
 * Copyright (C) 1999 Stefan Arentz.
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

static const char *RCSID = "@(#) $Header$, compiled: " __DATE__ " " __TIME__;

#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include "nsopenssl.h"
#include "config.h"
#include "thread.h"

/* What happens if we run multiple copies of nsopenssl in the same server? */
/* XXX test this -- set them to the same # and see if conflicts develop */
/* XXX also, go look in OpenSSL sources to see how this is used */
static int s_server_session_id_context = 1;
static int s_client_session_id_context = 2;



static int InitializeSSL(void);
static int MakeModuleDir(char *server, char *module, char **dirp);

/*
 * Functions common to both client and server SSL
 */

static int SetProtocols(NsOpenSSLContext *pdPtr);
static int SetCipherSuite(NsOpenSSLContext *pdPtr);
static int LoadAndCheckCertificate(NsOpenSSLContext *pdPtr);
static int LoadCertificate(NsOpenSSLContext *pdPtr);
static int LoadKey(NsOpenSSLContext *pdPtr);
static int CheckKey(NsOpenSSLContext *pdPtr);
static int LoadCACerts(NsOpenSSLContext *pdPtr);
static int InitSessionCache(NsOpenSSLContext *pdPtr);

/*
 * SSL Server-only functions
 */

static int ServerMakeContext(NsServerSSLDriver *sdPtr);
static int ServerInitLocation(NsServerSSLDriver *sdPtr);
static int ServerVerifyClientCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);

/*
 * For generating temporary RSA keys. Temp RSA keys are REQUIRED if
 * you want 40-bit encryption to work in old export browsers. This is
 * only used by the server-side.
 */
static int AddEntropyFromRandomFile(NsServerSSLDriver *sdPtr, long maxbytes);
static int PRNGIsSeeded(NsServerSSLDriver *sdPtr);
static int SeedPRNG(NsServerSSLDriver *sdPtr);
static RSA * IssueTmpRSAKey(SSL *ssl, int export, int keylen);

/*
 * SSL Client-only functions
 */

static int ClientMakeContext(NsClientSSLDriver *cdPtr);
static int ClientLoadCertificate(NsOpenSSLContext *pdPtr);
/* XXX want to add logic in this function to check NsOpenSSLContext to */
/* XXX see if user wants to redirect to error page, allow application */
/* XXX to handle invalid certs, or to abort the conn when cert is invalid */
/* XXX Might also be able to merge this with ServerVerifyClientCallback */
static int ClientVerifyServerCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);


/*
 *----------------------------------------------------------------------
 *
 * NsInitOpenSSL --
 *
 *       Initialize the OpenSSL library.
 *
 * Results:
 *       None.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

int
NsInitOpenSSL()
{
    if (
	   NsOpenSSLInitThreads()                      == NS_ERROR
	|| InitializeSSL()                             == NS_ERROR
    ) {
	return NS_ERROR;
    }
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLModuleDataInit --
 *
 *       Create and fill the structure that maintains data common
 *       between the server and the client nsopenssl functions.
 *
 * Results:
 *       An NsOpenSSLModuleData* or NULL.
 *
 * Side effects:
 *       None.
 *
 *---------------------------------------------------------------------- */

NsOpenSSLModuleData *
NsOpenSSLModuleDataInit(char *server, char *module)
{
    NsOpenSSLModuleData *mPtr = NULL;

    mPtr = (NsOpenSSLModuleData *) ns_calloc(1, sizeof *mPtr);

    if (MakeModuleDir(server, module, &mPtr->dir)  == NS_ERROR) {
	if (mPtr->dir != NULL)      ns_free(mPtr->dir);
	ns_free(mPtr);
	return NULL;
    }

    Ns_MutexSetName(&mPtr->lock, "common");
    mPtr->refcnt = 0;
    mPtr->name = module;
    mPtr->configPath = Ns_ConfigGetPath(server, module, NULL);

    return mPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLModuleDataFree --
 *
 *      Destroy an NsOpenSSLModuleData*.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

void
NsOpenSSLModuleDataFree(NsOpenSSLModuleData *mPtr)
{
    NsServerSSLConnection *scPtr;

    Ns_Log(Debug, "%s: freeing(%p)",
	mPtr == NULL ? DRIVER_NAME : mPtr->name, mPtr);

    if (mPtr != NULL) {
	Ns_MutexDestroy(&mPtr->lock);
	if (mPtr->name  != NULL)          ns_free(mPtr->name);
	if (mPtr->configPath  != NULL)    ns_free(mPtr->configPath);
	if (mPtr->dir != NULL)            ns_free(mPtr->dir);
	ns_free(mPtr);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLCreateDriver --
 *
 *       Create the SSL driver.
 *
 * Results:
 *       An NsServerSSLDriver* or NULL.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

NsServerSSLDriver *
#ifndef NS_MAJOR_VERSION
NsServerSSLCreateDriver(char *server, char *module,
    NsOpenSSLModuleData *mPtr, Ns_DrvProc *procs)
#else
NsServerSSLCreateDriver(char *server, char *module,
    NsOpenSSLModuleData *mPtr)
#endif
{
    NsServerSSLDriver *sdPtr = NULL;

    sdPtr = (NsServerSSLDriver *) ns_calloc(1, sizeof *sdPtr);
    
    Ns_MutexSetName(&sdPtr->lock, "server");

    /* XXX assign these vars in the same order they're declared in the struct */
    sdPtr->module = mPtr;
    Ns_MutexLock(&mPtr->lock);
    sdPtr->module->refcnt++;
    Ns_MutexUnlock(&mPtr->lock);

    sdPtr->type = (char *) ns_calloc(1, sizeof SERVER_STRING);
    strcpy(sdPtr->type, SERVER_STRING);
    sdPtr->refcnt = 1;
    sdPtr->lsock = INVALID_SOCKET;

    sdPtr->certfile = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
			  CONFIG_SERVER_CERTFILE, sdPtr->module->dir, DEFAULT_SERVER_CERTFILE);

    sdPtr->keyfile =  ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
			  CONFIG_SERVER_KEYFILE, sdPtr->module->dir, DEFAULT_SERVER_KEYFILE);

    sdPtr->protocols = ConfigStringDefault(sdPtr->module->name, sdPtr->module->configPath,
                          CONFIG_SERVER_PROTOCOLS, DEFAULT_PROTOCOLS);

    sdPtr->cipherSuite = ConfigStringDefault(sdPtr->module->name, sdPtr->module->configPath,
                          CONFIG_SERVER_CIPHERSUITE, DEFAULT_CIPHERSUITE);

    sdPtr->cafile = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
			  CONFIG_SERVER_CAFILE, sdPtr->module->dir, DEFAULT_SERVER_CAFILE);

    sdPtr->cadir = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
			  CONFIG_SERVER_CADIR, sdPtr->module->dir, DEFAULT_SERVER_CADIR);

    sdPtr->cacheEnabled = ConfigBoolDefault(sdPtr->module->name, sdPtr->module->configPath,
                          CONFIG_SERVER_SESSIONCACHE, DEFAULT_SERVER_SESSIONCACHE);

    sdPtr->cacheSize = ConfigIntDefault(sdPtr->module->name, sdPtr->module->configPath,
			  CONFIG_SERVER_SESSIONCACHESIZE, DEFAULT_SERVER_SESSIONCACHESIZE);

    sdPtr->cacheTimeout = (long) ConfigIntDefault(sdPtr->module->name, sdPtr->module->configPath,
			  CONFIG_SERVER_SESSIONTIMEOUT, DEFAULT_SERVER_SESSIONTIMEOUT);


    if (
	   ServerMakeContext(sdPtr)                                == NS_ERROR
	|| SetProtocols((NsOpenSSLContext *) sdPtr)                == NS_ERROR
	|| SetCipherSuite((NsOpenSSLContext *) sdPtr)	           == NS_ERROR
	|| LoadAndCheckCertificate((NsOpenSSLContext *) sdPtr)	   == NS_ERROR
	|| LoadCACerts((NsOpenSSLContext *) sdPtr)	           == NS_ERROR
        || InitSessionCache((NsOpenSSLContext *) sdPtr)            == NS_ERROR
	|| ServerInitLocation(sdPtr)	                           == NS_ERROR

    ) {
	NsServerSSLFreeDriver(sdPtr);
	return NULL;
    }

    sdPtr->timeout = ConfigIntDefault(module, sdPtr->module->configPath,
	CONFIG_SERVER_SOCKTIMEOUT, DEFAULT_SERVER_SOCKTIMEOUT);
    if (sdPtr->timeout < 1) {
	sdPtr->timeout = DEFAULT_SERVER_SOCKTIMEOUT;
    }

    sdPtr->bufsize = ConfigIntDefault(module, sdPtr->module->configPath,
	CONFIG_SERVER_BUFFERSIZE, DEFAULT_SERVER_BUFFERSIZE);
    if (sdPtr->bufsize < 1) {
	sdPtr->bufsize = DEFAULT_SERVER_BUFFERSIZE;
    }

    sdPtr->randomFile = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
                                          CONFIG_RANDOMFILE, sdPtr->module->dir, NULL);

#ifndef NS_MAJOR_VERSION
    sdPtr->driver = Ns_RegisterDriver(server, module, procs, sdPtr);
    if (sdPtr->driver == NULL) {
	NsServerSSLFreeDriver(sdPtr);
	return NULL;
    }
#endif

    return sdPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsClientSSLCreateDriver --
 *
 *       Create the Client SSL "driver".
 *
 * Results:
 *       An NsClientSSLDriver* or NULL.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

NsClientSSLDriver *
NsClientSSLCreateDriver(char *server, char *module,
			NsOpenSSLModuleData *mPtr)
{
    NsClientSSLDriver *cdPtr = NULL;

    cdPtr = (NsClientSSLDriver *) ns_calloc(1, sizeof *cdPtr);

    Ns_MutexSetName(&cdPtr->lock, "client");

    cdPtr->module = mPtr;
    Ns_MutexLock(&mPtr->lock);
    cdPtr->module->refcnt++;
    Ns_MutexUnlock(&mPtr->lock);

    cdPtr->type = (char *) ns_calloc(1, sizeof CLIENT_STRING);
    strcpy(cdPtr->type, CLIENT_STRING);
    cdPtr->refcnt = 1;
    cdPtr->lsock = INVALID_SOCKET;

    cdPtr->certfile = ConfigPathDefault(cdPtr->module->name, cdPtr->module->configPath,
			  CONFIG_CLIENT_CERTFILE, cdPtr->module->dir, DEFAULT_CLIENT_CERTFILE);

    cdPtr->keyfile =  ConfigPathDefault(cdPtr->module->name, cdPtr->module->configPath,
			  CONFIG_CLIENT_KEYFILE, cdPtr->module->dir, DEFAULT_CLIENT_KEYFILE);

    cdPtr->protocols = ConfigStringDefault(cdPtr->module->name, cdPtr->module->configPath,
                          CONFIG_CLIENT_PROTOCOLS, DEFAULT_PROTOCOLS);

    cdPtr->cipherSuite = ConfigStringDefault(cdPtr->module->name, cdPtr->module->configPath,
                          CONFIG_CLIENT_CIPHERSUITE, DEFAULT_CIPHERSUITE);

    cdPtr->cafile = ConfigPathDefault(cdPtr->module->name, cdPtr->module->configPath,
			  CONFIG_CLIENT_CAFILE, cdPtr->module->dir, DEFAULT_CLIENT_CAFILE);

    cdPtr->cadir = ConfigPathDefault(cdPtr->module->name, cdPtr->module->configPath,
			  CONFIG_CLIENT_CADIR, cdPtr->module->dir, DEFAULT_CLIENT_CADIR);

    cdPtr->cacheEnabled = ConfigBoolDefault(cdPtr->module->name, cdPtr->module->configPath,
                          CONFIG_CLIENT_SESSIONCACHE, DEFAULT_CLIENT_SESSIONCACHE);

    cdPtr->cacheSize = ConfigIntDefault(cdPtr->module->name, cdPtr->module->configPath,
			  CONFIG_CLIENT_SESSIONCACHESIZE, DEFAULT_CLIENT_SESSIONCACHESIZE);

    cdPtr->cacheTimeout = (long) ConfigIntDefault(cdPtr->module->name, cdPtr->module->configPath,
			  CONFIG_CLIENT_SESSIONTIMEOUT, DEFAULT_CLIENT_SESSIONTIMEOUT);

    if (
	   ClientMakeContext(cdPtr)                                == NS_ERROR
	|| SetProtocols((NsOpenSSLContext *) cdPtr)                == NS_ERROR
	|| SetCipherSuite((NsOpenSSLContext *) cdPtr)              == NS_ERROR
	|| LoadAndCheckCertificate((NsOpenSSLContext *) cdPtr)	   == NS_ERROR
        || LoadCACerts((NsOpenSSLContext *) cdPtr)                 == NS_ERROR
        || InitSessionCache((NsOpenSSLContext *) cdPtr)            == NS_ERROR

    ) {
	NsClientSSLFreeDriver(cdPtr);
	return NULL;
    }

    cdPtr->timeout = ConfigIntDefault(module, cdPtr->module->configPath,
	CONFIG_CLIENT_SOCKTIMEOUT, DEFAULT_CLIENT_SOCKTIMEOUT);
    if (cdPtr->timeout < 1) {
	cdPtr->timeout = DEFAULT_CLIENT_SOCKTIMEOUT;
    }

    cdPtr->bufsize = ConfigIntDefault(module, cdPtr->module->configPath,
	CONFIG_CLIENT_BUFFERSIZE, DEFAULT_CLIENT_BUFFERSIZE);
    if (cdPtr->bufsize < 1) {
	cdPtr->bufsize = DEFAULT_CLIENT_BUFFERSIZE;
    }

    /* XXX this should probably be moved to a common init function */
    cdPtr->randomFile = ConfigPathDefault(cdPtr->module->name, 
			    cdPtr->module->configPath, CONFIG_RANDOMFILE,
			    cdPtr->module->dir, NULL);

    return cdPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLFreeDriver --
 *
 *      Destroy an NsServerSSLDriver.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

/* XXX validate that this really is freeing up all parts of the structure */
void
NsServerSSLFreeDriver(NsServerSSLDriver *sdPtr)
{
    NsServerSSLConnection *scPtr;

    Ns_Log(Debug, "%s: freeing(%p)",
	sdPtr == NULL ? DRIVER_NAME : sdPtr->module->name, sdPtr);

    if (sdPtr != NULL) {
	while ((scPtr = sdPtr->firstFreePtr) != NULL) {
	    sdPtr->firstFreePtr = scPtr->nextPtr;
            /* XXX shouldn't this be freeing scPtr piece by piece? */
	    ns_free(scPtr);
	}
	Ns_MutexDestroy(&sdPtr->lock);
	if (sdPtr->module != NULL) {
	    sdPtr->module->refcnt--;
	    if (sdPtr->module->refcnt == 0) {
		NsOpenSSLModuleDataFree(sdPtr->module);
	    }
	}
	if (sdPtr->certfile  != NULL)      ns_free(sdPtr->certfile);
	if (sdPtr->keyfile  != NULL)       ns_free(sdPtr->keyfile);
	if (sdPtr->cafile  != NULL)        ns_free(sdPtr->cafile);
	if (sdPtr->cadir  != NULL)         ns_free(sdPtr->cadir);
	if (sdPtr->type  != NULL)          ns_free(sdPtr->type);
	if (sdPtr->context  != NULL)  SSL_CTX_free(sdPtr->context);
	if (sdPtr->address  != NULL)       ns_free(sdPtr->address);
	if (sdPtr->location != NULL)       ns_free(sdPtr->location);
	ns_free(sdPtr);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * NsClientSSLFreeDriver --
 *
 *      Destroy an NsClientSSLDriver.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
/* XXX validate that this really is freeing up all parts of the structure */
void
NsClientSSLFreeDriver(NsClientSSLDriver *cdPtr)
{
    NsClientSSLConnection *ccPtr;

    Ns_Log(Debug, "%s: freeing(%p)",
	cdPtr == NULL ? DRIVER_NAME : cdPtr->module->name, cdPtr);

    if (cdPtr != NULL) {
	while ((ccPtr = cdPtr->firstFreePtr) != NULL) {
	    cdPtr->firstFreePtr = ccPtr->nextPtr;
	    ns_free(ccPtr);
	}
	Ns_MutexDestroy(&cdPtr->lock);
	if (cdPtr->module != NULL) {
	    cdPtr->module->refcnt--;
	    if (cdPtr->module->refcnt == 0) {
		NsOpenSSLModuleDataFree(cdPtr->module);
	    }
	}
	if (cdPtr->certfile  != NULL)      ns_free(cdPtr->certfile);
	if (cdPtr->keyfile  != NULL)       ns_free(cdPtr->keyfile);
	if (cdPtr->cafile  != NULL)        ns_free(cdPtr->cafile);
	if (cdPtr->cadir  != NULL)         ns_free(cdPtr->cadir);
	if (cdPtr->type  != NULL)          ns_free(cdPtr->type);
	if (cdPtr->context  != NULL)  SSL_CTX_free(cdPtr->context);
	if (cdPtr->address  != NULL)       ns_free(cdPtr->address);
	if (cdPtr->location != NULL)       ns_free(cdPtr->location);
	ns_free(cdPtr);
    }
}



/*
 *----------------------------------------------------------------------
 *
 * InitializeSSL --
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
InitializeSSL(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_library_init();
    X509V3_add_standard_extensions();

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * MakeModuleDir --
 *
 *       Set *dirp to the absolute path of the module's
 *       directory. This is actually called twice if both server and
 *       client are enabled.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       May create the directory on disk.
 *
 *---------------------------------------------------------------------- */

static int
MakeModuleDir(char *server, char *module, char **dirp)
{
    Ns_DString ds;

    Ns_DStringInit(&ds);
    Ns_ModulePath(&ds, server, module, NULL, NULL);
    *dirp = Ns_DStringExport(&ds);

    if (mkdir(*dirp, 0755) != 0 && errno != EEXIST) {
	Ns_Log(Error, "mkdir(%s) failed: %s", *dirp, strerror(errno));
	ns_free(*dirp);
	*dirp = NULL;
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerMakeContext --
 *
 *       Create a new SSL context for the specified SSLDriver.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Sets sdPtr->context.
 *
 *----------------------------------------------------------------------
 */

static int
ServerMakeContext(NsServerSSLDriver *sdPtr)
{
    sdPtr->context = SSL_CTX_new(SSLv23_server_method());
    if (sdPtr->context == NULL) {
	Ns_Log(Error, "%s: error creating %s SSL context", sdPtr->module->name,
	       sdPtr->type);
	return NS_ERROR;
    }

    /* Enable SSL bug compatibility. */
    SSL_CTX_set_options(sdPtr->context, SSL_OP_ALL);

    /* This apparently prevents some sort of DH attack. */
    SSL_CTX_set_options(sdPtr->context, SSL_OP_SINGLE_DH_USE);

    SSL_CTX_set_app_data(sdPtr->context, sdPtr);

    /* Temporary key callback required for 40-bit export browsers */
    SSL_CTX_set_tmp_rsa_callback(sdPtr->context, IssueTmpRSAKey);

    if (ConfigBoolDefault(sdPtr->module->name, sdPtr->module->configPath,
	    CONFIG_SERVER_VERIFIES_PEER, DEFAULT_SERVER_VERIFIES_PEER)) {
	SSL_CTX_set_verify(sdPtr->context, SSL_VERIFY_PEER,
	    ServerVerifyClientCallback);
    }

    if (ConfigBoolDefault(sdPtr->module->name, sdPtr->module->configPath,
	    CONFIG_SERVER_TRACE, DEFAULT_SERVER_TRACE)) {
	SSL_CTX_set_info_callback(sdPtr->context, NsServerSSLTrace);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ClientMakeContext --
 *
 *       Create a new Client SSL context for the specified SSLDriver.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Sets cdPtr->context.
 *
 *----------------------------------------------------------------------
 */

static int
ClientMakeContext(NsClientSSLDriver *cdPtr)
{
    cdPtr->context = SSL_CTX_new(SSLv23_client_method());
    if (cdPtr->context == NULL) {
	Ns_Log(Error, "%s: error creating client SSL context", cdPtr->module->name);
	return NS_ERROR;
    }

    /* Enable SSL bug compatibility. */
    SSL_CTX_set_options(cdPtr->context, SSL_OP_ALL);

    SSL_CTX_set_app_data(cdPtr->context, cdPtr);

    if (ConfigBoolDefault(cdPtr->module->name, cdPtr->module->configPath,
	    CONFIG_CLIENT_VERIFIES_PEER, DEFAULT_CLIENT_VERIFIES_PEER)) {
	SSL_CTX_set_verify(cdPtr->context, SSL_VERIFY_PEER,
	    ClientVerifyServerCallback);
    }

    if (ConfigBoolDefault(cdPtr->module->name, cdPtr->module->configPath,
	    CONFIG_CLIENT_TRACE, DEFAULT_CLIENT_TRACE)) {
	SSL_CTX_set_info_callback(cdPtr->context, NsClientSSLTrace);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SetCipherSuite --
 *
 *       Set the cipher suite to be used by the client or server
 *       according to the config file.
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
SetCipherSuite(NsOpenSSLContext *pdPtr)
{
    int rc;

    rc = SSL_CTX_set_cipher_list(pdPtr->context, pdPtr->cipherSuite);

    if (rc == 0) {
	Ns_Log(Error, "%s: error configuring %s cipher suite to \"%s\"",
	    pdPtr->module->name, pdPtr->type, pdPtr->type, pdPtr->cipherSuite);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SetProtocols --
 *
 *       Set the list of protocols that the client or server will
 *       use.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       Sets pdPtr->protocols.
 *
 *----------------------------------------------------------------------
 */

static int
SetProtocols(NsOpenSSLContext *pdPtr)
{
    char   *protocols;
    int     bits;

    bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

    protocols = ns_strdup(pdPtr->protocols);
    protocols = Ns_StrToLower(protocols);

    if (strstr(protocols, "all") != NULL) {

	Ns_Log(Notice, "%s: using all %s protocols SSLv2, SSLv3 and TLSv1",
	       pdPtr->module->name, pdPtr->type);
	bits = 1;

    } else {
	
	if (strstr(protocols, "sslv2") != NULL) {
	    Ns_Log(Notice, "%s: using %s protocol SSLv2",
		   pdPtr->module->name, pdPtr->type);
	    bits &= ~SSL_OP_NO_SSLv2;
	}
	
	if (strstr(protocols, "sslv3") != NULL) {
	    Ns_Log(Notice, "%s: using %s protocol SSLv3",
		   pdPtr->module->name, pdPtr->type);
	    bits &= ~SSL_OP_NO_SSLv3;
	}
	
	if (strstr(protocols, "tlsv1") != NULL) {
	    Ns_Log(Notice, "%s: using %s protocol TLSv1",
		   pdPtr->module->name, pdPtr->type);
	    bits &= ~SSL_OP_NO_TLSv1;
	}
    }
    
    SSL_CTX_set_options(pdPtr->context, bits);

    ns_free(protocols);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * InitSessionCache --
 *
 *       Initialize the session cache for the SSL client or server as
 *       specified in the config. This is an internal OpenSSL cache,
 *       so we don't do anything other than set a timeout and size.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

int
InitSessionCache(NsOpenSSLContext *pdPtr)
{
    if (pdPtr->cacheEnabled) {

	if (STREQ(pdPtr->type, SERVER_STRING)) {

	    SSL_CTX_set_session_cache_mode(pdPtr->context,
		SSL_SESS_CACHE_SERVER);

	    SSL_CTX_set_session_id_context(pdPtr->context,
                (void *) &s_server_session_id_context,
                sizeof(s_server_session_id_context));

	} else {

	    SSL_CTX_set_session_cache_mode(pdPtr->context,
		SSL_SESS_CACHE_CLIENT);

	    SSL_CTX_set_session_id_context(pdPtr->context,
                (void *) &s_client_session_id_context,
                sizeof(s_client_session_id_context));

	}

	SSL_CTX_set_timeout(pdPtr->context, pdPtr->cacheTimeout);

	SSL_CTX_sess_set_cache_size(pdPtr->context, pdPtr->cacheSize);

    } else {

	SSL_CTX_set_session_cache_mode(pdPtr->context, SSL_SESS_CACHE_OFF);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadAndCheckCertificate --
 *
 *       This is a wrapper that follows the same process as the server
 *       when loading its certificate, but since the client
 *       certificate is optional, we want add that logic outside of
 *       LoadCertificate, LoadKey, and CheckKey.
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
LoadAndCheckCertificate(NsOpenSSLContext *pdPtr)
{
    if (pdPtr->certfile == NULL) {

	if (STREQ(pdPtr->type, SERVER_STRING)) {
	    Ns_Log(Error, "%s: a server certificate is mandatory but is not set",
		   pdPtr->module->name);
	    return NS_ERROR;
	} else {
	    Ns_Log(Notice, "%s: not using a client certificate since one is not set",
		   pdPtr->module->name);
	    return NS_OK;
	}
    }

    if (
	    LoadCertificate(pdPtr)    == NS_ERROR
         || LoadKey(pdPtr)            == NS_ERROR
         || CheckKey(pdPtr)           == NS_ERROR
    ) {
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadCertificate --
 *
 *       Load the certificate for the SSL client or server from the file
 *       specified in the server config. Also loads a certificate
 *       chain that follows the certificate in the same file. To use a
 *       cert chain, simply append the CA certs to the end of your
 *       certificate file and they'll be passed to the client at
 *       connection time. If no certs are appended, no cert chain will
 *       be passed to the client.
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
LoadCertificate(NsOpenSSLContext *pdPtr)
{
    int rc;

    /* XXX can't i just put this in an if statement? */

    rc = SSL_CTX_use_certificate_chain_file(pdPtr->context, pdPtr->certfile);
#if 0    
    rc = SSL_CTX_use_certificate_file(pdPtr->context, pdPtr->certfile, SSL_FILETYPE_PEM);
#endif

    if (rc == 0) {
	Ns_Log(Error, "%s: error loading %s certificate file \"%s\"",
	    pdPtr->module->name, pdPtr->type, pdPtr->certfile);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadKey --
 *
 *       Load the private key for the SSL client or server from the
 *       file specified in the server config.
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
LoadKey(NsOpenSSLContext *pdPtr)
{
    int rc;

    /* XXX do i need rc anymore, since there's nothing to free ? */

    rc = SSL_CTX_use_PrivateKey_file(pdPtr->context, pdPtr->keyfile, SSL_FILETYPE_PEM);

    if (rc == 0) {
	Ns_Log(Error, "%s: error loading %s private key file \"%s\"",
	    pdPtr->module->name, pdPtr->type, pdPtr->keyfile);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * CheckKey --
 *
 *       Make sure that the private key for the SSL client or server
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
CheckKey(NsOpenSSLContext *pdPtr)
{
    if (SSL_CTX_check_private_key(pdPtr->context) == 0) {
	Ns_Log(Error, "%s: %s private key does not match certificate",
	    pdPtr->module->name, pdPtr->type);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadCACerts --
 *
 *       Load the CA certificates for the SSL client or server from
 *       the file and/or dir specified in the config.  Not an error if
 *       there are no CA certificates.
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
LoadCACerts(NsOpenSSLContext *pdPtr)
{
    int status;
    int rc;
    int fd;
    DIR *dd;

    status = NS_OK;

    fd = open(pdPtr->cafile, O_RDONLY);
    if (fd < 0) {
	if (errno == ENOENT) {
	    Ns_Log(Notice, "%s: %s CA certificate file does not exist",
		pdPtr->module->name, pdPtr->type);
	} else {
	    Ns_Log(Error, "%s: error opening %s CA certificate file",
		pdPtr->module->name, pdPtr->type);
	    status = NS_ERROR;
	}
    }

    else {
	close(fd);
    }

    dd = opendir(pdPtr->cadir);
    if (dd == NULL) {
	if (errno == ENOENT) {
	    Ns_Log(Notice, "%s: %s CA certificate directory does not exist",
		pdPtr->module->name, pdPtr->type);
	} else {
	    Ns_Log(Error, "%s: error opening %s CA certificate directory",
		pdPtr->module->name, pdPtr->type);
	    status = NS_ERROR;
	}

    }

    else {
	closedir(dd);
    }

    if (status == NS_OK && (pdPtr->cafile != NULL || pdPtr->cadir != NULL)) {
	rc = SSL_CTX_load_verify_locations(pdPtr->context, pdPtr->cafile, pdPtr->cadir);

	if (rc == 0) {
	    Ns_Log(Error, "%s: error loading %s CA certificates",
		pdPtr->module->name, pdPtr->type);
	    status = NS_ERROR;
	}
    }

    return status;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerInitLocation --
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
ServerInitLocation(NsServerSSLDriver *sdPtr)
{
    /* XXX check these decls -- are these not set yet? They should already be in sdPtr
     * XXX If so, clean up this routine */
    char       *module = sdPtr->module->name;
    char       *path = sdPtr->module->configPath;
    char       *hostname;
    char       *lookupHostname;
    Ns_DString  ds;

    sdPtr->bindaddr = ConfigStringDefault(module, path, "address",
	NULL);
    hostname = ConfigStringDefault(module, path, "hostname", NULL);

    if (sdPtr->bindaddr == NULL) {
	lookupHostname = (hostname != NULL) ? hostname : Ns_InfoHostname();

	Ns_DStringInit(&ds);
	if (Ns_GetAddrByHost(&ds, lookupHostname) == NS_ERROR) {
	    Ns_Log(Error, "%s: failed to resolve '%s': %s",
		module, lookupHostname, strerror(errno));
	    return NS_ERROR;
	}

	sdPtr->address = Ns_DStringExport(&ds);
    } else {
	sdPtr->address = ns_strdup(sdPtr->bindaddr);
    }

    if (hostname == NULL) {
	Ns_DStringInit(&ds);
	if (Ns_GetHostByAddr(&ds, sdPtr->address) == NS_ERROR) {
	    Ns_Log(Warning, "%s: failed to reverse resolve '%s': %s",
		module, sdPtr->address, strerror(errno));
	    hostname = ns_strdup(sdPtr->address);
	} else {
	    hostname = Ns_DStringExport(&ds);
	}
    }

    sdPtr->port = ConfigIntDefault(module, path, "port", DEFAULT_PORT);

    sdPtr->location = ConfigStringDefault(module, path, "location", NULL);
    if (sdPtr->location != NULL) {
	sdPtr->location = ns_strdup(sdPtr->location);
    } else {
        Ns_DStringInit(&ds);
	Ns_DStringVarAppend(&ds, DEFAULT_PROTOCOL "://", hostname, NULL);
	if (sdPtr->port != DEFAULT_PORT) {
	    Ns_DStringPrintf(&ds, ":%d", sdPtr->port);
	}
	sdPtr->location = Ns_DStringExport(&ds);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerVerifyClientCallback --
 *
 *	Called by the SSL library at each stage of client certificate
 *	verification.
 *
 * Results:
 *
 *	Always returns 1 to prevent verification errors from halting
 *      the SSL handshake.  We'd rather finish the handshake so we
 *      can either authenticate by other means or return an HTTP error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
ServerVerifyClientCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * ClientVerifyServerCallback --
 *
 *	Called by the SSL library at each stage of server certificate
 *	verification.
 *
 * Results:
 *
 *	Always returns 1 to prevent verification errors from halting
 *      the SSL handshake.  We'd rather finish the handshake so we
 *      can either authenticate by other means or return an HTTP error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
ClientVerifyServerCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return 1;
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

int
SeedPRNG(NsServerSSLDriver *sdPtr)
{
    int i;
    double *buf_ptr = NULL;
    double *bufoffset_ptr = NULL;
    size_t size;
    char *file;
    int seedbytes;

    if (PRNGIsSeeded(sdPtr)) {
        Ns_Log(Debug, "%s: PRNG already has enough entropy", sdPtr->module->name); 
        return NS_TRUE;
    }

    Ns_Log(Notice, "%s: Seeding the PRNG", sdPtr->module->name); 

    seedbytes = ConfigIntDefault(sdPtr->module->name, sdPtr->module->configPath,
	CONFIG_SEEDBYTES, DEFAULT_SEEDBYTES);

    /* The user configured a file to use; try that first */
    if (AddEntropyFromRandomFile(sdPtr, seedbytes) != NS_OK) {
        Ns_Log(Warning, "%s: %s parameter set, but can't access file %s",
                        sdPtr->module->name, CONFIG_RANDOMFILE, file);
    }

    if (PRNGIsSeeded(sdPtr)) {
        return NS_TRUE;
    }

    /* Use Ns API; I have no idea how to measure the amount of entropy, */
    /* so for now I just pass the same number as the 2nd arg to RAND_add */
    /* Also know that not all of the buffer is used */
    size = sizeof(double) * seedbytes;
    buf_ptr = Ns_Malloc(size); 
    bufoffset_ptr = buf_ptr;
    for (i = 0; i < seedbytes; i++) {
        *bufoffset_ptr = Ns_DRand();
        bufoffset_ptr++;
    }
    RAND_add(buf_ptr, seedbytes, (long) seedbytes);
    Ns_Free(buf_ptr);
    Ns_Log(Notice, "%s: Seeded PRNG with %d bytes from Ns_DRand",
                    sdPtr->module->name, seedbytes); 

    if (PRNGIsSeeded(sdPtr)) {
        return NS_TRUE;
    }

    Ns_Log(Warning, "%s: Failed to seed PRNG with enough entropy",
                     sdPtr->module->name); 
    return NS_FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * PRNGIsSeeded --
 *
 *       See if the PRNG contains enough entropy.
 *
 * Results:
 *       NS_TRUE or NS_FALSE
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

int
PRNGIsSeeded (NsServerSSLDriver *sdPtr)
{
    if (RAND_status()) {              
        Ns_Log(Debug, "%s: RAND_status reports sufficient entropy for the PRNG",
                       sdPtr->module->name);
        return NS_TRUE;                                                           
    }             
    
    /* Assume we don't have enough */  
    return NS_FALSE;
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
IssueTmpRSAKey(SSL *ssl, int export, int keylen)
{
    NsServerSSLConnection *scPtr;
    NsServerSSLDriver     *sdPtr;
    static RSA *rsa_tmp = NULL;

    scPtr = (NsServerSSLConnection*) SSL_get_app_data(ssl);
    sdPtr = scPtr->sdPtr;

    if (SeedPRNG(sdPtr)) {
        rsa_tmp = RSA_generate_key(keylen, RSA_F4, NULL, NULL);
        Ns_Log(Notice, "%s: Generated %d-bit temporary RSA key",
                        sdPtr->module->name, keylen);
        return rsa_tmp;
    } else {
        Ns_Log(Warning, 
               "%s: Cannot generate temporary RSA key due to insufficient entropy in PRNG",
               sdPtr->module->name);
        return NULL; 
    }
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
AddEntropyFromRandomFile(NsServerSSLDriver *sdPtr, long maxbytes) {
    int readbytes;

    if (access(sdPtr->randomFile, F_OK) == 0) {
        if ((readbytes = RAND_load_file(sdPtr->randomFile, maxbytes))) {
            Ns_Log(Debug, "%s: Obtained %d random bytes from %s", 
                           sdPtr->module->name, readbytes, sdPtr->randomFile);
            return NS_OK;
        } else {
            Ns_Log(Warning, "%s: Unable to retrieve any random data from %s",
                             sdPtr->module->name, sdPtr->randomFile);
            return NS_FALSE;
        }
    }
    return NS_FALSE;
}
