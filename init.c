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


static int InitializeSSL(void);
static int MakeModuleDir(char *server, char *module, char **dirp);

/*
 * SSL Server Functions
 */

static int ServerMakeContext(NsServerSSLDriver *sdPtr);
static int ServerSetCipherSuite(NsServerSSLDriver *sdPtr);
static int ServerSetProtocols(NsServerSSLDriver *sdPtr);
static int ServerLoadCertificate(NsServerSSLDriver *sdPtr);
static int ServerLoadKey(NsServerSSLDriver *sdPtr);
static int ServerCheckKey(NsServerSSLDriver *sdPtr);
static int ServerLoadCACerts(NsServerSSLDriver *sdPtr);
static int ServerInitLocation(NsServerSSLDriver *sdPtr);
static int ServerVerifyClientCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
static int ServerInitSessionCache(NsServerSSLDriver *sdPtr);
/* What happens if we run multiple copies of nsopenssl in the same server? */
static int s_server_session_id_context = 1;

/*
 * SSL Client Functions
 */

static int ClientMakeContext(NsClientSSLDriver *cdPtr);
#if 0
static int ClientSetCipherSuite(NsClientSSLDriver *cdPtr);
static int ClientSetProtocols(NsClientSSLDriver *cdPtr);
static int ClientLoadCertificate(NsClientSSLDriver *cdPtr);
static int ClientLoadKey(NsClientSSLDriver *cdPtr);
static int ClientCheckKey(NsClientSSLDriver *cdPtr);
static int ClientLoadCACerts(NsClientSSLDriver *cdPtr);
static int ClientInitLocation(NsClientSSLDriver *cdPtr);
#endif
static int ClientVerifyServerCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
#if 0
static int ClientInitSessionCache(NsClientSSLDriver *cdPtr);
#endif
/* What happens if we run multiple copies of nsopenssl in the same server? */
static int s_client_session_id_context = 2;


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

    if (
	MakeModuleDir(server, module, &mPtr->dir)  == NS_ERROR
	) {
	if (mPtr->dir      != NULL)      ns_free(mPtr->dir);
	ns_free(mPtr);
	return NULL;
    }

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

    Ns_MutexSetName(&sdPtr->lock, module);
    sdPtr->module = mPtr;
    sdPtr->refcnt = 1;
    sdPtr->lsock = INVALID_SOCKET;
  
    if (
	   ServerMakeContext(sdPtr)                    == NS_ERROR
	|| ServerSetProtocols(sdPtr)                   == NS_ERROR
	|| ServerSetCipherSuite(sdPtr)                 == NS_ERROR
	|| ServerLoadCertificate(sdPtr)                == NS_ERROR
	|| ServerLoadKey(sdPtr)                        == NS_ERROR
	|| ServerCheckKey(sdPtr)                       == NS_ERROR
	|| ServerLoadCACerts(sdPtr)                    == NS_ERROR
	|| ServerInitSessionCache(sdPtr)               == NS_ERROR
	|| ServerInitLocation(sdPtr)                   == NS_ERROR
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

    Ns_MutexSetName(&cdPtr->lock, module);
    cdPtr->module = mPtr;
    cdPtr->refcnt = 1;
    cdPtr->lsock = INVALID_SOCKET;

    if (
	   ClientMakeContext(cdPtr)                    == NS_ERROR
#if 0
	|| ClientSetProtocols(cdPtr)                   == NS_ERROR
	|| ClientSetCipherSuite(cdPtr)                 == NS_ERROR
	|| ClientLoadCertificate(cdPtr)                == NS_ERROR
	|| ClientLoadKey(cdPtr)                        == NS_ERROR
	|| ClientCheckKey(cdPtr)                       == NS_ERROR
	|| ClientLoadCACerts(cdPtr)                    == NS_ERROR
	|| ClientInitSessionCache(cdPtr)               == NS_ERROR
	|| ClientInitLocation(cdPtr)                   == NS_ERROR
#endif
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

void
NsServerSSLFreeDriver(NsServerSSLDriver *sdPtr)
{
    NsServerSSLConnection *scPtr;

    Ns_Log(Debug, "%s: freeing(%p)",
	sdPtr == NULL ? DRIVER_NAME : sdPtr->module->name, sdPtr);

    if (sdPtr != NULL) {
	while ((scPtr = sdPtr->firstFreePtr) != NULL) {
	    sdPtr->firstFreePtr = scPtr->nextPtr;
	    ns_free(scPtr);
	}
	Ns_MutexDestroy(&sdPtr->lock);
	if (sdPtr->module   != NULL)      ns_free(sdPtr->module);
	if (sdPtr->context  != NULL) SSL_CTX_free(sdPtr->context);
	if (sdPtr->address  != NULL)      ns_free(sdPtr->address);
	if (sdPtr->location != NULL)      ns_free(sdPtr->location);
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
	if (cdPtr->module   != NULL)      ns_free(cdPtr->module);
	if (cdPtr->context  != NULL) SSL_CTX_free(cdPtr->context);
	if (cdPtr->address  != NULL)      ns_free(cdPtr->address);
	if (cdPtr->location != NULL)      ns_free(cdPtr->location);
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
	Ns_Log(Error, "%s: error creating SSL context", sdPtr->module->name);
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
 * ServerSetCipherSuite --
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
ServerSetCipherSuite(NsServerSSLDriver *sdPtr)
{
    int rc;
    char *value = ConfigStringDefault(sdPtr->module->name, sdPtr->module->configPath,
	CONFIG_SERVER_CIPHERSUITE, DEFAULT_CIPHERSUITE);

    rc = SSL_CTX_set_cipher_list(sdPtr->context, value);

    if (rc == 0) {
	Ns_Log(Error, "%s: error configuring cipher suite to \"%s\"",
	    sdPtr->module->name, value);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerSetProtocols --
 *
 *       Set the list of protocols that the driver will allow.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       Sets sdPtr->protocols.
 *
 *----------------------------------------------------------------------
 */

static struct {
    char *name;
    int bits;
} protocolMap[] = {
    { "sslv2", SSL_OP_NO_SSLv2 },
    { "sslv3", SSL_OP_NO_SSLv3 },
    { "tlsv1", SSL_OP_NO_TLSv1 },
    /* If you add another protocol, don't forget to add it to bits below. */
    { "all",   ~0              },
    { NULL, 0 }
};

static int
ServerSetProtocols(NsServerSSLDriver *sdPtr)
{
    Ns_Set *config;
    int     i, j, l;
    char   *value;
    int     bits;
    int     foundConfig;

    foundConfig = 0;
    bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

    config = Ns_ConfigGetSection(sdPtr->module->configPath);
    if (config != NULL) {
	for (i = 0, l = Ns_SetSize(config); i < l; i++) {
	    /* XXX ServerProtocol should be in config.c, not here */
	    if (!STRIEQ(Ns_SetKey(config, i), CONFIG_SERVER_PROTOCOL)) {
		continue;
	    }

	    value = Ns_SetValue(config, i);

	    for (j = 0; protocolMap[j].name != NULL; j++) {
		if (STRIEQ(value, protocolMap[j].name)) {
		    bits &= ~protocolMap[j].bits;
		    foundConfig = 1;
		    break;
		}
	    }

	    if (protocolMap[j].name == NULL) {
		Ns_Log(Error, "%s: unknown protocol \"%s\"",
		    sdPtr->module->name, value);
		return NS_ERROR;
	    }
	}
    }

    if (foundConfig) {
	SSL_CTX_set_options(sdPtr->context, bits);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerInitSessionCache --
 *
 *       Initialize the session cache for the SSL server as specified
 *       in the server config. This is an internal OpenSSL cache, so
 *       we don't do anything other than set a timeout and size.
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
ServerInitSessionCache(NsServerSSLDriver *sdPtr)
{
    int cacheEnabled = ConfigBoolDefault(sdPtr->module->name, sdPtr->module->configPath,
        CONFIG_SERVER_SESSIONCACHE, DEFAULT_SERVER_SESSIONCACHE);
    int cacheSize;
    long timeout;

    if (cacheEnabled) {

	SSL_CTX_set_session_cache_mode(sdPtr->context,
	    SSL_SESS_CACHE_SERVER);

        SSL_CTX_set_session_id_context(sdPtr->context,
            (void *) &s_server_session_id_context,
            sizeof(s_server_session_id_context));

	timeout = (long) ConfigIntDefault(sdPtr->module->name, sdPtr->module->configPath,
	    CONFIG_SERVER_SESSIONTIMEOUT, DEFAULT_SERVER_SESSIONTIMEOUT);
	SSL_CTX_set_timeout(sdPtr->context, timeout);

	cacheSize = ConfigIntDefault(sdPtr->module->name, sdPtr->module->configPath,
	    CONFIG_SERVER_SESSIONCACHESIZE, DEFAULT_SERVER_SESSIONCACHESIZE);
	SSL_CTX_sess_set_cache_size(sdPtr->context, cacheSize);

    } else {

	SSL_CTX_set_session_cache_mode(sdPtr->context, SSL_SESS_CACHE_OFF);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerLoadCertificate --
 *
 *       Load the certificate for the SSL server from the file
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
ServerLoadCertificate(NsServerSSLDriver *sdPtr)
{
    int rc;
    char *file = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
	CONFIG_SERVER_CERTFILE, sdPtr->module->dir, DEFAULT_SERVER_CERTFILE);

    rc = SSL_CTX_use_certificate_chain_file(sdPtr->context, file);
#if 0
    rc = SSL_CTX_use_certificate_file(sdPtr->context, file, SSL_FILETYPE_PEM);
#endif

    if (rc == 0) {
	Ns_Log(Error, "%s: error loading certificate file \"%s\"",
	    sdPtr->module->name, file);
    }

    ns_free(file);
    return (rc == 0) ? NS_ERROR : NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerLoadKey --
 *
 *       Load the private key for the SSL server from the file
 *       specified in the server config.
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
ServerLoadKey(NsServerSSLDriver *sdPtr)
{
    int rc;
    char *file = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
	CONFIG_SERVER_KEYFILE, sdPtr->module->dir, DEFAULT_SERVER_KEYFILE);

    rc = SSL_CTX_use_PrivateKey_file(sdPtr->context, file, SSL_FILETYPE_PEM);

    if (rc == 0) {
	Ns_Log(Error, "%s: error loading private key file \"%s\"",
	    sdPtr->module->name, file);
    }

    ns_free(file);
    return (rc == 0) ? NS_ERROR : NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerCheckKey --
 *
 *       Make sure that the private key for the SSL server matches the
 *       certificate.
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
ServerCheckKey(NsServerSSLDriver *sdPtr)
{
    if (SSL_CTX_check_private_key(sdPtr->context) == 0) {
	Ns_Log(Error, "%s: private key does not match certificate",
	    sdPtr->module->name);
	return NS_ERROR;
    }
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerLoadCACerts --
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
ServerLoadCACerts(NsServerSSLDriver *sdPtr)
{
    int status;
    int rc;
    int fd;
    DIR *dd;
    char *file;
    char *dir;

    status = NS_OK;

    file = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
	CONFIG_SERVER_CAFILE, sdPtr->module->dir, DEFAULT_SERVER_CAFILE);

    fd = open(file, O_RDONLY);
    if (fd < 0) {
	if (errno == ENOENT) {
	    Ns_Log(Notice, "%s: CA certificate file does not exist",
		sdPtr->module->name);
	} else {
	    Ns_Log(Error, "%s: error opening CA certificate file",
		sdPtr->module->name);
	    status = NS_ERROR;
	}
	ns_free(file);
	file = NULL;
    }

    else {
	close(fd);
    }

    dir = ConfigPathDefault(sdPtr->module->name, sdPtr->module->configPath,
	CONFIG_SERVER_CADIR, sdPtr->module->dir, DEFAULT_SERVER_CADIR);

    dd = opendir(dir);
    if (dd == NULL) {
	if (errno == ENOENT) {
	    Ns_Log(Notice, "%s: CA certificate directory does not exist",
		sdPtr->module->name);
	} else {
	    Ns_Log(Error, "%s: error opening CA certificate directory",
		sdPtr->module->name);
	    status = NS_ERROR;
	}

	ns_free(dir);
	dir = NULL;
    }

    else {
	closedir(dd);
    }

    if (status == NS_OK && (file != NULL || dir != NULL)) {
	rc = SSL_CTX_load_verify_locations(sdPtr->context, file, dir);

	if (rc == 0) {
	    Ns_Log(Error, "%s: error loading CA certificates",
		sdPtr->module->name);
	    status = NS_ERROR;
	}
    }

    if (file != NULL) ns_free(file);
    if (dir != NULL) ns_free(dir);

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
