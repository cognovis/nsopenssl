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
 * Copyright (C) 1999 Stefan Arentz.
 * Copyright (C) 2000 Scott S. Goodwin
 * Copyright (C) 2000 Rob Mayoff
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
#include "cache.h"
#include "thread.h"



static int InitializeSSL(void);
static int MakeModuleDir(char *server, char *module, char **dirp);
static int MakeSSLContext(NsOpenSSLDriver *sdPtr);
static int SetCipherSuite(NsOpenSSLDriver *sdPtr);
static int SetProtocols(NsOpenSSLDriver *sdPtr);
static int LoadCertificate(NsOpenSSLDriver *sdPtr);
static int LoadKey(NsOpenSSLDriver *sdPtr);
static int CheckKey(NsOpenSSLDriver *sdPtr);
static int LoadCACerts(NsOpenSSLDriver *sdPtr);
static int InitSessionCache(NsOpenSSLDriver *sdPtr);
static int InitLocation(NsOpenSSLDriver *sdPtr);
static int ClientVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);



/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLCreateDriver --
 *
 *       Create the SSL driver.
 *
 * Results:
 *       An NsOpenSSLDriver* or NULL.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLDriver *
NsOpenSSLCreateDriver(char *server, char *module, Ns_DrvProc *procs)
{
    NsOpenSSLDriver *sdPtr = NULL;

    sdPtr = (NsOpenSSLDriver *) ns_calloc(1, sizeof *sdPtr);

    Ns_MutexSetName(&sdPtr->lock, module);
    sdPtr->module = module;
    sdPtr->refcnt = 1;
    sdPtr->lsock = INVALID_SOCKET;
    sdPtr->configPath = Ns_ConfigGetPath(server, module, NULL);

    if (
	   NsOpenSSLInitThreads()                      == NS_ERROR
	|| InitializeSSL()                             == NS_ERROR
	|| MakeSSLContext(sdPtr)                       == NS_ERROR
	|| MakeModuleDir(server, module, &sdPtr->dir)  == NS_ERROR
	|| SetProtocols(sdPtr)                         == NS_ERROR
	|| SetCipherSuite(sdPtr)                       == NS_ERROR
	|| LoadCertificate(sdPtr)                      == NS_ERROR
	|| LoadKey(sdPtr)                              == NS_ERROR
	|| CheckKey(sdPtr)                             == NS_ERROR
	|| LoadCACerts(sdPtr)                          == NS_ERROR
	|| NsOpenSSLInitSessionCache(sdPtr)            == NS_ERROR
	|| InitLocation(sdPtr)                         == NS_ERROR
    ) {
	NsOpenSSLFreeDriver(sdPtr);
	return NULL;
    }

    sdPtr->timeout = ConfigIntDefault(module, sdPtr->configPath,
	CONFIG_SOCKTIMEOUT, DEFAULT_SOCKTIMEOUT);
    if (sdPtr->timeout < 1) {
	sdPtr->timeout = DEFAULT_SOCKTIMEOUT;
    }

    sdPtr->bufsize = ConfigIntDefault(module, sdPtr->configPath,
	CONFIG_BUFFERSIZE, DEFAULT_BUFFERSIZE);
    if (sdPtr->bufsize < 1) {
	sdPtr->bufsize = DEFAULT_BUFFERSIZE;
    }

    sdPtr->driver = Ns_RegisterDriver(server, module, procs, sdPtr);
    if (sdPtr->driver == NULL) {
	NsOpenSSLFreeDriver(sdPtr);
	return NULL;
    }

    return sdPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLFreeDriver --
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

void
NsOpenSSLFreeDriver(NsOpenSSLDriver *sdPtr)
{
    NsOpenSSLConnection *scPtr;

    Ns_Log(Debug, "%s: freeing(%p)",
	sdPtr == NULL ? DRIVER_NAME : sdPtr->module, sdPtr);

    if (sdPtr != NULL) {
	while ((scPtr = sdPtr->firstFreePtr) != NULL) {
	    sdPtr->firstFreePtr = scPtr->nextPtr;
	    ns_free(scPtr);
	}
	Ns_MutexDestroy(&sdPtr->lock);
	if (sdPtr->context  != NULL) SSL_CTX_free(sdPtr->context);
	if (sdPtr->dir      != NULL)      ns_free(sdPtr->dir);
	if (sdPtr->address  != NULL)      ns_free(sdPtr->address);
	if (sdPtr->location != NULL)      ns_free(sdPtr->location);
	ns_free(sdPtr);
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
    SSLeay_add_ssl_algorithms();
    SSL_library_init();
    X509V3_add_standard_extensions();

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * MakeModuleDir --
 *
 *       Set *dirp to the absolute path of the module's directory.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       May create the directory on disk.
 *
 *----------------------------------------------------------------------
 */

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
 * MakeSSLContext --
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
MakeSSLContext(NsOpenSSLDriver *sdPtr)
{
    sdPtr->context = SSL_CTX_new(SSLv23_server_method());
    if (sdPtr->context == NULL) {
	Ns_Log(Error, "%s: error creating SSL context", sdPtr->module);
	return NS_ERROR;
    }

    /* Enable SSL bug compatibility. */
    SSL_CTX_set_options(sdPtr->context, SSL_OP_ALL);

    /* This apparently prevents some sort of DH attack. */
    SSL_CTX_set_options(sdPtr->context, SSL_OP_SINGLE_DH_USE);

    SSL_CTX_set_app_data(sdPtr->context, sdPtr);

    if (ConfigBoolDefault(sdPtr->module, sdPtr->configPath,
	    CONFIG_CLIENTVERIFY, DEFAULT_CLIENTVERIFY)) {
	SSL_CTX_set_verify(sdPtr->context, SSL_VERIFY_PEER,
	    ClientVerifyCallback);
    }

    if (ConfigBoolDefault(sdPtr->module, sdPtr->configPath,
	    CONFIG_TRACE, DEFAULT_TRACE)) {
	SSL_CTX_set_info_callback(sdPtr->context, NsOpenSSLTrace);
    }

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
SetCipherSuite(NsOpenSSLDriver *sdPtr)
{
    int rc;
    char *value = ConfigStringDefault(sdPtr->module, sdPtr->configPath,
	CONFIG_CIPHERSUITE, DEFAULT_CIPHERSUITE);

    rc = SSL_CTX_set_cipher_list(sdPtr->context, value);

    if (rc == 0) {
	Ns_Log(Error, "%s: error configuring cipher suite to \"%s\"",
	    sdPtr->module, value);
	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SetProtocols --
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
SetProtocols(NsOpenSSLDriver *sdPtr)
{
    Ns_Set *config;
    int     i, j, l;
    char   *value;
    int     bits;
    int     foundConfig;

    foundConfig = 0;
    bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;

    config = Ns_ConfigGetSection(sdPtr->configPath);
    if (config != NULL) {
	for (i = 0, l = Ns_SetSize(config); i < l; i++) {
	    if (!STRIEQ(Ns_SetKey(config, i), "Protocol")) {
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
		    sdPtr->module, value);
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
 * LoadCertificate --
 *
 *       Load the certificate for the SSL server from the file
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
LoadCertificate(NsOpenSSLDriver *sdPtr)
{
    int rc;
    char *file = ConfigPathDefault(sdPtr->module, sdPtr->configPath,
	CONFIG_CERTFILE, sdPtr->dir, DEFAULT_CERTFILE);

    rc = SSL_CTX_use_certificate_file(sdPtr->context, file, SSL_FILETYPE_PEM);

    if (rc == 0) {
	Ns_Log(Error, "%s: error loading certificate file \"%s\"",
	    sdPtr->module, file);
    }

    ns_free(file);
    return (rc == 0) ? NS_ERROR : NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LoadKey --
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
LoadKey(NsOpenSSLDriver *sdPtr)
{
    int rc;
    char *file = ConfigPathDefault(sdPtr->module, sdPtr->configPath,
	CONFIG_KEYFILE, sdPtr->dir, DEFAULT_KEYFILE);

    rc = SSL_CTX_use_PrivateKey_file(sdPtr->context, file, SSL_FILETYPE_PEM);

    if (rc == 0) {
	Ns_Log(Error, "%s: error loading private key file \"%s\"",
	    sdPtr->module, file);
    }

    ns_free(file);
    return (rc == 0) ? NS_ERROR : NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * CheckKey --
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
CheckKey(NsOpenSSLDriver *sdPtr)
{
    if (SSL_CTX_check_private_key(sdPtr->context) == 0) {
	Ns_Log(Error, "%s: private key does not match certificate",
	    sdPtr->module);
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
LoadCACerts(NsOpenSSLDriver *sdPtr)
{
    int status;
    int rc;
    int fd;
    DIR *dd;
    char *file;
    char *dir;

    status = NS_OK;

    file = ConfigPathDefault(sdPtr->module, sdPtr->configPath,
	CONFIG_CAFILE, sdPtr->dir, DEFAULT_CAFILE);

    fd = open(file, O_RDONLY);
    if (fd < 0) {
	if (errno == ENOENT) {
	    Ns_Log(Notice, "%s: CA certificate file does not exist",
		sdPtr->module);
	} else {
	    Ns_Log(Error, "%s: error opening CA certificate file",
		sdPtr->module);
	    status = NS_ERROR;
	}
	ns_free(file);
	file = NULL;
    }

    else {
	close(fd);
    }

    dir = ConfigPathDefault(sdPtr->module, sdPtr->configPath,
	CONFIG_CADIR, sdPtr->dir, DEFAULT_CADIR);

    dd = opendir(dir);
    if (dd == NULL) {
	if (errno == ENOENT) {
	    Ns_Log(Notice, "%s: CA certificate directory does not exist",
		sdPtr->module);
	} else {
	    Ns_Log(Error, "%s: error opening CA certificate directory",
		sdPtr->module);
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
		sdPtr->module);
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
InitLocation(NsOpenSSLDriver *sdPtr)
{
    char       *module = sdPtr->module;
    char       *path = sdPtr->configPath;
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
 * ClienVerifyCallback --
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
ClientVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return 1;
}

