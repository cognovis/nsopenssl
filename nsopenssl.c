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

/* XXX merge these into the Ns_OpenSSLContext* equivalents ... */
static int InitLocation (NsOpenSSLDriver *driver);
#if 0
static char *GetModuleDir (char *server, char *module);
#endif
static int PeerVerifyCallback (int preverify_ok, X509_STORE_CTX *x509_ctx);
static int SessionCacheIdGetNext (void);

/*
 * Session cache id management
 */

typedef struct SessionCacheId {
    Ns_Mutex lock;
    int id;
} SessionCacheId;

static SessionCacheId *nextSessionCacheId;

/*
 * Driver initialization/destruction
 */

/* XXX determine whether or not to make these static */
#if 0
static NsOpenSSLDriver *NsOpenSSLDriverCreate (char *server, char *module);
static void NsOpenSSLDriverFree (NsOpenSSLDriver *driver);
#endif

/*
 * SSL Operations on active connections
 */
 
static Ns_DriverProc OpenSSLProc;
static RSA *IssueTmpRSAKey (SSL *ssl, int export, int keylen);	

/*
 * Linked lists
 */

typedef struct OpenSSLStructs {
    Ns_OpenSSLContext  *firstSSLContextPtr;
    Ns_OpenSSLConn     *firstSSLConnPtr;
    NsOpenSSLDriver    *firstSSLDriver;
} OpenSSLStructs;

/* XXX put into above struct */
Ns_OpenSSLContext  *firstSSLContext;
Ns_OpenSSLConn     *firstSSLConn;
NsOpenSSLDriver    *firstSSLDriver;

/* XXX remove */
Ns_OpenSSLContext  *sockClientContext;
Ns_OpenSSLContext  *sockServerContext;



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
Ns_ModuleInit (char *server, char *module)
{
    DEBUG(where());
    NsOpenSSLModuleInit(server, module);
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDriverInit --
 *
 *     Initialize an SSL driver
 *
 * Results:
 *     NS_OK or NS_ERROR
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLDriverInit(char *server, char *module, NsOpenSSLDriver *driver)
{
    DEBUG(where());

    /*
     * Maintain the drivers in a single linked-list. You can find out what
     * server a particular driver serves by looking at driver->server.
     */

#if 0
    driver->next = OpenSSLStructs->firstSSLDriver;
    OpenSSLStructs->firstSSLDriver = driver;
#endif

    /*
     * Register the driver with AOLserver.
     */

    if (Ns_DriverInit (server, module, MODULE, OpenSSLProc, driver, NS_DRIVER_SSL)
		    != NS_OK) {
	    Ns_Log(Error, MODULE, ": driver for server %s failed to initialize",
		    server);
        return NS_ERROR;
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDriverCreate --
 *
 *       Create an SSL driver. There will be one driver for each virtual
 *       server/port comibination.
 *
 * Results:
 *       An NsOpenSSLDriver* or NULL.
 *
 * Side effects:
 *       Allocates memory. Adds driver to driver linked list.
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLDriver *
NsOpenSSLDriverCreate (char *server, char *module)
{
    NsOpenSSLDriver *driver = NULL;

    driver = (NsOpenSSLDriver *) ns_calloc (1, sizeof *driver);

    if (driver == NULL) {
	    Ns_Log(Error, "%s: Failed to create driver structure", module);
	    return NULL;
    }

    /* XXX check what else I need to initialize here */

    driver->server     = server;
    driver->module     = module;
    driver->configPath = Ns_ConfigGetPath(server, module, NULL);

    Ns_MutexSetName(&driver->lock, module);

    if (InitLocation(driver) == NS_ERROR) {
        Ns_Log(Error, MODULE, ": InitLocation failed");
	    NsOpenSSLDriverDestroy(driver);
	    return NULL;
    }

    /* XXX tmp shutoff */
#if 0
    /* XXX this belongs in another function */
    if (SetModuleDir (driver) == NS_ERROR || InitLocation (driver) == NS_ERROR) {
	NsOpenSSLDriverFree (driver);
	    return NULL;
    }
#endif

    return driver;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDriverDestroy --
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
NsOpenSSLDriverDestroy (NsOpenSSLDriver *driver)
{
    Ns_OpenSSLConn *conn;

    if (driver == NULL)
	    return;

    /* XXX ENSURE ALL ITEMS THAT NEED TO BE FREED ARE BEING FREED */

    /* XXX check refcnt before freeing */

    driver->server            = NULL;
    driver->module            = NULL;

    /* XXX validate... */
    driver->driver            = NULL;

    /* XXX need to walk through and free each Ns_OpenSSLConn */
    driver->next              = NULL;

    while ((conn = driver->firstFreeConn) != NULL) {
	    driver->firstFreeConn = conn->next;
	    /* XXX doesn't this need to have it's contents free'd? */
	    Ns_Free (conn);
    }

    if (driver->context != NULL) {
	    Ns_OpenSSLContextDestroy(driver->context);
        /* XXX move this op to Ns_OpenSSLContextDestroy */
	    driver->context = NULL;
    }
   
    /* driver->refcnt */

    driver->configPath        = NULL;
    driver->dir               = NULL;
    driver->location          = NULL;
    driver->address           = NULL;
    driver->bindaddr          = NULL;
    driver->lsock             = INVALID_SOCKET;
    driver->port              = -1;
    driver->refcnt            = 1;

    Ns_MutexDestroy (&driver->lock);

    Ns_Free (driver);

    return;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockConnect --
 *
 *      Open an SSL connection to the given host and port.
 *
 * Arguments:
 *      name:    The name of the SSL context to use
 *      host:    The remote hosts name or IP address
 *      port:    The port to connect to
 *      async:   If 0, leave socket in synchronous mode, otherwise async
 *      timeout: How long to wait for response from remote host
 *      
 * Results:
 *      A pointer to a new Ns_OpenSSLConn structure.
 *
 * Side effects:
 *      Runs the SSL handshake.
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLConn *
Ns_OpenSSLSockConnect (char *name, char *host, int port, int async, int timeout)
{
    Ns_OpenSSLConn *conn;
    SOCKET sock;

    if (timeout < 0) {
	    sock = Ns_SockConnect (host, port);
    } else {
	    sock = Ns_SockTimedConnect (host, port, timeout);
    }

    if (sock == INVALID_SOCKET)
	    return NULL;

    if ((conn = NsOpenSSLCreateConn(sock, firstSSLDriver, 
             ROLE_SSL_CLIENT, CONNTYPE_SOCKCLIENT)) == NULL) {
	return NULL;
    }

    /*
     * We leave the socket blocking until after the handshake.
     */

    if (async)
	Ns_SockSetNonBlocking (conn->sock);

    SSL_set_app_data (conn->ssl, conn);

    return conn;
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockAccept --
 *
 *      Accept a TCP socket, setting close on exec.
 *
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      sock: the socket id that we're accept'ing on
 *      
 * Results:
 *      A socket or INVALID_SOCKET on error.
 *
 * Side effects:
 *      The socket is always placed in non-blocking mode.
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLConn *
Ns_OpenSSLSockAccept (char *name, SOCKET sock)
{
    Ns_OpenSSLConn *conn = NULL;

    if (sock == INVALID_SOCKET)
        return NULL;

    /* XXX these args must be changed */
    if ((conn = NsOpenSSLCreateConn(sock, firstSSLDriver, 
	ROLE_SSL_SERVER, CONNTYPE_SOCKSERVER)) == NULL) {
	return NULL;
    }

    Ns_SockSetNonBlocking (conn->sock);

    SSL_set_app_data (conn->ssl, conn);

    return conn;
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockListen --
 *
 *      Listen for connections with default backlog. Just a wrapper
 *      around Ns_SockListen at the moment.
 *
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      addr: the IP address to bind to
 *      port: the port to listen on
 *
 * Results:
 *      A socket.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

SOCKET
Ns_OpenSSLSockListen (char *name, char *addr, int port)
{
    return Ns_SockListen (addr, port);
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockCallback --
 *
 *      Register a callback to be run when a socket that underlies an
 *      SSL connection reaches a certain state. The callback proc is
 *      responsible for layering SSL on top of the connected socket.
 *
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      sock: the id of the socket to listen on
 *      proc: the proc to run when a connection comes in
 *      when:
 *      
 * Results:
 *      NS_OK/NS_ERROR
 *
 * Side effects:
 *      Will wake up the callback thread.
 *
 *----------------------------------------------------------------------
 */

/* XXX unusable with a direct call except from NsTclSSLSockCallback */
/* XXX essentially, the callback proc is going to have to be reponsible */
/* XXX for layering SSL on top of the socket once a connection comes in, */
/* XXX and before the script is run. I might need a new type, Ns_OpenSSLSockProc */
/* XXX but we'll see. I may be able to create a generic way to do this */
/* XXX so the developer using the API won't have to */

int
Ns_OpenSSLSockCallback (char *name, SOCKET sock, Ns_SockProc *proc, void *arg, int when)
{
	/* XXX need to handle SSL wrapping here somehow... */
	return Ns_SockCallback (sock, proc, arg, when);
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLSockListenCallback --
 *
 *      Listen on an address/port that underlies an SSL connection and
 *      register a callback to be run when connections come in on it.
 *
 * Arguments:
 *      name: the name of the SSL context to use for this connection
 *      addr: the IP address to listen on
 *      port: the port to listen on
 *      proc: the proc to run when a connection comes in
 *      arg:  the argument to pass to the proc
 *
 * Results:
 *      NS_OK/NS_ERROR
 *
 * Side effects:
 *      Will wake up the callback thread.
 *
 *----------------------------------------------------------------------
 */

/* XXX unusable with a direct call except from NsTclSSLSockListenCallback */
/* XXX essentially, the callback proc is going to have to be reponsible */
/* XXX for layering SSL on top of the socket once a connection comes in, */
/* XXX and before the script is run. I might need a new type, Ns_OpenSSLSockProc */
/* XXX but we'll see. I may be able to create a generic way to do this */
/* XXX so the developer using the API won't have to */

int
Ns_OpenSSLSockListenCallback (char *addr, int port, Ns_SockProc *proc,
			      void *arg)
{
    return Ns_SockListenCallback (addr, port, proc, arg);
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSockServerDefault --
 *
 *	Return a pointer to the default SSL_CTX for Sock Servers. 
 *
 * Results:
 *	Pointer to SSL_CTX.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLContext *
NsOpenSSLContextSockServerDefault (void)
{
    /* XXX get rid of this function? */
#if 0
    return sockServerContext;
#endif
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLContextSockClientDefault --
 *
 *	Return a pointer to the default SSL Context for Sock Clients. 
 *
 * Results:
 *	Pointer to Ns_OpenSSLContext.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLContext *
NsOpenSSLContextSockClientDefault (void)
{
    return sockClientContext;
}

/*
 *----------------------------------------------------------------------
 *
 * SessionCacheIdGetNext --
 *
 *      Get the next unique session cache id number
 *
 * Results:
 *      Integer number
 *
 * Side effects:
 *      Increments the global session cache id generator.
 *
 *----------------------------------------------------------------------
 */

static int
SessionCacheIdGetNext (void)
{
    int id;

    Ns_MutexLock(&nextSessionCacheId->lock);
    id = nextSessionCacheId->id;
    nextSessionCacheId->id++;
    Ns_MutexUnlock(&nextSessionCacheId->lock);

    return id;
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
Ns_OpenSSLContextModuleDirSet(char *server, char *module, Ns_OpenSSLContext *context, 
        char *moduleDir)
{
    /* XXX lock struct */
    /* XXX validate that directory exists and is readable */
    context->moduleDir = moduleDir;

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
Ns_OpenSSLContextModuleDirGet(char *server, char *module, Ns_OpenSSLContext *context) {
    return context->moduleDir;
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
 *       (XXX I need to validate the above statements)
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
Ns_OpenSSLContextCertFileSet(char *server, char *module, Ns_OpenSSLContext *context, 
        char *certFile)
{
    int rc;

    context->certFile = certFile;

    if (access(certFile, F_OK) != 0) {
        Ns_Log(Error, MODULE, ": %s: certificate file does not exist: %s", server, certFile);
        return NS_ERROR;
    }

    if (access(certFile, R_OK) != 0) {
        Ns_Log(Error, MODULE, ": %s: certificate file is not readable: %s", server, certFile);
        return NS_ERROR;
    }

    rc = SSL_CTX_use_certificate_chain_file (context->sslctx, certFile);

    if (rc == 0) {
	    Ns_Log (Error, MODULE, ": %s: error loading certificate \"%s\"", 
                server, certFile);
        return NS_ERROR;
    }

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
Ns_OpenSSLContextCertFileGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->certFile;
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
Ns_OpenSSLContextKeyFileSet(char *server, char *module, Ns_OpenSSLContext *context,
        char *keyFile)
{
    int rc;

    context->keyFile = keyFile;

    if (access(keyFile, F_OK) != 0) {
        Ns_Log(Error, MODULE, ": %s: key file does not exist: %s", server, keyFile);
        return NS_ERROR;
    }

    if (access(keyFile, R_OK) != 0) {
        Ns_Log(Error, MODULE, ": %s: key file is not readable: %s", server, keyFile);
        return NS_ERROR;
    }

    rc = SSL_CTX_use_PrivateKey_file(context->sslctx, keyFile, SSL_FILETYPE_PEM);

    if (rc == 0) {
	    Ns_Log (Error, MODULE, ": %s: error loading private key \"%s\"", 
                server, keyFile);
        return NS_ERROR;
    }

    /*
     * See if the key matches the certificate
     */

    if (SSL_CTX_check_private_key(context->sslctx) == 0) {
	    Ns_Log (Error, MODULE, ": %s: private key does not match certificate", server);
	    return NS_ERROR;
    }

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
Ns_OpenSSLContextKeyFileGet(char *server, char *module, Ns_OpenSSLContext *context) 
{
    return context->keyFile;
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
Ns_OpenSSLContextCipherSuiteSet(char *server, char *module, Ns_OpenSSLContext *context,
        char *cipherSuite)
{
    int rc;

    context->cipherSuite = cipherSuite;

    rc = SSL_CTX_set_cipher_list(context->sslctx, cipherSuite);

    if (rc == 0) {
	    Ns_Log(Error, MODULE, ": %s: error setting cipher suite to \"%s\"", server, cipherSuite);
	    return NS_ERROR;
    }

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
Ns_OpenSSLContextCipherSuiteGet(char *server, char *module, Ns_OpenSSLContext *context) 
{
    return context->cipherSuite;
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
Ns_OpenSSLContextProtocolsSet(char *server, char *module, Ns_OpenSSLContext *context,
        char *protocols)
{
    int bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    char *lprotocols = NULL;

    /* XXX Need to ifdef out the protocols and ciphers that aren't compiled*/
    /* XXX a particular instance of an OpenSSL library */

    context->protocols = protocols;

    if (protocols == NULL) {
    	Ns_Log (Notice, MODULE, ": %s: Protocol string not set; using all protocols: SSLv2, SSLv3 and TLSv1",
                server);
	    bits = 1;
    } else {
	    lprotocols = Ns_StrDup(protocols);
	    lprotocols = Ns_StrToLower(lprotocols);

	    if (strstr (lprotocols, "all") != NULL) {
	        bits = 1;
	        Ns_Log (Notice, MODULE, ": %s: using all protocols: SSLv2, SSLv3 and TLSv1",
                    server);
	    } else {
	        if (strstr (protocols, "sslv2") != NULL) {
		        bits &= ~SSL_OP_NO_SSLv2;
		        Ns_Log (Notice, MODULE, ": %s: Using SSLv2 protocol",
                        server);
	        }
	        if (strstr (protocols, "sslv3") != NULL) {
		        bits &= ~SSL_OP_NO_SSLv3;
		        Ns_Log (Notice, MODULE, ": %s: Using SSLv3 protocol",
                        server);
	        }
	        if (strstr (protocols, "tlsv1") != NULL) {
		        bits &= ~SSL_OP_NO_TLSv1;
		        Ns_Log (Notice, MODULE, ": %s: Using TLSv1 protocol",
                        server);
	        }
        }

    	Ns_Free(lprotocols);
    }

    /* XXX see if there's a simpler way to do this whole function */
    SSL_CTX_set_options(context->sslctx, bits);

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
Ns_OpenSSLContextProtocolsGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->protocols;
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
Ns_OpenSSLContextCAFileSet(char *server, char *module, Ns_OpenSSLContext *context,
        char *caFile)
{
    int rc;

    context->caFile = caFile;

    if (access(caFile, F_OK) != 0) { 
        Ns_Log(Error, MODULE, ": %s: certificate authority file does not exist: %s",
                server, caFile);
        return NS_ERROR;
    }

    
    if (access(caFile, R_OK) != 0) { 
        Ns_Log(Error, MODULE, ": %s: certificate authority file is not readable: %s", 
                server, caFile);
        return NS_ERROR;
    }

	rc = SSL_CTX_load_verify_locations(context->sslctx, caFile, NULL);

	if (rc == 0) {
	    Ns_Log(Error, MODULE, ": %s: error loading CA certificate file %s", 
                server, caFile);
	    return NS_ERROR;
    }

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
Ns_OpenSSLContextCAFileGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->caFile;
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
Ns_OpenSSLContextCADirSet(char *server, char *module, Ns_OpenSSLContext *context,
        char *caDir)
{
    DIR *dirfp;
    int rc;

    context->caDir = caDir;

    dirfp = opendir(caDir);
    if (dirfp == NULL) {
	    Ns_Log (Notice, MODULE, ": %s: Cannot open CA certificate directory %s",
		    server, caDir);
        return NS_ERROR;
    }
    closedir(dirfp);

	rc = SSL_CTX_load_verify_locations (context->sslctx, NULL, caDir);

	if (rc == 0) {
	    Ns_Log (Error, MODULE, ": %s: error using CA directory: %s", 
                server, caDir);
	    return NS_ERROR;
    }

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
Ns_OpenSSLContextCADirGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->caDir;
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
Ns_OpenSSLContextPeerVerifySet(char *server, char *module, Ns_OpenSSLContext *context,
        int peerVerify)
{
    /* XXX lock struct */
    /* XXX handle default case where peerVerify is NULL */
    context->peerVerify = peerVerify;

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
Ns_OpenSSLContextPeerVerifyGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->peerVerify;
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
Ns_OpenSSLContextPeerVerifyDepthSet(char *server, char *module, Ns_OpenSSLContext *context,
        int peerVerifyDepth)
{
    /* XXX lock struct */
    /* XXX how do I handle the default case? with varargs in func call? */
    /* XXX ah, no, preset all the default values in Ns_OpenSSLContextCreate */
    context->peerVerifyDepth = peerVerifyDepth;

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
Ns_OpenSSLContextPeerVerifyDepthGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->peerVerifyDepth;
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
Ns_OpenSSLContextSessionCacheSet(char *server, char *module, Ns_OpenSSLContext *context, 
        int sessionCache)
{
    /* XXX lock struct */
    context->sessionCache = sessionCache;

    /* XXX need to make this work well with Timeout, Size set/get funcs */
    if (context->sessionCache) {
        SSL_CTX_set_session_cache_mode(context->sslctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_session_id_context(context->sslctx,
            (void *) &context->sessionCacheId,
            sizeof (context->sessionCacheId));

        /*
         * If not already set, set to defaults
         */

        SSL_CTX_set_timeout(context->sslctx, context->sessionCacheTimeout);

        SSL_CTX_sess_set_cache_size(context->sslctx, context->sessionCacheSize);
    } else {
        SSL_CTX_set_session_cache_mode(context->sslctx, SSL_SESS_CACHE_OFF);
    }

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
Ns_OpenSSLContextSessionCacheGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->sessionCache;
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
Ns_OpenSSLContextSessionCacheSizeSet(char *server, char *module, Ns_OpenSSLContext *context,
        int sessionCacheSize)
{
    /* XXX lock struct */
    context->sessionCacheSize = sessionCacheSize;

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
Ns_OpenSSLContextSessionCacheSizeGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->sessionCacheSize;
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
Ns_OpenSSLContextSessionCacheTimeoutSet(char *server, char *module, Ns_OpenSSLContext *context,
        int sessionCacheTimeout)
{
    /* XXX lock struct */
    context->sessionCacheTimeout = sessionCacheTimeout;

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
Ns_OpenSSLContextSessionCacheTimeoutGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    /* XXX lock struct */
    return context->sessionCacheTimeout;
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
Ns_OpenSSLContextTraceSet(char *server, char *module, Ns_OpenSSLContext *context,
        int trace)
{
    /* XXX lock struct */
    context->trace = trace;

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
Ns_OpenSSLContextTraceGet(char *server, char *module, Ns_OpenSSLContext *context)
{
    return context->trace;
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
Ns_OpenSSLContextCreate (char *server, char *module, char *name, char *role)
{
    Ns_OpenSSLContext *context = NULL;
    Ns_DString ds;

#if 0
    /* XXX turn this on */
    /*
     * The name of an SSL context must be unique within a virtual server.
     */

    if (SSLContextNameCheck (server, module, name)) {
	    Ns_Log(Error, "%s: SSL context with name %s already defined",
			    MODULE, name);
	    return NULL;
    }
#endif

    context = (Ns_OpenSSLContext *) ns_calloc (1, sizeof *context);
    if (context == NULL) {
        Ns_Log(Error, MODULE, ": Failed to create SSL context: %s, %s, %s", 
                server, name, role);
        return NULL;
    }

    Ns_MutexLock(&context->lock);

    Ns_MutexSetName2(&context->lock, MODULE, name);

    if (STREQ(role, "server")) {
        context->role = SERVER_ROLE;
    } else if (STREQ(role, "client")) {
        context->role = CLIENT_ROLE;
    } else {
        Ns_Log(Error, MODULE, ": SSL context has an invalid role: %s, %s, %s",
                server, name, role);
        Ns_MutexUnlock(&context->lock);
        Ns_Free(context);
        return NULL;
    }

    /*
     * Set defaults that cannot be overridden by the user (i.e. variables for
     * which no Ns_OpenSSL*Set/Get functions exist.)
     */

    context->server         = server;
    context->module         = module;
    context->name           = name;
    context->sessionCacheId = SessionCacheIdGetNext();

    /*
     * Create a sane default path for the module directory
     */

    Ns_DStringInit (&ds);
   
    /*
     * Set initial default values that can be overridden in nsd.tcl, C API and
     * Tcl API.
     */

    Ns_HomePath (&ds, "servers", server, "modules", module, NULL);
    context->moduleDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CERT_FILE, NULL);
    context->certFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_KEY_FILE, NULL);
    context->keyFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CA_FILE, NULL);
    context->caFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CA_DIR, NULL);
    context->caDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    context->peerVerify          = DEFAULT_PEER_VERIFY;
    context->peerVerifyDepth     = DEFAULT_PEER_VERIFY_DEPTH;
    context->protocols           = DEFAULT_PROTOCOLS;
    context->cipherSuite         = DEFAULT_CIPHER_LIST;
    context->sessionCache        = DEFAULT_SESSION_CACHE;
    context->sessionCacheSize    = DEFAULT_SESSION_CACHE_SIZE;
    context->sessionCacheTimeout = DEFAULT_SESSION_CACHE_TIMEOUT;
    context->trace               = DEFAULT_TRACE;

    Ns_DStringFree (&ds);

    /*
     * Initialize parts of SSL_CTX that are common to all Ns_OpenSSLContexts
     * (i.e. these are not configurable via nsd.tcl or Ns_OpenSSL* calls).
     */

    if (context->role == SERVER_ROLE) {
        /* XXX should I select this by looking at protocols? */
        context->sslctx = SSL_CTX_new(SSLv23_server_method());
    } else {
        context->sslctx = SSL_CTX_new(SSLv23_client_method());
    }
   
    if (context->sslctx == NULL) {
        /* XXX FAILURE: clean up and then free the struct */
        return NULL;
    }

    /*
     * This allows us to get to our context struct within OpenSSL callback
     * functions.
     */

    SSL_CTX_set_app_data (context->sslctx, context);

    /*
     * Enable SSL bug compatibility.
     * XXX expand this so user can configure what bug handling options they
     * want
     */

    SSL_CTX_set_options (context->sslctx, SSL_OP_ALL);

    /*
     * This apparently prevents some sort of DH attack.
     */

    SSL_CTX_set_options (context->sslctx, SSL_OP_SINGLE_DH_USE);

    /*
     * Temporary key callback required for 40-bit export browsers
     */

    SSL_CTX_set_tmp_rsa_callback (context->sslctx, IssueTmpRSAKey);

    /*
     * Insert the context into the linked list. Instead of wasting time looking
     * for the end of the list, we'll insert it at the front.
     */

    /* XXX lock firstSSLContext before modifying */
    if (firstSSLContext != NULL) {
	    /* There are already other contexts */
	    context->next = firstSSLContext;
	    firstSSLContext = context;
    } else {
	    /* We're the first context created */
	    context->next = NULL;
	    firstSSLContext = context;
    }

    Ns_MutexUnlock(&context->lock);

    return context;
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
Ns_OpenSSLContextDestroy(Ns_OpenSSLContext *context)
{
    return NS_OK;
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
InitLocation (NsOpenSSLDriver *driver)
{
    char *hostname;
    char *lookupHostname;
    Ns_DString ds;

    driver->bindaddr = Ns_ConfigGetValue (driver->configPath,
					   "address");

    hostname = Ns_ConfigGetValue (driver->configPath,
				    "hostname");

    if (driver->bindaddr == NULL) {
	    lookupHostname = (hostname != NULL) ? hostname : Ns_InfoHostname ();
	    Ns_DStringInit (&ds);
	    if (Ns_GetAddrByHost (&ds, lookupHostname) == NS_ERROR) {
	        Ns_Log (Error, MODULE, ": %s: failed to resolve '%s': %s",
		        driver->server, lookupHostname, strerror (errno));
	        return NS_ERROR;
	    }
	    driver->address = Ns_DStringExport (&ds);
    } else {
	    driver->address = ns_strdup (driver->bindaddr);
    }

    if (hostname == NULL) {
	    Ns_DStringInit (&ds);
	    if (Ns_GetHostByAddr (&ds, driver->address) == NS_ERROR) {
	        Ns_Log (Warning, MODULE, ": %s: failed to reverse resolve '%s': %s",
		        driver->server, driver->address, strerror (errno));
	        hostname = ns_strdup (driver->address);
	    } else {
	        hostname = Ns_DStringExport (&ds);
	    }
    }

    if (Ns_ConfigGetInt(driver->configPath, "port", &driver->port) == NS_FALSE) {
        Ns_Log(Warning, MODULE, ": %s: No port set for driver", driver->server);
        /* XXX this should be a mandatory setting */
        driver->port = DEFAULT_PORT;
    }
    if (driver->location != NULL) {
	    driver->location = ns_strdup (driver->location);
    } else {
        Ns_Log(Notice, MODULE, ": %s: location not set; defaulting", driver->server);
	    Ns_DStringInit (&ds);
	    Ns_DStringVarAppend (&ds, DEFAULT_PROTOCOL "://", hostname, NULL);
	    if (driver->port != DEFAULT_PORT) {
	        Ns_DStringPrintf (&ds, ":%d", driver->port);
	    }
	    driver->location = Ns_DStringExport (&ds);
    }
    Ns_Log (Notice, MODULE, ": %s: location %s", driver->server, driver->location);

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
PeerVerifyCallback (int preverify_ok, X509_STORE_CTX * x509_ctx)
{
    return 1;
}

/* XXX merge with Ns_OpenSSLContextModuleDirSet ??? */
#if 0

/*
 *----------------------------------------------------------------------
 *
 * GetModuleDir --
 *
 *       Get the absolute path of the module's directory.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       May create the directory on disk
 *
 *----------------------------------------------------------------------
 */

static char *
GetModuleDir (char *server, char *module)
{
    char *path;
    Ns_DString ds;

    Ns_DStringInit (&ds);

    path = Ns_ConfigGetValue (Ns_ConfigGetPath(server, module, NULL), 
			    CONFIG_MODULE_DIR);

    /* Path not set in config; create default path */
    
    if (path == NULL) {
    	Ns_ModulePath (&ds, server, module, NULL);
	    path = Ns_DStringExport (&ds);
    } else if (! Ns_PathIsAbsolute (path)) {
	    Ns_DStringVarAppend (&ds, path, value, NULL);
	    path = Ns_DStringExport (&ds);
    }

    Ns_Log (Notice, "Module directory defaults to %s", path);

    /*
     * Attempt to create the directory if it doesn't already exist
     */

    if (mkdir (path, 0755) != 0 && errno != EEXIST) {
        Ns_Log (Error, "mkdir(%s) failed: %s", path, strerror (errno));
    }

    Ns_DStringFree (&ds);

    return path;
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
OpenSSLProc (Ns_DriverCmd cmd, Ns_Sock *sock, struct iovec *bufs, int nbufs)
{
    Ns_Driver *driver = sock->driver;
    Ns_OpenSSLConn *conn;
    int n, total;

    switch (cmd) {
    case DriverRecv:
    case DriverSend:

	/*          
	 * On first I/O, initialize the connection context.
	 */

	if (sock->arg == NULL) {
	    n = driver->recvwait;
	    if (n > driver->sendwait) {
    		n = driver->sendwait;
	    }
#if 0
	    sock->arg = NsOpenSSLCreateConn(sock->sock, n, driver->arg);
#endif
        /* XXX driver is supposed to be of type Ns_OpenSSLDriver ... fix */
	    sock->arg = NsOpenSSLCreateConn(sock->sock, driver, "server", CONNTYPE_SERVER);
	    if (sock->arg == NULL) {
    		return -1;
	    }
    }

#if 0 /* XXX */
	conn = sock->arg;
	if (conn == NULL) {
	    conn = ns_calloc (1, sizeof (*conn));

	    if (conn == NULL) {
	       Ns_Log(Error, MODULE, ":unable to allocate memory");
	       return NS_ERROR;
	    }
	    
	    conn->driver   = driver->arg;
	    conn->conntype = CONNTYPE_SERVER;
	    conn->refcnt   = 0;	/* always 0 for nsdserver conns */
	    conn->sock     = sock->sock;
	    sock->arg      = conn;

	    if (NsOpenSSLCreateConn ((Ns_OpenSSLConn *) conn) != NS_OK) {
		return NS_ERROR;
	    }
	}
#endif


	/*
	 * Process each buffer one at a time.
	 */

	total = 0;
	do {
	    if (cmd == DriverSend) {
		n = NsOpenSSLSend (sock->arg, bufs->iov_base, bufs->iov_len);
	    } else {
		n = NsOpenSSLRecv (sock->arg, bufs->iov_base, bufs->iov_len);
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
	        NsOpenSSLDestroyConn (sock->arg);
	        sock->arg = NULL;
	    }
	    n = 0;
	    break;

    default:
    	Ns_Log(Error, MODULE, ": Unsupported driver command encountered");
	    n = -1;
	    break;
    }
    return n;

