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

static int PeerVerifyCallback (int preverify_ok, X509_STORE_CTX *x509_ctx);
static int SessionCacheIdGetNext (void);
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

/* XXX not yet used */
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
    NsOpenSSLModuleInit(server, module);
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDriverInit --
 *
 *       Create an initialized an SSL driver. There will be one driver for each
 *       virtual server/port combination.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       Allocates memory. Adds driver to driver linked list.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLDriverInit (char *server, char *module, char *name)
{
    Ns_DriverInitData *init;
    NsOpenSSLDriver *driver;
#if 0
    Ns_DString ds;
    char *lookupHostname;
#endif
    char *path;

    Ns_Log(Debug, "%s: %s: In NsOpenSSLDriverInit", MODULE, server);
    
    path = Ns_ConfigGetPath(server, module, "driver", name, NULL);
    if (path == NULL) {
        Ns_Log(Error, "%s: %s: Failed to find SSL driver '%s' in nsd.tcl",
                MODULE, server, name);
        return NULL;
    }
 
    driver = (NsOpenSSLDriver *) ns_calloc (1, sizeof(*driver));
    if (driver == NULL) {
	Ns_Log(Error, "%s: %s: Failed to create driver '%s'", 
                MODULE, server, name);
	return NULL;
    }

    driver->server = server;
    driver->module = module;
    driver->name = name;
    driver->path = path;

#if 0
    /* XXX mutex names can't be name of module anymore */
    Ns_MutexSetName(&driver->lock, module);
#endif

#if 0

    /* XXX ALL TAKEN CARE OF IN Ns_DriverInit -- no need to duplicate it here */

    /*
     * The port number is mandatory
     */

    if (Ns_ConfigGetInt(path, "port", &driver->port) != NS_TRUE) {
        Ns_Log(Error, "%s: %s: Port not set for driver %s", MODULE, server, name);
        Ns_Free(driver);
        return NULL;
    }
    Ns_Log(Notice, "%s: %s: port = %d", MODULE, server, driver->port);

    driver->address  = Ns_ConfigGetValue(path, "address");
    driver->hostname = Ns_ConfigGetValue(path, "hostname");
    driver->location = Ns_ConfigGetValue(path, "location");

    /*
     * Set driver's address
     */

    if (driver->address == NULL) {
        Ns_DStringInit (&ds);
        lookupHostname = (driver->hostname != NULL) ? driver->hostname : Ns_InfoHostname ();
        if (Ns_GetAddrByHost (&ds, lookupHostname) == NS_ERROR) {
            Ns_Log (Error, "%s: %s: failed to resolve '%s': %s",
                    MODULE, server, lookupHostname, strerror (errno));
            /* XXX failure mode here ??? */
            return NULL;
        }
        driver->address = Ns_DStringExport (&ds);
    } else {
        driver->address = Ns_StrDup(driver->address);
    }
    Ns_Log(Notice, "%s: %s: address = %s", MODULE, server, driver->address);

    /*
     * Set driver's hostname
     */

    if (driver->hostname == NULL) {
        Ns_DStringInit (&ds);
        if (Ns_GetHostByAddr (&ds, driver->address) == NS_ERROR) {
            Ns_Log (Warning, "%s: %s: failed to reverse resolve address '%s': %s",
                    MODULE, driver->server, driver->address, strerror (errno));
            driver->hostname = (Ns_InfoHostname() != NULL) ? Ns_InfoHostname() : driver->address;
        } else {
            driver->hostname = Ns_DStringExport (&ds);
        }
    } else {
        driver->hostname = Ns_StrDup(driver->hostname);
    }
    Ns_Log(Notice, "%s: %s: hostname = %s", MODULE, server, driver->hostname);

    /*
     * Set driver's location string
     */

    if (driver->location == NULL) {
        Ns_DStringInit (&ds);
        Ns_DStringVarAppend (&ds, DEFAULT_PROTOCOL "://", driver->hostname, NULL);
        if (driver->port != DEFAULT_PORT) {
            Ns_DStringPrintf (&ds, ":%d", driver->port);
        }
        driver->location = Ns_DStringExport (&ds);
    } else {
        driver->location = Ns_StrDup(driver->location);
    }
    Ns_Log (Notice, "%s: %s: location %s", MODULE, server, driver->location);
#endif

    /*
     * Register the driver with AOLserver.
     */

    init = ns_calloc(1, sizeof(Ns_DriverInitData));
    if (init == NULL) {
        Ns_Log(Error, "%s: Memory allocation failure in Ns_ModuleInit",
                module);
        Ns_Free(driver);
        return NS_ERROR;
    }

    init->version = NS_DRIVER_VERSION_1;
    /* XXX Make name equivalent of "%s: %s: " or "MODULE: drivername: " */
    init->name = MODULE;
    init->proc = OpenSSLProc;
    init->opts = NS_DRIVER_SSL;
    init->arg  = driver;
    /* XXX NEED TO SET THIS PATH */
    init->path = driver->path;

    if (Ns_DriverInit(server, module, init) == NS_ERROR) {
        /* XXX validate these */
        Ns_Free(init);
        Ns_Free(driver);
        return NS_ERROR;
    }

    /*
     * Insert driver into driver linked list.
     */

#if 0
    driver->next = OpenSSLStructs->firstSSLDriver;
    OpenSSLStructs->firstSSLDriver = driver;
#endif

    /* XXX create per-virtual-server driver linked lists */
    /* XXX need to lock around firstSSLDriver here */

    if (firstSSLDriver != NULL) {
            /* There are already other drivers */
            driver->next = firstSSLDriver;
            firstSSLDriver = driver;
    } else {
            /* We're the first driver created */
            driver->next = NULL;
            firstSSLDriver = driver;
    }

    driver->refcnt = 0;

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLDriversDestroy --
 *
 *      Destroy all NsOpenSSLDrivers.
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
NsOpenSSLDriversDestroy (void)
{
    /* XXX lock around firstSSLDriver ??? */
    /* XXX register this function to destroy all drivers at shutdown ??? */


    while (firstSSLDriver != NULL) {
        NsOpenSSLDriverDestroy(firstSSLDriver);
    }
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

    Ns_Log(Debug, "%s: %s: shutting down driver '%s'", MODULE, 
            driver->server, driver->name);

    if (driver == NULL)
        return;

    /*
     * Remove driver from driver linked list.
     */



    /*
     * Destroy connections that are still tied to this driver.
     */

    /* XXX need to lock around refcnt and firstFreeConn here */
    /* XXX race condition if new conn comes in while we're doing this part ??? */
    if (driver->refcnt > 0) {
        while ((conn = driver->firstFreeConn) != NULL) {
            driver->firstFreeConn = conn->next;
            /* XXX doesn't this need to have it's contents free'd? */
            Ns_Free (conn);
        }
    }

#if 0
    Ns_Free(driver->address);
    Ns_Free(driver->hostname);
    Ns_Free(driver->location);
#endif
    Ns_MutexDestroy (&driver->lock);

    /* XXX should an SSL context be deallocated when it's refcnt reaches 0 ??? */
    if (driver->context != NULL) 
        driver->context->refcnt--;
  
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
Ns_OpenSSLSockConnect (char *host, int port, int async, int timeout)
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

    if ((conn = NsOpenSSLConnCreate(sock, NULL, ROLE_CLIENT)) == NULL) {
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
Ns_OpenSSLSockAccept (SOCKET sock)
{
    Ns_OpenSSLConn *conn = NULL;

    if (sock == INVALID_SOCKET)
        return NULL;

    if ((conn = NsOpenSSLConnCreate(sock, NULL, ROLE_SERVER)) == NULL) {
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
Ns_OpenSSLSockListen (char *addr, int port)
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
Ns_OpenSSLSockCallback (SOCKET sock, Ns_SockProc *proc, void *arg, int when)
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
    Ns_Log(Debug, "%s: %s: moduleDir set to %s", MODULE, server, moduleDir);
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
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextCertFileSet(char *server, char *module, Ns_OpenSSLContext *context, 
        char *certFile)
{
    char *certFilePath;
    int rc;
    Ns_DString ds;

    Ns_Log(Debug, "%s: %s: certFile set to %s", MODULE, server, certFile);

    if (context->certFile == NULL) {
        Ns_Log(Error, "%s: %s: certFile is NULL", MODULE, server);
        return NS_ERROR;
    }

    context->certFile = certFile;

    if (Ns_PathIsAbsolute(context->certFile)) {
        certFilePath = context->certFile;
    } else {
        Ns_DStringInit(&ds);
        Ns_MakePath(&ds, context->moduleDir, certFile, NULL);
#if 0
        Ns_DStringVarAppend(&ds, dir, value, NULL);
#endif
        certFilePath = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }


    if (access(certFilePath, F_OK) != 0) {
        Ns_Log(Error, "%s: %s: certificate file does not exist: %s", 
                MODULE, server, certFilePath);
        return NS_ERROR;
    }

    if (access(certFilePath, R_OK) != 0) {
        Ns_Log(Error, "%s: %s: certificate file is not readable: %s", 
                MODULE, server, certFilePath);
        return NS_ERROR;
    }

    rc = SSL_CTX_use_certificate_chain_file (context->sslctx, certFilePath);

    if (rc == 0) {
        Ns_Log (Error, "%s: %s: error loading certificate \"%s\"", 
               MODULE, server, certFilePath);
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

/* XXX merge this with Ns_OpenSSLContextCertFileSet -- most code is duplicated */
int
Ns_OpenSSLContextKeyFileSet(char *server, char *module, Ns_OpenSSLContext *context,
        char *keyFile)
{
    int rc;
    Ns_DString ds;
    char *keyFilePath;

    Ns_Log(Debug, "%s: %s: keyFile set to %s", MODULE, server, keyFile);

    if (context->keyFile == NULL) {
        Ns_Log(Error, "%s: %s: keyFile is NULL", MODULE, server);
        return NS_ERROR;
    }

    context->keyFile = keyFile;

    if (Ns_PathIsAbsolute(context->keyFile)) {
        keyFilePath = context->keyFile;
    } else {
        Ns_DStringInit(&ds);
        Ns_MakePath(&ds, context->moduleDir, keyFile, NULL);
#if 0
        Ns_DStringVarAppend(&ds, dir, value, NULL);
#endif
        keyFilePath = Ns_DStringExport(&ds);
        Ns_DStringFree(&ds);
    }

    if (access(keyFilePath, F_OK) != 0) {
        Ns_Log(Error, "%s: %s: key file does not exist: %s", MODULE, server, keyFilePath);
        return NS_ERROR;
    }

    if (access(keyFilePath, R_OK) != 0) {
        Ns_Log(Error, "%s: %s: key file is not readable: %s", MODULE, server, keyFilePath);
        return NS_ERROR;
    }

    rc = SSL_CTX_use_PrivateKey_file(context->sslctx, keyFilePath, SSL_FILETYPE_PEM);

    if (rc == 0) {
        Ns_Log (Error, "%s: %s: error loading private key \"%s\"", 
                MODULE, server, keyFilePath);
        return NS_ERROR;
    }

    /*
     * See if the key matches the certificate
     */

    if (SSL_CTX_check_private_key(context->sslctx) == 0) {
	    Ns_Log (Error, "%s: %s: private key does not match certificate", 
                    MODULE, server);
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

    Ns_Log(Debug, "%s: %s: cipherSuite set to %s", MODULE, server, cipherSuite);

    context->cipherSuite = cipherSuite;

    rc = SSL_CTX_set_cipher_list(context->sslctx, cipherSuite);

    if (rc == 0) {
	    Ns_Log(Error, "%s: %s: error setting cipher suite to \"%s\"", 
                    MODULE, server, cipherSuite);
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

    Ns_Log(Debug, "%s: %s: protocols set to %s", MODULE, server, protocols);
    context->protocols = protocols;

    if (protocols == NULL) {
    	Ns_Log (Notice, "%s: %s: Protocol string not set; using all protocols: SSLv2, SSLv3 and TLSv1",
                MODULE, server);
	    bits = 1;
    } else {
	    lprotocols = Ns_StrDup(protocols);
	    lprotocols = Ns_StrToLower(lprotocols);

	    if (strstr (lprotocols, "all") != NULL) {
	        bits = 1;
	        Ns_Log (Notice, "%s: %s: using all protocols: SSLv2, SSLv3 and TLSv1",
                    MODULE, server);
	    } else {
	        if (strstr (protocols, "sslv2") != NULL) {
                    bits &= ~SSL_OP_NO_SSLv2;
                    Ns_Log (Notice, "%s: %s: Using SSLv2 protocol", MODULE, server);
	        }
	        if (strstr (protocols, "sslv3") != NULL) {
                    bits &= ~SSL_OP_NO_SSLv3;
                    Ns_Log (Notice, "%s: %s: Using SSLv3 protocol", MODULE, server);
	        }
	        if (strstr (protocols, "tlsv1") != NULL) {
                    bits &= ~SSL_OP_NO_TLSv1;
                    Ns_Log (Notice, "%s: %s: Using TLSv1 protocol",
                        MODULE, server);
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

    Ns_Log(Debug, "%s: %s: caFile set to %s", MODULE, server, caFile);
    context->caFile = caFile;

    if (access(caFile, F_OK) != 0) { 
        Ns_Log(Error, "%s: %s: certificate authority file does not exist: %s",
                MODULE, server, caFile);
        return NS_ERROR;
    }

    
    if (access(caFile, R_OK) != 0) { 
        Ns_Log(Error, "%s: %s: certificate authority file is not readable: %s", 
                MODULE, server, caFile);
        return NS_ERROR;
    }

	rc = SSL_CTX_load_verify_locations(context->sslctx, caFile, NULL);

	if (rc == 0) {
	    Ns_Log(Error, "%s: %s: error loading CA certificate file %s", 
                MODULE, server, caFile);
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

    Ns_Log(Debug, "%s: %s: caDir set to %s", MODULE, server, caDir);
    context->caDir = caDir;

    dirfp = opendir(caDir);
    if (dirfp == NULL) {
	    Ns_Log (Notice, "%s: %s: Cannot open CA certificate directory %s",
		    MODULE, server, caDir);
        return NS_ERROR;
    }
    closedir(dirfp);

	rc = SSL_CTX_load_verify_locations (context->sslctx, NULL, caDir);

	if (rc == 0) {
	    Ns_Log (Error, "%s: %s: error using CA directory: %s", 
                MODULE, server, caDir);
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
    Ns_Log(Debug, "%s: %s: peerVerify set to %d", MODULE, server, peerVerify);
    context->peerVerify = peerVerify;

    if (peerVerify) {
        SSL_CTX_set_verify(context->sslctx, (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE),
                PeerVerifyCallback);
    } else {
        SSL_CTX_set_verify(context->sslctx, SSL_VERIFY_NONE, NULL);
    }

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
    Ns_Log(Debug, "%s: %s: peerVerifyDepth set to %d", MODULE, server, peerVerifyDepth);
    context->peerVerifyDepth = peerVerifyDepth;

    if (peerVerifyDepth >= 0) {
        SSL_CTX_set_verify_depth(context->sslctx, peerVerifyDepth);
    } else {
        Ns_Log(Warning, "%s: %s: Peer verify parameter invalid - defaulting to %d",
                MODULE, server, DEFAULT_PEER_VERIFY_DEPTH);
        SSL_CTX_set_verify_depth(context->sslctx, DEFAULT_PEER_VERIFY_DEPTH);
    }

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
    Ns_Log(Debug, "%s: %s: sessionCache set to %d", MODULE, server, sessionCache);
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
    Ns_Log(Debug, "%s: %s: sessionCacheSize set to %d", MODULE, server, sessionCacheSize);
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
    Ns_Log(Debug, "%s: %s: sessionCacheTimeout set to %d", MODULE, server, sessionCacheTimeout);
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
    Ns_Log(Debug, "%s: %s: trace set to %d", MODULE, server, trace);
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
Ns_OpenSSLContextCreate (char *server, char *module)
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

    context = (Ns_OpenSSLContext *) ns_calloc (1, sizeof(*context));
    if (context == NULL) {
        Ns_Log(Error, "%s: %s: Failed to create SSL context", 
                MODULE, server);
        return NULL;
    }

    /*
     * Set defaults that cannot be overridden by the user (i.e. variables for
     * which no Ns_OpenSSL*Set/Get functions exist.)
     */

    context->server         = server;
    context->module         = module;
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

    if (context->role == ROLE_SERVER) {
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

    //Ns_MutexUnlock(&context->lock);

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
IssueTmpRSAKey (SSL * ssl, int export, int keylen)
{
    Ns_OpenSSLConn *conn;
    NsOpenSSLDriver *driver;
    static RSA *rsa_tmp = NULL;

    conn = (Ns_OpenSSLConn *) SSL_get_app_data (ssl);
    driver = conn->driver;

    rsa_tmp = RSA_generate_key (keylen, RSA_F4, NULL, NULL);
    if (rsa_tmp == NULL) {
        Ns_Log(Error, "%s: %s: Temporary RSA key generation failed",
                MODULE, conn->driver->server);
    } else {
        Ns_Log (Notice, "%s: %s: Generated %d-bit temporary RSA key",
                MODULE, conn->driver->server, keylen);
    }

    return rsa_tmp;
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
    int n, total;

    switch (cmd) {
    case DriverRecv:
    case DriverSend:

	/*          
	 * On first I/O, initialize the connection context.
	 */

	if (sock->arg == NULL) {
	    n = driver->recvwait;
	    if (n > driver->sendwait) 
    		n = driver->sendwait;
	   
#if 0
	    sock->arg = NsOpenSSLCreateConn(sock->sock, n, driver->arg);
#endif
	    sock->arg = NsOpenSSLConnCreate(sock->sock, driver->arg, ROLE_SERVER);
	    if (sock->arg == NULL) {
    		return -1;
	    }
    }

#if 0 /* XXX */
	conn = sock->arg;
	if (conn == NULL) {
	    conn = ns_calloc (1, sizeof (*conn));

	    if (conn == NULL) {
	       Ns_Log(Error, ":unable to allocate memory", MODULE);
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
		n = NsOpenSSLSend (sock->arg, bufs->iov_base, (int) bufs->iov_len);
	    } else {
		n = NsOpenSSLRecv (sock->arg, bufs->iov_base, (int) bufs->iov_len);
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
	        NsOpenSSLConnDestroy (sock->arg);
	        sock->arg = NULL;
	    }
	    n = 0;
	    break;

    default:
    	Ns_Log(Error, "%s: Unsupported driver command encountered", MODULE);
	    n = -1;
	    break;
    }
    return n;
}


/*            
 *----------------------------------------------------------------------
 *
 * NsInitSessionCache --
 *
 *      Initialize the session cache.
 *
 * Results:   
 *      Session cache number sequence initialized.
 *
 * Side effects:
 *      None. 
 *            
 *----------------------------------------------------------------------
 */

int
NsOpenSSLSessionCacheInit (void)
{
    nextSessionCacheId = (SessionCacheId *) ns_calloc (1, sizeof(*nextSessionCacheId));
    if (nextSessionCacheId == NULL) {
        Ns_Log (Error, "%s: Failed to allocate memory for session id generator",
                MODULE);
        return NS_ERROR;
    } 
    Ns_MutexLock(&nextSessionCacheId->lock);
    Ns_MutexSetName2(&nextSessionCacheId->lock, MODULE, "sessioncacheid");
    nextSessionCacheId->id = 1;
    Ns_MutexUnlock(&nextSessionCacheId->lock);

    return NS_OK;
}
