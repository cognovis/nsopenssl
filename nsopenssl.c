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

Tcl_HashTable NsOpenSSLServers;
NsOpenSSLSessionCacheId *nextSessionCacheId;

static int PeerVerifyCallback (int preverify_ok, X509_STORE_CTX *x509_ctx);
static RSA *IssueTmpRSAKey (SSL *ssl, int export, int keylen);
static void OpenSSLTrace (SSL *ssl, int where, int rc);


/* XXX put into NsOpenSSLVirtualServerTable->server */
static Ns_OpenSSLContext  *firstSSLContext;
static Ns_OpenSSLConn     *firstSSLConn;

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
    return NsOpenSSLModuleInit(server, module);
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
    Ns_OpenSSLConn *sslconn;
    Ns_OpenSSLContext *sslcontext;
    SOCKET sock;

    if (timeout < 0) {
	    sock = Ns_SockConnect (host, port);
    } else {
	    sock = Ns_SockTimedConnect (host, port, timeout);
    }

    if (sock == INVALID_SOCKET)
	    return NULL;

    /* XXX add code to use default SSL context if it exists */
   
    if ((sslconn = NsOpenSSLConnCreate(sock, NULL, sslcontext, ROLE_CLIENT)) == NULL) {
	    return NULL;
    }

    /*
     * We leave the socket blocking until after the handshake.
     */

    if (async)
	Ns_SockSetNonBlocking (sslconn->sock);

    SSL_set_app_data (sslconn->ssl, sslconn);

    return sslconn;
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
    Ns_OpenSSLConn *sslconn;
    Ns_OpenSSLContext *sslcontext;

    if (sock == INVALID_SOCKET) {
        return NULL;
    }

    if ((sslconn = NsOpenSSLConnCreate(sock, NULL, sslcontext, ROLE_SERVER)) == NULL) {
        return NULL;
    }

    Ns_SockSetNonBlocking (sslconn->sock);
    SSL_set_app_data (sslconn->ssl, sslconn);

    return sslconn;
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
    /* XXX lock struct */
    /* XXX validate that directory exists and is readable */
    Ns_Log(Debug, "%s: %s: moduleDir set to %s", MODULE, server, moduleDir);
    sslcontext->moduleDir = moduleDir;

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
 *       None
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLContextCertFileSet(char *server, char *module, Ns_OpenSSLContext *sslcontext, 
        char *certFile)
{
    char *certFilePath;
    int rc;
    Ns_DString ds;

    Ns_Log(Debug, "%s: %s: certFile set to %s", MODULE, server, certFile);

    if (sslcontext->certFile == NULL) {
        Ns_Log(Error, "%s: %s: certFile is NULL", MODULE, server);
        return NS_ERROR;
    }

    sslcontext->certFile = certFile;

    if (Ns_PathIsAbsolute(sslcontext->certFile)) {
        certFilePath = sslcontext->certFile;
    } else {
        Ns_DStringInit(&ds);
        Ns_MakePath(&ds, sslcontext->moduleDir, certFile, NULL);
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

    rc = SSL_CTX_use_certificate_chain_file (sslcontext->sslctx, certFilePath);

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

/* XXX merge this with Ns_OpenSSLContextCertFileSet -- most code is duplicated */
int
Ns_OpenSSLContextKeyFileSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        char *keyFile)
{
    int rc;
    Ns_DString ds;
    char *keyFilePath;

    Ns_Log(Debug, "%s: %s: keyFile set to %s", MODULE, server, keyFile);

    if (sslcontext->keyFile == NULL) {
        Ns_Log(Error, "%s: %s: keyFile is NULL", MODULE, server);
        return NS_ERROR;
    }

    sslcontext->keyFile = keyFile;

    if (Ns_PathIsAbsolute(sslcontext->keyFile)) {
        keyFilePath = sslcontext->keyFile;
    } else {
        Ns_DStringInit(&ds);
        Ns_MakePath(&ds, sslcontext->moduleDir, keyFile, NULL);
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

    rc = SSL_CTX_use_PrivateKey_file(sslcontext->sslctx, keyFilePath, SSL_FILETYPE_PEM);

    if (rc == 0) {
        Ns_Log (Error, "%s: %s: error loading private key \"%s\"", 
                MODULE, server, keyFilePath);
        return NS_ERROR;
    }

    /*
     * See if the key matches the certificate
     */

    if (SSL_CTX_check_private_key(sslcontext->sslctx) == 0) {
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
    int rc;

    Ns_Log(Debug, "%s: %s: cipherSuite set to %s", MODULE, server, cipherSuite);

    sslcontext->cipherSuite = cipherSuite;

    rc = SSL_CTX_set_cipher_list(sslcontext->sslctx, cipherSuite);

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
    int bits = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    char *lprotocols = NULL;

    /* XXX Need to ifdef out the protocols and ciphers that aren't compiled into OpenSSL */

    if (protocols == NULL) {
    	Ns_Log (Notice, "%s: %s: Protocol parameter not set; using all protocols: SSLv2, SSLv3 and TLSv1",
                MODULE, server);
            bits &= ~bits;
    } else {
	    lprotocols = Ns_StrDup(protocols);
	    lprotocols = Ns_StrToLower(lprotocols);

	    if (strstr (lprotocols, "all") != NULL) {
	        Ns_Log (Notice, "%s: %s: using all protocols: SSLv2, SSLv3 and TLSv1",
                    MODULE, server);
                bits &= ~bits;
	    } else {
	        if (strstr (lprotocols, "sslv2") != NULL) {
                    Ns_Log (Notice, "%s: %s: Using SSLv2 protocol", MODULE, server);
                    bits &= ~SSL_OP_NO_SSLv2;
	        }
	        if (strstr (lprotocols, "sslv3") != NULL) {
                    Ns_Log (Notice, "%s: %s: Using SSLv3 protocol", MODULE, server);
                    bits &= ~SSL_OP_NO_SSLv3;
	        }
	        if (strstr (lprotocols, "tlsv1") != NULL) {
                    Ns_Log (Notice, "%s: %s: Using TLSv1 protocol",
                        MODULE, server);
                    bits &= ~SSL_OP_NO_TLSv1;
	        }
        }

    	Ns_Free(lprotocols);
    }

    sslcontext->protocols = protocols;
    SSL_CTX_set_options(sslcontext->sslctx, bits);

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

int
Ns_OpenSSLContextCAFileSet(char *server, char *module, Ns_OpenSSLContext *sslcontext,
        char *caFile)
{
    int rc;

    Ns_Log(Debug, "%s: %s: caFile set to %s", MODULE, server, caFile);
    sslcontext->caFile = caFile;

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

	rc = SSL_CTX_load_verify_locations(sslcontext->sslctx, caFile, NULL);

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
    DIR *dirfp;
    int rc;

    Ns_Log(Debug, "%s: %s: caDir set to %s", MODULE, server, caDir);
    sslcontext->caDir = caDir;

    dirfp = opendir(caDir);
    if (dirfp == NULL) {
	    Ns_Log (Notice, "%s: %s: Cannot open CA certificate directory %s",
		    MODULE, server, caDir);
        return NS_ERROR;
    }
    closedir(dirfp);

	rc = SSL_CTX_load_verify_locations (sslcontext->sslctx, NULL, caDir);

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
    Ns_Log(Debug, "%s: %s: peerVerify set to %d", MODULE, server, peerVerify);
    sslcontext->peerVerify = peerVerify;

    if (peerVerify) {
        SSL_CTX_set_verify(sslcontext->sslctx, (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE),
                PeerVerifyCallback);
    } else {
        SSL_CTX_set_verify(sslcontext->sslctx, SSL_VERIFY_NONE, NULL);
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
    Ns_Log(Debug, "%s: %s: peerVerifyDepth set to %d", MODULE, server, peerVerifyDepth);
    sslcontext->peerVerifyDepth = peerVerifyDepth;

    if (peerVerifyDepth >= 0) {
        SSL_CTX_set_verify_depth(sslcontext->sslctx, peerVerifyDepth);
    } else {
        Ns_Log(Warning, "%s: %s: Peer verify parameter invalid - defaulting to %d",
                MODULE, server, DEFAULT_PEER_VERIFY_DEPTH);
        SSL_CTX_set_verify_depth(sslcontext->sslctx, DEFAULT_PEER_VERIFY_DEPTH);
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
    Ns_Log(Debug, "%s: %s: sessionCache set to %d", MODULE, server, sessionCache);
    sslcontext->sessionCache = sessionCache;

    /* XXX need to make this work well with Timeout, Size set/get funcs */
    if (sslcontext->sessionCache) {
        SSL_CTX_set_session_cache_mode(sslcontext->sslctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_session_id_context(sslcontext->sslctx,
            (void *) &sslcontext->sessionCacheId,
            sizeof (sslcontext->sessionCacheId));

        /*
         * If not already set, set to defaults
         */

        SSL_CTX_set_timeout(sslcontext->sslctx, sslcontext->sessionCacheTimeout);

        SSL_CTX_sess_set_cache_size(sslcontext->sslctx, sslcontext->sessionCacheSize);
    } else {
        SSL_CTX_set_session_cache_mode(sslcontext->sslctx, SSL_SESS_CACHE_OFF);
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
    Ns_Log(Debug, "%s: %s: sessionCacheSize set to %d", MODULE, server, sessionCacheSize);
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
    Ns_Log(Debug, "%s: %s: sessionCacheTimeout set to %d", MODULE, server, sessionCacheTimeout);
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
    if (trace) {
        Ns_Log(Debug, "****  %s: %s: Turning trace ON", MODULE, server);
        SSL_CTX_set_info_callback(sslcontext->sslctx, OpenSSLTrace);
    } else {
        Ns_Log(Debug, "****  %s: %s: Turning trace OFF", MODULE, server);
        SSL_CTX_set_info_callback(sslcontext->sslctx, NULL);
    }

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
Ns_OpenSSLContextCreate (char *server, char *module)
{
    Ns_OpenSSLContext *sslcontext;
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

    sslcontext = ns_calloc(1, sizeof(*sslcontext));
    sslcontext->server = server;
    sslcontext->module = module;
    sslcontext->bufsize = DEFAULT_BUFFER_SIZE;
    sslcontext->timeout = DEFAULT_TIMEOUT;

    /* 
     * WARNING: session cache ids are global to the OpenSSL library. This means
     * that if another AOLserver module uses the OpenSSL library for SSL
     * connections that use session caching, some coordination will be
     * necessary so cache ids don't collide.
     */

    /* XXX see if session cache ids can be alpha-numeric */
    Ns_MutexLock(&nextSessionCacheId->lock);
    sslcontext->sessionCacheId = nextSessionCacheId->id;
    nextSessionCacheId->id++;
    Ns_MutexUnlock(&nextSessionCacheId->lock);

    /*
     * First we set initial default values. These can be overridden in nsd.tcl,
     * C API and Tcl API.
     */

    Ns_DStringInit (&ds);
   
    Ns_HomePath (&ds, "servers", server, "modules", module, NULL);
    sslcontext->moduleDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CERT_FILE, NULL);
    sslcontext->certFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_KEY_FILE, NULL);
    sslcontext->keyFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CA_FILE, NULL);
    sslcontext->caFile = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    Ns_HomePath (&ds, "servers", server, "modules", module, DEFAULT_CA_DIR, NULL);
    sslcontext->caDir = Ns_DStringExport(&ds);
    Ns_DStringTrunc(&ds, 0);

    sslcontext->peerVerify          = DEFAULT_PEER_VERIFY;
    sslcontext->peerVerifyDepth     = DEFAULT_PEER_VERIFY_DEPTH;
    sslcontext->protocols           = DEFAULT_PROTOCOLS;
    sslcontext->cipherSuite         = DEFAULT_CIPHER_LIST;
    sslcontext->sessionCache        = DEFAULT_SESSION_CACHE;
    sslcontext->sessionCacheSize    = DEFAULT_SESSION_CACHE_SIZE;
    sslcontext->sessionCacheTimeout = DEFAULT_SESSION_CACHE_TIMEOUT;
    sslcontext->trace               = DEFAULT_TRACE;

    Ns_DStringFree (&ds);

    /*
     * Initialize parts of SSL_CTX that are common to all Ns_OpenSSLContexts
     * (i.e. these are not configurable via nsd.tcl or Ns_OpenSSL* calls).
     */

    if (sslcontext->role == ROLE_SERVER) {
        /* XXX should I select this by looking at protocols? */
        sslcontext->sslctx = SSL_CTX_new(SSLv23_server_method());
        Ns_Log(Debug, "*** SSL_CTX_new for SERVER");
    } else {
        sslcontext->sslctx = SSL_CTX_new(SSLv23_client_method());
        Ns_Log(Debug, "*** SSL_CTX_new for CLIENT");
    }
   
        Ns_Log(Debug, "*** ssl_ctx=%p");
    if (sslcontext->sslctx == NULL) {
        /* XXX FAILURE: clean up and then free the struct */
        return NULL;
    }

#if 0
    /* XXX this is always over-ridden by SSL_set_app_data */
    /* Allows us to get context struct from within OpenSSL callbacks */
    SSL_CTX_set_app_data (sslcontext->sslctx, sslcontext);
#endif

    /* Enable SSL bug compatibility */
    SSL_CTX_set_options (sslcontext->sslctx, SSL_OP_ALL);

    /* This apparently prevents some sort of DH attack */
    SSL_CTX_set_options (sslcontext->sslctx, SSL_OP_SINGLE_DH_USE);

    /* Temporary key callback required for 40-bit export browsers */
    SSL_CTX_set_tmp_rsa_callback (sslcontext->sslctx, IssueTmpRSAKey);

    /* Insert the context into the linked list */

    /* XXX lock firstSSLContext before modifying */
    /* XXX these need to be merged into virtual server table */
    if (firstSSLContext != NULL) {
	    /* There are already other contexts */
	    sslcontext->next = firstSSLContext;
	    firstSSLContext = sslcontext;
    } else {
	    /* We're the first context created */
	    sslcontext->next = NULL;
	    firstSSLContext = sslcontext;
    }

    /* XXX need locking at startup? */
    //Ns_MutexUnlock(&sslcontext->lock);

    return sslcontext;
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
Ns_OpenSSLContextDestroy(Ns_OpenSSLContext *sslcontext)
{
    /* XXX fill this in */
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
PeerVerifyCallback (int preverify_ok, X509_STORE_CTX *x509_ctx)
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
IssueTmpRSAKey (SSL *ssl, int export, int keylen)
{
    Ns_OpenSSLConn *sslconn;
    static RSA *rsa_tmp;

    sslconn = (Ns_OpenSSLConn *) SSL_get_app_data (ssl);

    rsa_tmp = RSA_generate_key (keylen, RSA_F4, NULL, NULL);
    if (rsa_tmp == NULL) {
        Ns_Log(Error, "%s: %s: Temporary RSA key generation failed",
                MODULE, sslconn->ssldriver->server);
    } else {
        Ns_Log (Notice, "%s: %s: Generated %d-bit temporary RSA key",
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
OpenSSLTrace (SSL *ssl, int where, int rc)
{
    Ns_OpenSSLConn *sslconn;
    char *alertTypePrefix;
    char *alertType;
    char *alertDescPrefix;
    char *alertDesc;

    Ns_Log(Debug, "*** HERE in TRACE");

    sslconn = (Ns_OpenSSLConn *) SSL_get_app_data (ssl);

    if (where & SSL_CB_ALERT) {
	alertTypePrefix = "; alert type = ";
	alertType = SSL_alert_type_string_long (rc);
	alertDescPrefix = "; alert desc = ";
	alertDesc = SSL_alert_desc_string_long (rc);
    } else {
	alertTypePrefix = alertType = "";
	alertDescPrefix = alertDesc = "";
    }

    Ns_Log (Notice, "%s: trace: %s: %s%s%s%s%s",
	    MODULE,
            sslconn->type,
	    SSL_state_string_long (ssl),
	    alertTypePrefix, alertType, alertDescPrefix, alertDesc);
}

