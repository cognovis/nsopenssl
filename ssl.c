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
 * ssl.c --
 *
 *     Implements functions dealing with SSL_CTXs and SSL instance structures.
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#ifdef _WIN32
#define SHUT_WR SD_SEND
#endif

#include "nsopenssl.h"
#include <netinet/tcp.h>

/* XXX put into defaults.h */
#define BUFSIZE 2048

typedef struct Stream {
    NsOpenSSLConn *sslconn;
    int error;
    int cnt;
    char *ptr;
    char buf[BUFSIZE + 1];
} Stream;

static int
GetLine(Stream *sPtr, Ns_DString *dsPtr);

static int
FillBuf(Stream *sPtr);


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnCreate --
 *
 *     Create an SSL connection. The socket has already been accept()ed and is
 *     ready for reading/writing.
 * 
 * Results:
 *     Pointer to sslconn, which might be NULL
 *
 * Side effects:
 *     If the SSL connection was open then it will be forced to close first.
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLConn *
NsOpenSSLConnCreate(SOCKET socket, NsOpenSSLContext *sslcontext)
{
    NsOpenSSLConn *sslconn  = NULL;
    int            status   = NS_FALSE;
    int            n        = 1;

    if (Ns_InfoShutdownPending()) {
        Ns_Log(Notice,
                "%s (%s): connection refused due to server shutdown pending",
                MODULE, sslcontext->server);

    }
    sslconn = ns_calloc(1, sizeof(NsOpenSSLConn));
    if (sslconn == NULL) {
        Ns_Log(Error, "%s (%s): failed to create SSL connection structure",
                MODULE, sslcontext->server);
        return NULL;
    }
    //Ns_Log(Debug, "NsOpenSSLConnCreate(%p)", sslconn);

    /*
     * Default is a core-driven connection. Connections created by nsopenssl's
     * Tcl API are responsible for setting this value to TCLAPI.
     */

    sslconn->type            = CORE;

    /*
     * Set connection structure initial values.
     */

    sslconn->server          = sslcontext->server;
    sslconn->sslcontext      = sslcontext;
    sslconn->socket          = socket;
    sslconn->sendwait        = DEFAULT_SENDWAIT;
    sslconn->recvwait        = DEFAULT_RECVWAIT;
    sslconn->ssl             = NULL;
    sslconn->sslctx          = NULL;
    sslconn->peerport        = -1;

    /*
     * It's the caller's responsibility to increment the reference count; the
     * same connection may be referenced multiple times simultaneously as when
     * we wrap the Tcl channels around a connection socket.
     */

    sslconn->refcnt     = 0;

    /* It's GMT, but we use this to do time diffs */
    gettimeofday(&sslconn->timer, NULL);

    /*
     * Instantiate the SSL structure from the sslcontext.
     */

    sslconn->ssl = SSL_new(sslcontext->sslctx);
    if (sslconn->ssl == NULL) {
        Ns_Log(Error, "%s (%s): failed to create new SSL structure",
                MODULE, sslcontext->server);
        NsOpenSSLConnDestroy(sslconn);
        return NULL;
    }
    SSL_clear(sslconn->ssl);

    /*
     * Associate the socket with the SSL instance. 
     */

    SSL_set_fd(sslconn->ssl, socket);

    /*
     * Associate the connection structure with the SSL instance.
     */

    SSL_set_app_data(sslconn->ssl, sslconn);

    /*
     * Define the SSL instance's role.
     */

    if (sslcontext->role == SERVER_ROLE) {
        SSL_set_accept_state(sslconn->ssl);
    } else {
        SSL_set_connect_state(sslconn->ssl);
    }

#if 0

    /*
     * XXX don't need to explicitly run the handshake. Run the SSL handshake.
     */

    if (NsOpenSSLConnHandshake(sslconn) != NS_OK) {
        NsOpenSSLConnDestroy(sslconn);
    }
#endif 

#if 0
/* XXX add as config option before turning on */
    /*
     * Turn off the Nagle algorithm. The Nagle algorithm waits for the ACK to
     * come back from the first packet sent before sending any further packets,
     * in hopes that the TCP output buffer has more data. It is intended to
     * increase the efficiency of network bandwidth usage by preventing lots of
     * small packets from being tranmitted the second the hit the TCP buffer,
     * thus clogging the network. For SSL the Nagle algorithm doesn't make much
     * sense as SSL will just about always have larger chunks of data to send;
     * in our case Nagle just slows down SSL handshake and communications for
     * no real benefit in network bandwidth usage.
     */

    if (setsockopt(sslconn->socket, IPPROTO_TCP, TCP_NODELAY, (char *) &n, sizeof(n)) == -1) {
        Ns_Log(Warning, "%s (%s): unable to turn off Nagle algorithm", MODULE, sslconn->server);
    }
#endif

    return sslconn;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnDestroy --
 *
 *      Destroy an SSL connection.
 *
 * Results:
 *      None.
 *
 * Side effects: 
 *      If the SSL connection was open then it will be forced to close first.
 *      If the connection is still being referenced, no action is taken.
 *
 *----------------------------------------------------------------------
 */

extern void
NsOpenSSLConnDestroy(NsOpenSSLConn *sslconn)
{
    int i  = 0;
    int rc = 0;

    //Ns_Log(Debug, "NsOpenSSLConnDestroy(%p)", sslconn);

    if (sslconn == NULL) {
	return;
    }

    /*
     * Don't destroy the connection if it's still referenced somewhere.
     */

    sslconn->refcnt--;
    if (sslconn->refcnt > 0) {
	return;
    }


        /*
         * Shutdown the Tcl channel wrapped around the socket, if there is one.
         */

//        if (sslconn->chan != NULL) {
//            Ns_Log(Debug, "*** CHAN: DESTROYING: %s", Tcl_GetChannelName(sslconn->chan));
//            Tcl_UnregisterChannel(NULL, sslconn->chan);
//        }

    /*
     * Shutdown the SSL connection and free the SSL structure.
     */

    if (sslconn->ssl != NULL) {
	// SSL_set_shutdown(sslconn->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
	for (i = rc = 0; rc == 0 && i < 4; i++) {
	    rc = SSL_shutdown(sslconn->ssl);
	}
	SSL_free(sslconn->ssl);
    }

    /*
     * Shutdown and close the socket itself, but only if it's an nsopenssl Tcl
     * API-created socket. If the core server is driving the socket, we leave
     * it alone and let the core driver do what it wants with it.
     */

    //if (sslconn->type == TCLAPI) {
    //    if (sslconn->socket != INVALID_SOCKET) {
//	    shutdown(sslconn->socket, SHUT_RDWR);
//            ns_sockclose(sslconn->socket);
//            sslconn->socket = INVALID_SOCKET;
//        }
//    }
    ns_free(sslconn);
    sslconn = NULL;

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
 *      A pointer to a new NsOpenSSLConn structure.
 *
 * Side effects:
 *      Runs the SSL handshake.
 *
 *----------------------------------------------------------------------
 */

extern NsOpenSSLConn *
Ns_OpenSSLSockConnect(char *server, char *host, int port, int async, int timeout,
                      NsOpenSSLContext *sslcontext)
{
    NsOpenSSLConn *sslconn = NULL;
    SOCKET         socket  = INVALID_SOCKET;

    /*
     * Create the socket connection.
     */

    if (timeout < 0) {
        socket = Ns_SockConnect(host, port);
    } else {
        socket = Ns_SockTimedConnect(host, port, timeout);
    }
    if (socket == INVALID_SOCKET) {
        return NULL;
    }

    /*
     * Wrap SSL around the socket.
     */

    sslconn = NsOpenSSLConnCreate(socket, sslcontext);
    sslconn->type = TCLAPI;
    if (sslconn != NULL) {
        sslconn->refcnt++;
        if (async) {
            Ns_SockSetNonBlocking(sslconn->socket);
        } else {
            Ns_SockSetBlocking(sslconn->socket);
        }
    }

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

extern NsOpenSSLConn *
Ns_OpenSSLSockAccept(SOCKET sock, NsOpenSSLContext *sslcontext)
{
    NsOpenSSLConn *sslconn = NULL;

    if (sock == INVALID_SOCKET) {
        Ns_Log(Error, "%s (%s): attempted accept on invalid socket",
                MODULE, sslcontext->server);
        return NULL;
    }

    /*
     * Wrap SSL around socket.
     */

    sslconn = NsOpenSSLConnCreate(sock, sslcontext);
    sslconn->type = TCLAPI;
    if (sslconn != NULL) {
        sslconn->refcnt++;
        Ns_SockSetNonBlocking(sslconn->socket);
    }

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

extern SOCKET
Ns_OpenSSLSockListen(char *addr, int port)
{
    return Ns_SockListen(addr, port);
}

#if 0

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

extern int
Ns_OpenSSLIsPeerCertValid(NsOpenSSLConn *sslconn)
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
#endif


/*                     
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLFetchUrl --
 *
 *      Open up an HTTPS connection to an arbitrary URL.
 *
 * Results:
 *      NS_OK or NS_ERROR.  
 *
 * Side effects: 
 *      Page contents will be appended to the passed-in dstring.  Headers
 *      returned to us will be put into the passed-in Ns_Set.  The set name
 *      will be changed to a copy of the HTTP status line.
 *
 *----------------------------------------------------------------------
 */

extern int
Ns_OpenSSLFetchUrl(char *server, Ns_DString *dsPtr, char *url,
        Ns_Set *headers, NsOpenSSLContext *sslcontext)
{
    NsOpenSSLConn *sslconn = NULL;
    Ns_Request    *request = NULL;
    Ns_DString     ds;
    Stream         stream;
    char          *p       = NULL;
    int            status  = NS_ERROR;
    int            tosend  = 0;
    int            n       = 0;

    Ns_DStringInit(&ds);

    /*
     * Parse the URL and open a connection.
     */

    Ns_DStringVarAppend(&ds, "GET ", url, " HTTP/1.0", NULL);
    request = Ns_ParseRequest(ds.string);
    if (
            request == NULL || 
            request->protocol == NULL ||
            !STREQ(request->protocol, "https") || 
            request->host == NULL
       ) {
        Ns_Log(Notice, "urlopen: invalid url '%s'", url);
        goto done;
    }

    /*
     * Open an SSL connection.
     */

    if (request->port == 0) {
        request->port = 443;
    }
    sslconn = Ns_OpenSSLSockConnect(server, request->host, request->port, 0, 300, sslcontext);
    if (sslconn == NULL) {
        Ns_Log(Error, "%s (%s): Ns_OpenSSLFetchURL: failed to connect to '%s'",
                MODULE, server, url);
        goto done;
    }

    /*
     * Send HTTP GET request.
     */

    Ns_DStringTrunc(&ds, 0);
    Ns_DStringVarAppend(&ds, "GET ", request->url, NULL);
    if (request->query != NULL) {
        Ns_DStringVarAppend(&ds, "?", request->query, NULL);
    }
    Ns_DStringAppend(&ds, " HTTP/1.0\r\nAccept: */*\r\n\r\n");
    p = ds.string;
    tosend = ds.length;
    while (tosend > 0) {
        //n = NsOpenSSLConnSend(sslconn->ssl, p, tosend);
        n = NsOpenSSLConnOp(sslconn->ssl, p, tosend, NSOPENSSL_SEND);
        if (n <= 0) {
            Ns_Log(Error, "%s (%s): failed to send data to '%s'", 
                    MODULE, server, url);
            goto done;
        }
        tosend -= n;
        p += n;
    }

    /*
     * Buffer the socket and read the response line and then consume the
     * headers, parsing them into any given header set.
     */

    stream.cnt     = 0;
    stream.error   = 0;
    stream.ptr     = stream.buf;
    stream.sslconn = (NsOpenSSLConn *) sslconn;
    if (!GetLine (&stream, &ds)) {
        goto done;
    }
    if (headers != NULL && strncmp(ds.string, "HTTP", 4) == 0) {
        if (headers->name != NULL) {
            ns_free (headers->name);
        }
        headers->name = Ns_DStringExport(&ds);
    }
    do {
        if (!GetLine (&stream, &ds)) {
            goto done;
        }
        if (ds.length > 0
                && headers != NULL
                && Ns_ParseHeader(headers, ds.string, Preserve) != NS_OK) {
            goto done;
        }
    } while (ds.length > 0);

    /*
     * Without any check on limit or total size, foolishly read
     * the remaining content into the dstring.
     */

    do {
        Ns_DStringNAppend(dsPtr, stream.ptr, stream.cnt);
    } while (FillBuf(&stream));
    if (!stream.error) {
        status = NS_OK;
    }

done:
    if (request != NULL) {
        Ns_FreeRequest(request);
    }
    if (sslconn != NULL) {
        NsOpenSSLConnDestroy(sslconn);
    }
    Ns_DStringFree(&ds);

    return status;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnOp --
 *
 *     Send/Recv data through an SSL connection.
 *
 * Results:
 *     The number of bytes send or a negative number in case of an error.
 *
 * Side effects:
 *     SSL handshake will be performed if it hasn't been.
 *
 *----------------------------------------------------------------------
 */

extern int
NsOpenSSLConnOp(SSL *ssl, void *buffer, int bytes, int type)
{
    NsOpenSSLConn *sslconn = SSL_get_app_data(ssl);
    SOCKET         socket  = SSL_get_fd(ssl);
    int n, err;
    char *dir;
    
    /*
     * Perhaps we should enable SSL_MODE_AUTO_RETRY to avoid having to
     * handle retries in the case of SSL re-negotiation.
     */

retry:
    switch (type) {
        case NSOPENSSL_RECV:
            dir = "read";
            n = SSL_read(ssl, (char *) buffer, bytes);
            break;

        case NSOPENSSL_SEND:
            /*
             * Unless the SSL_MODE_ENABLE_PARTIAL_WRITE option is
             * set via SSL_CTX_set_mode(), then SSL_write() returns
             * successful only when the entire buffer is written.
             */

            dir = "write";
            n = SSL_write(ssl, (char *) buffer, bytes);
            break;

        default:
            Ns_Log(Error, "%s (%s): Invalid command '%d'",
                    MODULE, sslconn->server, type); 
            return -1;
    }

    switch (SSL_get_error(ssl, n)) {
        case SSL_ERROR_NONE:
            /* Success: n > 0 */
            break;

        case SSL_ERROR_ZERO_RETURN:
            /* Transport close alert received. */
            Ns_Log(Warning, "%s (%s): SSL %s: socket gone; disconnected by client?",
                    MODULE, sslconn->server, dir);
            n = -1;
            break;

        case SSL_ERROR_WANT_WRITE:
            if (Ns_SockWait(sslconn->socket, NS_SOCK_WRITE, sslconn->sendwait)
                    != NS_OK) {
                n = -1;
                break;
            }
            goto retry;

        case SSL_ERROR_WANT_READ:
            if (Ns_SockWait(sslconn->socket, NS_SOCK_READ, sslconn->recvwait)
                    != NS_OK) {
                n = -1;
                break;
            }
            goto retry;

        case SSL_ERROR_WANT_X509_LOOKUP:
            Ns_Log(Warning, "%s (%s): SSL %s wants X509 Lookup; unsupported?",
                    MODULE, sslconn->server, dir);
            n = -1;
            break;

        case SSL_ERROR_SYSCALL:
            err = ERR_get_error();
            if (err) {
                Ns_Log(Warning, "%s (%s): SSL %s interrupted: %s",
                    MODULE, sslconn->server, dir, ERR_reason_error_string(err));
            } else if (n == 0) {
                Ns_Log(Warning, "%s (%s): SSL %s interrupted: unexpected eof",
                    MODULE, sslconn->server, dir);
            } else {
                Ns_Log(Warning, "%s (%s): SSL %s interrupted: %s",
                    MODULE, sslconn->server, dir, ns_sockstrerror(ns_sockerrno));
            }
            n = -1;
            break;

        case SSL_ERROR_SSL:
            Ns_Log(Error, "%s (%s): SSL %s error: %s",
                    MODULE, sslconn->server, dir,
                    ERR_reason_error_string(ERR_get_error()));
            n = -1;
            break;

        default:
            Ns_Log(Error, "%s (%s): Unknown SSL %s error code in ssl.c (%d)",
                    MODULE, sslconn->server, dir, n);
            n = -1;
            break;
    }

    /*
     * On error, we mark the SSL conn as received shutdown so that later
     * on, when we try to flush, we can detect that the conn has been
     * shut down.
     */

    if (n < 0) {
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    }

    return n;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnFlush --
 *
 *      Flush an SSL connection.
 *
 * Results:
 *      Always NS_OK.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLConnFlush(NsOpenSSLConn *sslconn)
{
    SSL *ssl = sslconn->ssl;
    BIO *bio;

    if (ssl != NULL) {
        if (SSL_get_shutdown(ssl) != 0) {
            return NS_ERROR;
        }
        bio = SSL_get_wbio(ssl);
        if (bio == NULL) {
            return NS_ERROR;
        }
        if (BIO_flush(bio) < 1) {
            Ns_Log(Error, "%s (%s): BIO returned error on flushing buffer",
                    MODULE, sslconn->server);
            return NS_ERROR;
        }
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 * 
 * FillBuf --
 * 
 *      Fill the socket stream buffer.
 *
 * Results:
 *      NS_TRUE if fill ok, NS_FALSE otherwise.
 *
 * Side effects:       
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
FillBuf(Stream *sPtr)
{
    //int n      = NsOpenSSLConnRecv(sPtr->sslconn->ssl, sPtr->buf, BUFSIZE);
    int n      = NsOpenSSLConnOp(sPtr->sslconn->ssl, sPtr->buf, BUFSIZE, NSOPENSSL_RECV);
    int status = NS_TRUE;

    if (n > 0) {
        sPtr->buf[n] = '\0';
        sPtr->ptr    = sPtr->buf;
        sPtr->cnt    = n;
    } else if (n == 0) {    
        status       = NS_FALSE;
    } else {
        Ns_Log(Error, "FillBuf: failed to fill socket stream buffer");
        sPtr->error  = 1;
        status       = NS_FALSE;
    }

    return status;
}


/*
 *----------------------------------------------------------------------
 *   
 * GetLine --
 *
 *      Copy the next line from the stream to a dstring, trimming
 *      the \n and \r.
 *
 * Results:
 *      NS_TRUE or NS_FALSE.
 *
 * Side effects:
 *      The dstring is truncated on entry.
 *
 *----------------------------------------------------------------------
 */

static int
GetLine(Stream *sPtr, Ns_DString *dsPtr)
{
    char *eol = NULL;
    int   n   = 0;

    Ns_DStringTrunc(dsPtr, 0);
    do {
        if (sPtr->cnt > 0) {
            eol = strchr(sPtr->ptr, '\n');
            if (eol == NULL) {
                n = sPtr->cnt;
            } else {
                *eol++ = '\0';
                n = eol - sPtr->ptr;
            }
            Ns_DStringNAppend (dsPtr, sPtr->ptr, n - 1);
            sPtr->ptr += n;
            sPtr->cnt -= n;
            if (eol != NULL) {
                n = dsPtr->length;
                if (n > 0 && dsPtr->string[n - 1] == '\r') {
                    Ns_DStringTrunc (dsPtr, n - 1);
                }
                return NS_TRUE;
            }
        }
    } while (FillBuf(sPtr));

    return NS_FALSE;
}
