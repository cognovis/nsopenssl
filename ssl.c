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
 *	Create an SSL connection. The socket has already been accept()ed
 *      and is ready for reading/writing.
 *
 *      BIO stack:
 *
 *        nsopenssl module
 *        buffering BIO
 *        SSL BIO
 *        socket BIO
 *        TCP socket to client
 *
 * Results:
 *      sslconn, which might be NULL
 *
 * Side effects:
 *      If the SSL connection was open then it will be forced to close
 *      first.
 *
 *----------------------------------------------------------------------
 */

NsOpenSSLConn *
NsOpenSSLConnCreate(SOCKET socket, NsOpenSSLContext *sslcontext)
{
    NsOpenSSLConn *sslconn  = NULL;
    BIO           *sock_bio = NULL;
    BIO           *ssl_bio  = NULL;
    int            status   = NS_FALSE;

    if (Ns_InfoShutdownPending()) {
	Ns_Log(Notice,
		"%s (%s): connection refused due to server shutdown pending",
		MODULE, sslcontext->server);
	return NULL;
    }

    sslconn = ns_calloc(1, sizeof(NsOpenSSLConn));
    if (sslconn == NULL) {
	Ns_Log(Error, "%s (%s): failed to create SSL connection structure",
		MODULE, sslcontext->server);
	return NULL;
    }

    sslconn->server     = sslcontext->server;
    sslconn->sslcontext = sslcontext;
    sslconn->wsock      = INVALID_SOCKET;
    sslconn->ssl        = NULL;
    sslconn->bio        = NULL;
    sslconn->sslctx     = NULL;
    sslconn->peerport   = -1;
    sslconn->socket     = socket;

    /*
     * It's the caller's responsibility to increment the reference count; the
     * same connection may be referenced multiple times simultaneously as when
     * we wrap the Tcl channels around a connection socket.
     */

    sslconn->refcnt     = 0;

    /* Initialize the SSL structure */

    sslconn->ssl = SSL_new(sslcontext->sslctx);
    if (sslconn->ssl == NULL) {
	Ns_Log(Error, "%s (%s): failed to create new SSL structure",
		MODULE, sslcontext->server);
	NsOpenSSLConnDestroy(sslconn);
	return NULL;
    }

    SSL_clear(sslconn->ssl);
    SSL_set_app_data(sslconn->ssl, sslconn);

    /* Create socket BIO and attach it to the socket */
    sock_bio = BIO_new_socket(sslconn->socket, BIO_NOCLOSE);

    /* Create SSL BIO and attach it to the socket BIO */
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, sslconn->ssl, BIO_NOCLOSE);
    BIO_push(ssl_bio, sock_bio);

    /* Create buffering BIO and attach it to the SSL BIO */
    sslconn->bio = BIO_new(BIO_f_buffer());
    BIO_set_write_buffer_size(sslconn->bio, sslconn->sslcontext->bufsize);
    BIO_set_read_buffer_size(sslconn->bio, sslconn->sslcontext->bufsize);
    BIO_push(sslconn->bio, ssl_bio);

    /* Run the SSL handshake on the connection */
    if (sslcontext->role == SERVER_ROLE) {
	SSL_set_accept_state(sslconn->ssl);
	status = NsOpenSSLConnAccept(sslconn);
    } else if (sslcontext->role == CLIENT_ROLE) {
	SSL_set_connect_state(sslconn->ssl);
	status = NsOpenSSLConnConnect(sslconn);
    }

    if (status != NS_OK) {
	NsOpenSSLConnDestroy(sslconn);
	sslconn = NULL;
    }

    Ns_Log(Debug, "NsOpenSSLConnCreate: sslconn = (%p), sslcontext = (%p)",
	    sslconn, sslcontext);

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

    sslconn->refcnt--;

    if (sslconn->refcnt > 0) {
	Ns_Log(Debug, "NsOpenSSLConnDestroy: SSL conn still active: refcnt = (%d), sslconn = (%p)", sslconn->refcnt, sslconn);
	return;
    }

    if (sslconn == NULL)
	return;

    Ns_Log(Debug, "NsOpenSSLConnDestroy: sslconn = (%p)", sslconn);

    if (sslconn->ssl != NULL) {
	/* XXX review these shutdown procedures w/r to SSL_shutdown man page */
	/* XXX seems we can clean this up a bit */
	SSL_set_shutdown(sslconn->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

	/* Call SSL_shutdown repeatedly until we're sure it's done. */
	for (i = rc = 0; rc == 0 && i < 4; i++) {
	    rc = SSL_shutdown(sslconn->ssl);
	}
    }

    /*
     * We disallow sending through the socket, since BIO_free_all triggers
     * SSL_shutdown, which is sending something (2 bytes).  It confuses Win32
     * clients, since they automatically close socket on FIN packet only if
     * there is no waiting received bytes (it gives "connection reset" message
     * in MSIE when socket is freed by keepalive thread).
     */

    if (sslconn->socket != INVALID_SOCKET) 
	shutdown(sslconn->socket, SHUT_WR);

    if (sslconn->bio != NULL)
	BIO_free_all(sslconn->bio);

    if (sslconn->ssl != NULL) 
	SSL_free(sslconn->ssl);

    ns_free(sslconn);
    sslconn = NULL;

    return;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnRecv --
 *
 *      Read data from an SSL connection
 *
 * Results:
 *      The number of bytes read or a negative number in case of
 *      an error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

extern int
NsOpenSSLConnRecv(BIO *bio, void *buffer, int toread)
{
    int rc     = -1;
    int socket = INVALID_SOCKET;

    /*
     * Check the socket to see if it's still alive. If the client
     * aborts the connection during a file upload, the BIO read will
     * loop forever, using cpu cycles, but reading no further
     * data. Note that checking to see if sock is INVALID_SOCKET
     * doesn't always work here.
     */

    /* XXX uncomment */
#if 0
    if (send(sslconn->socket, NULL, 0, 0) != 0) {
        Ns_Log(Notice, "%s (%s): connection reset by peer",
                MODULE, sslconn->server);
        return NS_ERROR;
    }
#endif

    BIO_get_fd(bio, &socket);

    do {
        rc = BIO_read(bio, buffer, toread);
        Ns_Log(Debug, "NsOpenSSLConnRecv: read = (%d); sock = (%d)", rc, socket);
    } while (
            rc < 0 && 
            rc < toread &&
            BIO_should_retry(bio) &&
            Ns_SockWait(socket, NS_SOCK_READ, 2) == NS_OK
            );
    

    return rc;
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

    Ns_Log(Debug, "Ns_OpenSSLSockConnect %s %d", host, port);
    Ns_Log(Debug, "Ns_OpenSSLSockConnect: sslcontext = (%p)", sslcontext);
    Ns_Log(Debug, "Ns_OpenSSLSockConnect: sslcontext->initialized = (%d)", sslcontext->initialized);

    if (timeout < 0) {
        socket = Ns_SockConnect(host, port);
    } else {
        socket = Ns_SockTimedConnect(host, port, timeout);
    }

    if (socket == INVALID_SOCKET) {
        return NULL;
    }

    sslconn = NsOpenSSLConnCreate(socket, sslcontext);
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

    Ns_Log(Debug, "Ns_OpenSSLSockAccept: sslcontext = (%p)", sslcontext);

    if (sock == INVALID_SOCKET) {
        Ns_Log(Error, "%s (%s): attempted accept on invalid socket",
                MODULE, sslcontext->server);
        return NULL;
    }

    sslconn = NsOpenSSLConnCreate(sock, sslcontext);
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

/* XXX move to x509.c; change args */
/* XXX add *server arg */
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
    /* XXX uninitialized */
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
     * Send a simple HTTP GET request.
     */

    // SendHTTPGet(url, query, )
    Ns_DStringTrunc(&ds, 0);
    Ns_DStringVarAppend(&ds, "GET ", request->url, NULL);

    if (request->query != NULL) {
        Ns_DStringVarAppend(&ds, "?", request->query, NULL);
    }

    Ns_DStringAppend(&ds, " HTTP/1.0\r\nAccept: */*\r\n\r\n");
    p = ds.string;
    tosend = ds.length;

    while (tosend > 0) {
        n = NsOpenSSLConnSend(sslconn->bio, p, tosend);
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
 * NsOpenSSLConnSend --
 *
 *     Send data through an SSL connection
 *
 * Results:
 *     The number of bytes send or a negative number in case of an error.
 *
 * Side effects:
 *     None.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLConnSend(BIO *bio, void *buffer, int towrite)
{
    int    rc     = 0;
    int    total  = towrite;
    /* XXX temporary */
    SOCKET socket = INVALID_SOCKET;

    /* XXX temporary */
    BIO_get_fd(bio, &socket);

    do {
	rc = BIO_write(bio, buffer, towrite);
	Ns_Log(Debug, "NsOpenSSLConnSend: wrote = (%d); sock = (%d)", rc, socket);
	BIO_flush(bio);
    } while (
	    rc < towrite && 
	    BIO_should_retry(bio) &&
	    BIO_should_write(bio)
	    );

    return rc;
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
    if (sslconn->ssl != NULL) {
        if (BIO_flush(SSL_get_wbio(sslconn->ssl)) < 1) {
            Ns_Log(Error, "%s (%s): BIO returned error on flushing buffer",
                    MODULE, sslconn->server);
        }
        return NS_OK;
    }

    return NS_ERROR;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnAccept --
 *
 *      Run the server-side SSL handshake. 
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

extern int
NsOpenSSLConnAccept(NsOpenSSLConn *sslconn)
{
    int rc = -1;

    do {
	rc = BIO_do_handshake(sslconn->bio);
    } while (rc < 0 && BIO_should_retry(sslconn->bio));

    if (rc < 0) {
	return NS_ERROR;
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnConnect --
 *
 *	Run the client-side SSL handshake.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *	Sets pointer to peer certificate
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLConnConnect(NsOpenSSLConn *sslconn)
{
    int rc = -1;

    do {
	rc = BIO_do_handshake (sslconn->bio);
    } while (rc < 0 && BIO_should_retry(sslconn->bio));

    if (rc < 0) {
	return NS_ERROR;
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
    int n      = NsOpenSSLConnRecv(sPtr->sslconn->bio, sPtr->buf, BUFSIZE);
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

#if 0

/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLErrorDump --
 *
 *     Send data through an SSL connection
 *
 * Results:
 *     The number of bytes send or a negative number in case of an error.
 *
 * Side effects:
 *     None.
 *
 *----------------------------------------------------------------------
 */

void
NsOpenSSLErrorDump(NsOpenSSLConn *sslconn, int code) 
{
    int           error = 0;
    unsigned long e     = 0;

    error = SSL_get_error(sslconn->ssl, code);

    switch (error) {
        case SSL_ERROR_NONE:
            Ns_Log(Debug, "--- SSL_ERROR_NONE");
            break;
        case SSL_ERROR_ZERO_RETURN:
            Ns_Log(Debug, "--- SSL_ERROR_ZERO_RETURN");
            break;
        case SSL_ERROR_WANT_READ:
            Ns_Log(Debug, "--- SSL_ERROR_WANT_READ");
            break;
        case SSL_ERROR_WANT_WRITE:
            Ns_Log(Debug, "--- SSL_ERROR_WANT_WRITE");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            Ns_Log(Debug, "--- SSL_ERROR_WANT_X509_LOOKUP");
            break;
        case SSL_ERROR_SYSCALL:
            Ns_Log(Debug, "--- SSL_ERROR_SYSCALL");
            break;
        case SSL_ERROR_SSL:
            Ns_Log(Debug, "--- SSL_ERROR_SSL");
            break;
    }

    while ((e = ERR_get_error()) != 0) {
        Ns_Log(Debug, "--- ERR    = %s", ERR_error_string(e, NULL));
        Ns_Log(Debug, "  - LIB    = %d", ERR_GET_LIB(e));
        Ns_Log(Debug, "  - FUNC   = %d", ERR_GET_FUNC(e));
        Ns_Log(Debug, "  - REASON = %d", ERR_GET_REASON(e));
    }
}
#endif
