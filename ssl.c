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
 * Copyright (C) 1999 Stefan Arentz.
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#ifndef WIN32
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "nsopenssl.h"

/*
 * Local functions defined in this file
 */

static int RunSSLHandshake (Ns_OpenSSLConn *sslconn);
static int RunServerSSLHandshake (Ns_OpenSSLConn *sslconn);
static void DestroySSLSockConn (Ns_OpenSSLConn *sslconn);


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
 *      NS_ERROR or NS_OK.
 *
 * Side effects:
 *      If the SSL connection was open then it will be forced to close
 *      first.
 *
 *----------------------------------------------------------------------
 */

Ns_OpenSSLConn *
NsOpenSSLConnCreate(SOCKET sock, NsOpenSSLDriver *ssldriver, 
        Ns_OpenSSLContext *sslcontext)
{
    Ns_OpenSSLConn *sslconn;
    BIO *sock_bio;
    BIO *ssl_bio;

    sslconn = ns_calloc(1, sizeof(Ns_OpenSSLConn));

    sslconn->server     = sslcontext->server;
    sslconn->module     = sslcontext->module;
    sslconn->role       = sslcontext->role;
    sslconn->ssldriver  = ssldriver; /* NULL if not driven by AOLserver comm driver */
    sslconn->sslcontext = sslcontext;
    sslconn->next       = NULL;
    sslconn->ssl        = NULL;
    sslconn->io         = NULL;
    sslconn->peercert   = NULL;
    sslconn->refcnt     = 0;
    sslconn->peerport   = -1;
    sslconn->sock       = sock;
    sslconn->wsock      = INVALID_SOCKET;

    /* Create the SSL struct for a connection */

    sslconn->ssl = SSL_new (sslcontext->sslctx);
    if (sslconn->ssl == NULL) {
        Ns_Log (Error, ": %s: error creating sslconn->ssl structure",
            MODULE, sslconn->server);
        return NS_ERROR;
    }
    SSL_clear (sslconn->ssl);
    SSL_set_app_data (sslconn->ssl, sslconn);

    if (STRIEQ(sslconn->role, ROLE_SERVER)) {
        SSL_set_accept_state (sslconn->ssl);
    } else if (STRIEQ(sslconn->role, ROLE_CLIENT)) {
        SSL_set_connect_state (sslconn->ssl);
    } else {
        Ns_Log(Error, "%s: %s: SSL context '%s' role is wrong!",
                sslconn->server, MODULE, sslconn->role);
        return NS_ERROR;
    }

    /* Create socket BIO and attach it to the socket */

    sock_bio = BIO_new_socket (sslconn->sock, BIO_NOCLOSE);

    /* Create SSL BIO */

    ssl_bio = BIO_new (BIO_f_ssl ());
    BIO_set_ssl (ssl_bio, sslconn->ssl, BIO_NOCLOSE);
    BIO_push (ssl_bio, sock_bio);

    /* Create buffering BIO */

    sslconn->io = BIO_new (BIO_f_buffer ());
    /* XXX using core driver's value for bufsize here */
    if (!BIO_set_write_buffer_size (sslconn->io, sslconn->sslcontext->bufsize)) {
        Ns_Log(Error, "%s: %s: BIO_set_write_buffer_size failed", sslconn->server, MODULE);
	return NS_ERROR;
    }
    BIO_push (sslconn->io, ssl_bio);

    if (RunSSLHandshake (sslconn) == NS_ERROR) {
        /* XXX these steps happen often enough; put in NsOpenSSLConnDestroy */
        SSL_set_shutdown (sslconn->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        NsOpenSSLShutdown (sslconn->ssl);
        NsOpenSSLConnDestroy (sslconn);
        return NULL;
    }

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

int
NsOpenSSLConnDestroy (Ns_OpenSSLConn *sslconn)
{
    if (sslconn->refcnt > 0) {
        Ns_Log(Warning, "%s: %s: attempt to destroy an active SSL connection",
                sslconn->server, MODULE);
        return NS_ERROR;
    }

    if (sslconn != NULL) {

	/*
         * We disallow sending through the socket, since BIO_free_all triggers
         * SSL_shutdown, which is sending something (2 bytes).  It confuses
         * Win32 clients, since they automatically close socket on FIN packet
         * only if there is no waiting received bytes (it gives "connection
         * reset" message in MSIE when socket is freed by keepalive thread).
	 */

        if (sslconn->sock != INVALID_SOCKET) {
            shutdown(sslconn->sock, SHUT_WR);
        }

	if (sslconn->peercert != NULL) {
	    X509_free (sslconn->peercert);
	    sslconn->peercert = NULL;
	}
	if (sslconn->io != NULL) {
	    BIO_free_all (sslconn->io);
	    sslconn->io = NULL;
	}
	if (sslconn->ssl != NULL) {
	    SSL_free (sslconn->ssl);
	    sslconn->ssl = NULL;
	}

	/*
         * We only free the connection structure if it's an SSL socket type not
         * tied to the comm API. If it is tied to the comm API, it's freed when
         * the comm driver shuts down.
	 */

	if (sslconn->ssldriver != NULL) {

	    if (sslconn->sock != INVALID_SOCKET) {
		ns_sockclose (sslconn->sock);
		sslconn->sock = INVALID_SOCKET;
	    }
	    
	    if (sslconn->wsock != INVALID_SOCKET) {
		ns_sockclose (sslconn->wsock);
		sslconn->wsock = INVALID_SOCKET;
	    }
	    
	    ns_free (sslconn);
	    sslconn = NULL;
	}
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLRecv --
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

int
NsOpenSSLRecv (Ns_OpenSSLConn *sslconn, void *buffer, int toread)
{
    int rc;

    /*
     * Check the socket to see if it's still alive. If the client
     * aborts the connection during a file upload, the BIO read will
     * loop forever, using cpu cycles, but reading no further
     * data. Note that checking to see if sock is INVALID_SOCKET
     * doesn't always work here.
     */

    if (send (sslconn->sock, NULL, 0, 0) != 0) {
	Ns_Log (Notice, "%s: %s: connection reset by peer",
		MODULE, sslconn->type);
	return NS_ERROR;
    }

    rc = BIO_read (sslconn->io, buffer, toread);
    Ns_Log (Debug, "NsOpenSSLRecv: read(1): %d %d", toread, rc);
    if (rc < 0 && BIO_should_retry (sslconn->io)
	&& Ns_SockWait (sslconn->sock, NS_SOCK_READ, 2) == NS_OK) {
	rc = BIO_read (sslconn->io, buffer, toread);
        Ns_Log (Debug, "NsOpenSSLRecv: read(2): %d %d", toread, rc);
    }

    return rc;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLSend --
 *
 *  Send data through an SSL connection
 *
 * Results:
 *  The number of bytes send or a negative number in case of
 *      an error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLSend (Ns_OpenSSLConn *sslconn, void *buffer, int towrite)
{
#if 0
    /* XXX how it was done in nsopenssl 1.1c */
    return SSL_write (sslconn->ssl, buffer, towrite);
#endif

    int rc;
    int total;

    total = towrite;

    do {
	rc = SSL_write (sslconn->ssl, buffer, towrite);
	if (rc > 0)
	    towrite -= rc;
    } while (BIO_should_retry (sslconn->ssl->wbio) &&
	     BIO_should_write (sslconn->ssl->wbio));

    return rc;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLFlush --
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
NsOpenSSLFlush (Ns_OpenSSLConn *sslconn)
{
    if (sslconn->ssl == NULL) {
	return NS_ERROR;
    } else {
	if (BIO_flush (SSL_get_wbio (sslconn->ssl)) < 1) {
	    Ns_Log (Error, "%s: BIO returned error on flushing buffer",
                    MODULE);
	}
    }

	return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLShutdown --
 *
 *      Shut down an SSL connection.
 *
 * Results:
 *	OpenSSL error code.
 *
 * Side effects:
 *	Calls SSL_shutdown multiple times to ensure the connection
 *      really has been shutdown.
 *
 * Note: based on SSL_smart_shutdown from mod_ssl, by Ralf Engelschall.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLShutdown (SSL *ssl)
{
    int i;
    int rc;

    /*
     * Call SSL_shutdown repeatedly until we're sure it's done.
     */

    for (i = rc = 0; rc == 0 && i < 4; i++) {
	rc = SSL_shutdown (ssl);
    }

    return rc;
}


/*
 *----------------------------------------------------------------------
 *
 * DestroySSLSockConn --
 *
 *      Free memory associated with an Ns_OpenSSLConn.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *
 *
 *----------------------------------------------------------------------
 */

static void
DestroySSLSockConn (Ns_OpenSSLConn *sslconn)
{
}


/*
 *----------------------------------------------------------------------
 *
 * RunSSLHandshake --
 *
 *	Run the SSL handshake sequence.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *	Sets pointer to peer certificate
 *
 *----------------------------------------------------------------------
 */

static int
RunSSLHandshake (Ns_OpenSSLConn *sslconn)
{
    int rc;
    //char buffer[256];
    //char *buf = (char *) &buffer;

    /* XXX reverse these -- server handshakes happen more often */
    if (STREQ(sslconn->role, ROLE_SERVER)) {
        return RunServerSSLHandshake (sslconn);
    }

    do {
        rc = BIO_do_handshake (sslconn->io);
#if 0
        if (rc < 0) {
            ERR_error_string (ERR_get_error (), buf);
            Ns_Log (Error, MODULE, ": %s", buf);
        }
#endif
    } while (rc < 0 && BIO_should_retry (sslconn->io));

    if (rc < 0) {
	    return NS_ERROR;
    }

    sslconn->peercert = SSL_get_peer_certificate (sslconn->ssl);

    /* Test cert validity in log file */
    if (Ns_OpenSSLIsPeerCertValid (sslconn)) {
	    Ns_Log (Notice, "%s: %s: SERVER's CERT is VALID",
		    MODULE, sslconn->type);
    } else {
	    Ns_Log (Notice, "%s: %s: SERVER's CERT is NOT VALID",
		    MODULE, sslconn->type);
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * RunServerSSLHandshake --
 *
 *      Run the Server SSL handshake sequence.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
RunServerSSLHandshake (Ns_OpenSSLConn *sslconn)
{
    int rc, error, n;
    time_t endtime;
    struct timeval tv;
    fd_set *wfds, *rfds, fds;
    char errstring[132];

    Ns_SockSetBlocking(sslconn->sock);
    /* XXX check this */
    //BIO_set_nbio (sslconn->io, 0);

    /* XXX using core driver's value for sendwait */
    endtime = time (NULL) + sslconn->ssldriver->driver->sendwait + 1;
    FD_ZERO (&fds);

    while (1) {
	rc = SSL_accept (sslconn->ssl);

	if (rc == 1)
	    break;

	error = SSL_get_error (sslconn->ssl, rc);

	if (error == SSL_ERROR_SYSCALL) {
	    if (rc == 0) {
	    	Ns_Log (Error, "%s: %s: EOF during SSL handshake", MODULE, sslconn->server);
	    } else {
                Ns_Log (Error, "%s: %s: error during SSL handshake: %s",
                        MODULE, sslconn->server, ns_sockstrerror (errno));
	    }
	    return NS_ERROR;

	} else if (error == SSL_ERROR_WANT_READ) {
	    rfds = &fds;
	    wfds = NULL;

	} else if (error == SSL_ERROR_WANT_WRITE) {
	    rfds = NULL;
	    wfds = &fds;

	} else if (error == SSL_ERROR_ZERO_RETURN) {
	    Ns_Log (Error, "%s: %s: SSL_ERROR_ZERO_RETURN", MODULE, sslconn->server);
	} else if (error == SSL_ERROR_NONE) {
	    Ns_Log (Error, "%s: %s: SSL_ERROR_NONE", MODULE, sslconn->server);
	} else if (error == SSL_ERROR_WANT_CONNECT) {
	    Ns_Log (Error, "%s: %s: SSL_ERROR_WANT_CONNECT", MODULE, sslconn->server);
	} else if (error == SSL_ERROR_WANT_ACCEPT) {
	    Ns_Log (Error, "%s: %s: SSL_ERROR_WANT_ACCEPT", MODULE, sslconn->server);
	} else if (error == SSL_ERROR_WANT_X509_LOOKUP) {
	    Ns_Log (Error, "%s: %s: SSL_ERROR_X509_LOOKUP", MODULE, sslconn->server);

	} else {
	    Ns_Log (Error, "%s: %s: error %d/%d during SSL handshake",
		    MODULE, sslconn->server, rc, error);
	    return NS_ERROR;
	}

	FD_SET (sslconn->sock, &fds);

	do {
	    tv.tv_sec = endtime - time (NULL);
	    tv.tv_usec = 0;
	    n = select (sslconn->sock + 1, rfds, wfds, NULL, &tv);
	} while (n < 0 && errno == EINTR);

	if (n < 0) {
	    Ns_Log (Error, "%s: %s: select failed: %s",
		    MODULE, sslconn->server, ns_sockstrerror (errno));
	    return NS_ERROR;
	}

	if (n == 0) {
	    Ns_Log (Notice, "%s: %s: SSL handshake timeout",
                    MODULE, sslconn->server);
	    return NS_ERROR;
	}
    }

    sslconn->peercert = SSL_get_peer_certificate (sslconn->ssl);

    Ns_SockSetNonBlocking(sslconn->sock);
    /* XXX check this */
    //BIO_set_nbio (sslconn->io, 1);

    /* XXX log if the cert is valid as a test */
#if 0
    /* Test cert validity in log file */
    if (Ns_OpenSSLIsPeerCertValid (sslconn)) {
	Ns_Log (Notice, MODULE, ": %s: CLIENT's CERT is VALID",
		sslconn->type);
    } else {
	Ns_Log (Notice, MODULE, ": %s: CLIENT's CERT is NOT VALID",
		sslconn->type);
    }
#endif

    return NS_OK;
}
