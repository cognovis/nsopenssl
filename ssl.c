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

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "nsopenssl.h"

static int ServerSetNonBlocking(NsOpenSSLConnection *scPtr, int flag);
static int ServerCreateStruct(NsOpenSSLConnection *scPtr);
static int ServerCreateBIOStack(NsOpenSSLConnection *scPtr);
static int ServerRunHandshake(NsOpenSSLConnection *scPtr);

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLShutdownConn --
 *
 *      Shut down an SSL connection.
 *
 * Results:
 *	OpenSSL error code.
 *
 * Side effects:
 *	None.
 *
 * Note: based on SSL_smart_shutdown from mod_ssl, by Ralf Engelschall.
 *
 *----------------------------------------------------------------------
 */

int
NsServerSSLShutdownConn(SSL *ssl)
{
    int i;
    int rc;

    /* Call SSL_shutdown repeatedly until we're sure it's done. */
    for (i = rc = 0; rc == 0 && i < 4; i++) {
        rc = SSL_shutdown(ssl);
    }

    return rc;
}

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLFlushConn --
 *
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
NsServerSSLFlushConn(NsOpenSSLConnection *scPtr)
{
    NsOpenSSLDriver     *sdPtr = scPtr->sdPtr;

    if (scPtr->ssl == NULL) {

	return NS_ERROR;

    } else {

	if (BIO_flush(SSL_get_wbio(scPtr->ssl)) < 1) {
            Ns_Log(Error, "%s: BIO returned error on flushing buffer",
                sdPtr->module);
        }
	return NS_OK;

    }
}

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLCreateConn --
 *
 *	Create an SSL connection. The socket has already been accept()ed
 *      and is ready for reading/writing.
 *
 * Results:
 *      NS_ERROR or NS_OK.
 *
 * Side effects:
 *      If the SSL connection was open then it will be forced to close
 *      first.
 *
 * Todo:
 *      Implement timeouts using an alarm and a OpenSSL callback.
 *
 *----------------------------------------------------------------------
 */

int
NsServerSSLCreateConn(NsOpenSSLConnection *scPtr)
{
    if (
	   ServerCreateStruct(scPtr)                  == NS_ERROR
	|| ServerCreateBIOStack(scPtr)                == NS_ERROR
	|| ServerRunHandshake(scPtr)                  == NS_ERROR
    ) {
	SSL_set_shutdown(scPtr->ssl,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
	NsServerSSLShutdownConn(scPtr->ssl);
	NsServerSSLDestroyConn(scPtr);

	return NS_ERROR;
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLDestroyConn --
 *
 *  Destroy an SSL connection.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      If the SSL connection was open then it will be forced to close
 *      first.
 *
 *----------------------------------------------------------------------
 */

void
NsServerSSLDestroyConn(NsOpenSSLConnection *scPtr)
{
    Ns_Log(Debug, "%s: destroying conn (%p)",
	scPtr == NULL ? DRIVER_NAME : scPtr->sdPtr->module, scPtr);

    if (scPtr != NULL) {
	if (scPtr->clientcert != NULL) {
	    X509_free(scPtr->clientcert);
	    scPtr->clientcert = NULL;
	}

	if (scPtr->io != NULL) {
	    BIO_free_all(scPtr->io);
	    scPtr->io = NULL;
	}
	if (scPtr->ssl != NULL) {
	    SSL_free(scPtr->ssl);
	    scPtr->ssl = NULL;
	}

#ifndef NS_MAJOR_VERSION
	if (scPtr->sock != INVALID_SOCKET) {
	    ns_sockclose(scPtr->sock);
	    scPtr->sock = INVALID_SOCKET;
	}
#endif

	Ns_Log(Debug, "%s: done destroying conn", scPtr->sdPtr->module);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLRecv --
 *
 *  Read data from an SSL connection
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
NsServerSSLRecv(NsOpenSSLConnection *scPtr, void *buffer, int toread)
{
  int rc;

#if 0
again:
#endif

#ifndef NS_MAJOR_VERSION
    do {
	rc = BIO_read(scPtr->io, buffer, toread);
    } while (rc < 0 && BIO_should_retry(scPtr->io));
#else
    rc = BIO_read(scPtr->io, buffer, toread);
    if (rc < 0
        && BIO_should_retry(scPtr->io)
        && Ns_SockWait(scPtr->sock, NS_SOCK_READ, 2) == NS_OK) {
            rc = BIO_read(scPtr->io, buffer, toread);
    }
    Ns_Log(Debug, "read: %d %d\n", toread, rc);
#endif

#if 0
    rd = SSL_read(conn->ssl, (char *)buffer, toread);
    switch (SSL_get_error(conn->ssl,rd)) {

    case SSL_ERROR_NONE:
        break;

    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_X509_LOOKUP:
        Ns_Log(Debug, "NsOpenSSLRecv: WANT_SOMETHING\n");
        SSL_renegotiate(conn->ssl);
        SSL_write(conn->ssl,NULL,0);
        goto again;

    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
        Ns_Log(Debug, "NsOpenSSLRecv: SSL_ERROR_SYSCALL\n");
        break;

    case SSL_ERROR_ZERO_RETURN:
        Ns_Log(Debug, "NsOpenSSLRecv: SSL_ERROR_ZERO_RETURN\n");
        break;

    }
#endif


  return rc;
}

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLSend --
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
NsServerSSLSend(NsOpenSSLConnection *scPtr, void *buffer, int towrite)
{
    return SSL_write(scPtr->ssl, buffer, towrite);
}

/*
 *----------------------------------------------------------------------
 *
 * NsServerSSLTrace --
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
NsServerSSLTrace(SSL *ssl, int where, int rc)
{
    NsOpenSSLConnection *scPtr;
    NsOpenSSLDriver     *sdPtr;
    char                *alertTypePrefix;
    char                *alertType;
    char                *alertDescPrefix;
    char                *alertDesc;

    scPtr = (NsOpenSSLConnection*) SSL_get_app_data(ssl);
    sdPtr = scPtr->sdPtr;

    if (where & SSL_CB_ALERT) {
	alertTypePrefix = "; alert type = ";
	alertType = SSL_alert_type_string_long(rc);
	alertDescPrefix = "; alert desc = ";
	alertDesc = SSL_alert_desc_string_long(rc);
    } else {
	alertTypePrefix = alertType = "";
	alertDescPrefix = alertDesc = "";
    }

    Ns_Log(Notice, "%s: trace: %s%s%s%s%s", sdPtr->module,
	SSL_state_string_long(ssl),
	alertTypePrefix, alertType, alertDescPrefix, alertDesc);

}

/*
 *----------------------------------------------------------------------
 *
 * ServerCreateStruct--
 *
 *	Create the SSL struct for a connection.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
ServerCreateStruct(NsOpenSSLConnection *scPtr)
{
    scPtr->ssl = SSL_new(scPtr->sdPtr->context);
    if (scPtr->ssl == NULL) {
	Ns_Log(Error, "%s: error creating new SSL", scPtr->sdPtr->module);
	return NS_ERROR;
    }

    SSL_clear(scPtr->ssl);
    SSL_set_accept_state(scPtr->ssl);
    SSL_set_app_data(scPtr->ssl, scPtr);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerCreateBIOStack --
 *
 *	Create the BIO stack that the module uses to talk to the
 *      client via SSL.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
ServerCreateBIOStack(NsOpenSSLConnection *scPtr)
{
    BIO    *sock_bio;
    BIO    *ssl_bio;

    /*
     * BIO stack:
     *
     *   nsopenssl module
     *   buffering BIO
     *   SSL BIO
     *   socket BIO
     *   TCP socket to client
     */

    /* socket BIO */

    sock_bio = BIO_new_socket(scPtr->sock, BIO_NOCLOSE);

    /* SSL BIO */

    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, scPtr->ssl, BIO_NOCLOSE);

    BIO_push(ssl_bio, sock_bio); /* Make ssl_bio use sock_bio for I/O. */

    /* buffering BIO */

    scPtr->io = BIO_new(BIO_f_buffer());
    if (!BIO_set_write_buffer_size(scPtr->io, scPtr->sdPtr->bufsize))
	return NS_ERROR;

    BIO_push(scPtr->io, ssl_bio); /* Make scPtr->io use ssl_bio for I/O.  */

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerSetNonBlocking --
 *
 *	Put the socket in blocking/nonblocking mode.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
ServerSetNonBlocking(NsOpenSSLConnection *scPtr, int flag)
{
    return BIO_socket_nbio(scPtr->sock, flag) ? NS_OK : NS_ERROR;
}

/*
 *----------------------------------------------------------------------
 *
 * ServerRunHandshake --
 *
 *	Run the SSL handshake sequence.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
ServerRunHandshake(NsOpenSSLConnection *scPtr)
{
    int             rc;
    int             error;
    time_t          endtime;
    struct timeval  tv;
    int             n;
    fd_set         *wfds;
    fd_set         *rfds;
    fd_set          fds;

    /* XXX take a close look at the nonblocking stuff here w/respect to new comm model */
    if (ServerSetNonBlocking(scPtr, 1) == NS_ERROR) {
	Ns_Log(Warning,
	    "%s: could not put socket in non-blocking mode; "
	    "timeout may not be enforced: %s",
	    scPtr->sdPtr->module, ns_sockstrerror(errno));
    }

    endtime = time(NULL) + scPtr->sdPtr->timeout + 1;
    FD_ZERO(&fds);

    while (1) {

	rc = SSL_accept(scPtr->ssl);

	if (rc == 1) {
	    break;
	}

	error = SSL_get_error(scPtr->ssl, rc);

	if (error == SSL_ERROR_SYSCALL) {
	    if (rc == 0) {
		Ns_Log(Error, "%s: EOF during SSL handshake",
		    scPtr->sdPtr->module);
	    } else {
		Ns_Log(Error, "%s: error during SSL handshake: %s",
		    scPtr->sdPtr->module, ns_sockstrerror(errno));
	    }
	    return NS_ERROR;

	} else if (error == SSL_ERROR_WANT_READ) {
	    rfds = &fds;
	    wfds = NULL;

	} else if (error == SSL_ERROR_WANT_WRITE) {
	    rfds = NULL;
	    wfds = &fds;

	} else {
	    Ns_Log(Error, "%s: error %d/%d during SSL handshake",
		scPtr->sdPtr->module, rc, error);
	    return NS_ERROR;
	}

	FD_SET(scPtr->sock, &fds);

	do {
	    tv.tv_sec = endtime - time(NULL);
	    tv.tv_usec = 0;
	    n = select(scPtr->sock + 1, rfds, wfds, NULL, &tv);
	} while (n < 0 && errno == EINTR);

	if (n < 0) {
	    Ns_Log(Error, "%s: select failed: %s",
		scPtr->sdPtr->module, ns_sockstrerror(errno));
	    return NS_ERROR;
	}

	if (n == 0) {
	    Ns_Log(Notice, "%s: SSL handshake timeout",
		scPtr->sdPtr->module);
	    return NS_ERROR;
	}
    }

    scPtr->clientcert = SSL_get_peer_certificate(scPtr->ssl);

#ifndef NS_MAJOR_VERSION
    if (ServerSetNonBlocking(scPtr, 0) == NS_ERROR) {
	Ns_Log(Warning,
	    "%s: could not put socket in blocking mode; "
	    "results unpredictable: %s",
	    scPtr->sdPtr->module, ns_sockstrerror(errno));
    }
#endif

    return NS_OK;
}

