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

#define BUFSIZE 2048

typedef struct Stream {
    Ns_OpenSSLConn *sslconn;
    int error;
    int cnt;
    char *ptr;
    /* XXX analyze this! */
    char buf[BUFSIZE + 1];
} Stream;

/*
 * Local functions defined in this file
 */

static int RunSSLHandshake (Ns_OpenSSLConn *sslconn);
static int RunServerSSLHandshake (Ns_OpenSSLConn *sslconn);
static void DestroySSLSockConn (Ns_OpenSSLConn *sslconn);
static int GetLine (Stream *stream, Ns_DString *ds);
static int FillBuf (Stream *stream);


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLConnCreate --
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
 *----------------------------------------------------------------------
 */

Ns_OpenSSLConn *
NsOpenSSLConnCreate(SOCKET sock, NsOpenSSLDriver *ssldriver, Ns_OpenSSLContext *sslcontext,
        int role)
{
    Ns_OpenSSLConn *sslconn;
    BIO *sock_bio;
    BIO *ssl_bio;


    sslconn = ns_calloc(1, sizeof(Ns_OpenSSLConn));
    sslconn->role       = role;
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

    if (sslconn->role == ROLE_SERVER) {
    	SSL_set_accept_state (sslconn->ssl);
    } else {
    	SSL_set_connect_state (sslconn->ssl);
    }

    /*
     * BIO stack:
     *
     *   nsopenssl module
     *   buffering BIO
     *   SSL BIO
     *   socket BIO
     *   TCP socket to client
     */

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
        Ns_Log(Error, "%s: BIO_set_write_buffer_size failed", MODULE);
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
 * Side effects: If the SSL connection was open then it will be forced
 *      to close first. If the connection is still being referenced,
 *      no action is taken.
 *
 *----------------------------------------------------------------------
 */

void
NsOpenSSLConnDestroy (Ns_OpenSSLConn *sslconn)
{
    if (sslconn->refcnt > 0)
        return;

    if (sslconn != NULL) {

	/*
	 * We disallow sending through the socket,
	 * since BIO_free_all triggers SSL_shutdown,
	 * which is sending something (2 bytes).
	 * It confuses Win32 clients, since they automatically
	 * close socket on FIN packet
	 * only if there is no waiting received bytes
	 * (it gives "connection reset" message in MSIE when
	 * socket is freed by keepalive thread).
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
#ifdef AOLSERVER_3
	if (sslconn->sock != INVALID_SOCKET) {
	    ns_sockclose (sslconn->sock);
	    sslconn->sock = INVALID_SOCKET;
	}
#endif

	/*
	 * We only free the connection structure if it's an
	 * SSL socket type not tied to the comm API. If it is
	 * tied to the comm API, it's freed when the comm driver
	 * shuts down.
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

#ifdef AOLSERVER_3
    do {
	rc = BIO_read (sslconn->io, buffer, toread);
    } while (rc < 0 && BIO_should_retry (sslconn->io));
#else
    rc = BIO_read (sslconn->io, buffer, toread);
#if 0
    Ns_Log (Debug, "NsOpenSSLRecv: read(1): %d %d\n", toread, rc);
#endif
    if (rc < 0 && BIO_should_retry (sslconn->io)
	&& Ns_SockWait (sslconn->sock, NS_SOCK_READ, 2) == NS_OK) {
	rc = BIO_read (sslconn->io, buffer, toread);
#if 0
        Ns_Log (Debug, "NsOpenSSLRecv: read(2): %d %d\n", toread, rc);
#endif
    }
#endif

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
 * NsOpenSSLTrace --
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
NsOpenSSLTrace (SSL *ssl, int where, int rc)
{
    Ns_OpenSSLConn *sslconn;
    char *alertTypePrefix;
    char *alertType;
    char *alertDescPrefix;
    char *alertDesc;

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
Ns_OpenSSLIsPeerCertValid (Ns_OpenSSLConn *sslconn)
{
    if (SSL_get_verify_result (sslconn->ssl) == X509_V_OK) {
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
 * Ns_OpenSSLFetchURL --
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

int
Ns_OpenSSLFetchURL (Ns_DString *page, char *url, Ns_Set *headers)
{
    Ns_OpenSSLConn *sslconn;
    Ns_DString ds;
    Stream stream;
    Ns_Request *request;
    char *p;
    int status, tosend, n;

    status = NS_ERROR;
    Ns_DStringInit (&ds);

    /*
     * Parse the URL and open a connection.
     */

    Ns_DStringVarAppend (&ds, "GET ", url, " HTTP/1.0", NULL);
    request = Ns_ParseRequest (ds.string);
    if (request == NULL || request->protocol == NULL ||
            /* XXX try to get the server name into the log message */
	!STREQ (request->protocol, "https") || request->host == NULL) {
	Ns_Log (Notice, "%s: urlopen: invalid url '%s'", MODULE, url);
	goto done;
    }
    if (request->port == 0) {
	request->port = 443;
    }
    sslconn = Ns_OpenSSLSockConnect (request->host, request->port, 0, 300);
            /* XXX try to get the server name into the log message */
    if (sslconn == NULL) {
	Ns_Log (Error, "%s: Ns_OpenSSLFetchURL failed to connect to '%s'", MODULE, url);
	goto done;
    }

    /*
     * Send a simple HTTP GET request.
     */

    Ns_DStringTrunc (&ds, 0);
    Ns_DStringVarAppend (&ds, "GET ", request->url, NULL);
    if (request->query != NULL) {
	Ns_DStringVarAppend (&ds, "?", request->query, NULL);
    }
    Ns_DStringAppend (&ds, " HTTP/1.0\r\nAccept: */*\r\n\r\n");
    p = ds.string;
    tosend = ds.length;
    while (tosend > 0) {
	n = NsOpenSSLSend (sslconn, p, tosend);
	if (n <= 0) {
	    Ns_Log (Error, "%s: urlopen: failed to send data to '%s'", MODULE, url);
	    goto done;
	}
	tosend -= n;
	p += n;
    }

    /*
     * Buffer the socket and read the response line and then
     * consume the headers, parsing them into any given header set.
     */

    stream.cnt = 0;
    stream.error = 0;
    stream.ptr = stream.buf;
    stream.sslconn = (Ns_OpenSSLConn *) sslconn;
    if (!GetLine (&stream, &ds)) {
	goto done;
    }
    if (headers != NULL && strncmp (ds.string, "HTTP", 4) == 0) {
	if (headers->name != NULL) {
	    ns_free (headers->name);
	}
	headers->name = Ns_DStringExport (&ds);
    }
    do {
	if (!GetLine (&stream, &ds)) {
	    goto done;
	}
	if (ds.length > 0
	    && headers != NULL
	    && Ns_ParseHeader (headers, ds.string, Preserve) != NS_OK) {
	    goto done;
	}
    } while (ds.length > 0);

    /*
     * Without any check on limit or total size, foolishly read
     * the remaining content into the dstring.
     */

    do {
	Ns_DStringNAppend (page, stream.ptr, stream.cnt);
    } while (FillBuf (&stream));
    if (!stream.error) {
	status = NS_OK;
    }

  done:
    if (request != NULL) {
	Ns_FreeRequest (request);
    }
    if (sslconn != NULL) {
	NsOpenSSLConnDestroy (sslconn);
    }
    Ns_DStringFree (&ds);
    return status;
}

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLFetchPage --
 *
 *      Fetch a page off of this very server. Url must reference a
 *      file in the filesystem.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *      The file contents will be put into the passed-in dstring.
 *
 *----------------------------------------------------------------------
 */

int
Ns_OpenSSLFetchPage (Ns_DString *page, char *url, char *server)
{
    return Ns_FetchPage (page, url, server);
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
FillBuf (Stream *stream)
{
    int n;

    n = NsOpenSSLRecv (stream->sslconn, stream->buf, BUFSIZE);
    if (n <= 0) {
	if (n < 0) {
	    Ns_Log (Error, "%sNs_OpenSSLFetchURL failed to fill socket stream buffer",
                    MODULE);
	    stream->error = 1;
	}
	return NS_FALSE;
    }
    stream->buf[n] = '\0';
    stream->ptr = stream->buf;
    stream->cnt = n;

    return NS_TRUE;
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
GetLine (Stream *stream, Ns_DString *ds)
{
    char *eol;
    int n;

    Ns_DStringTrunc (ds, 0);
    do {
	if (stream->cnt > 0) {
	    eol = strchr (stream->ptr, '\n');
	    if (eol == NULL) {
		n = stream->cnt;
	    } else {
		*eol++ = '\0';
		n = eol - stream->ptr;
	    }
	    Ns_DStringNAppend (ds, stream->ptr, n - 1);
	    stream->ptr += n;
	    stream->cnt -= n;
	    if (eol != NULL) {
		n = ds->length;
		if (n > 0 && ds->string[n - 1] == '\r') {
		    Ns_DStringTrunc (ds, n - 1);
		}
		return NS_TRUE;
	    }
	}
    } while (FillBuf (stream));

    return NS_FALSE;
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
    if (sslconn->role == ROLE_SERVER) {
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
