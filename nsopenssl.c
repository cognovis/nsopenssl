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
 * Copyright (C) 1999 Stefan Arentz
 * Copyright (C) 2000 Scott S. Goodwin
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

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>

#include "ns.h"
#include "nsopenssl.h"

/*
 * Local functions to this file
 */

static
SSLConnection *NsSSLAbortConn (SSLConnection * conPtr);

static int
  SSL_smart_shutdown (SSL * ssl);

static int
  NsSSLClientVerify (int num);

int count, i;
int clientverify;

static char server_session_id_context[] = "nsopenssl/OpenSSL";	/* anything will do */

/*
 *----------------------------------------------------------------------
 *
 * NsSSLCreateServer --
 *
 *      Create an SSL server.
 *
 * Results:
 *      Always NS_OK.
 *
 * Side effects:
 *      None.
 *
 * Todo:
 *      None.
 *
 *----------------------------------------------------------------------
 */

SSLServer *
NsSSLCreateServer (SSLConf * config)
{
    SSLServer *srvPtr;
    STACK_OF (X509_NAME) * client_ca_stack;
    X509_NAME *caname;
    char buf[120];
    X509_NAME *xn;
    int i, j;

    Ns_Log (Debug, "Entering NsSSLCreateServer()");

#if 0
    assert (config->certfile != NULL && *certfile != 0x00);
    assert (config->keyfile != NULL && *keyfile != 0x00);
#endif

    srvPtr = (SSLServer *) ns_calloc (1, sizeof (SSLServer));
    if (srvPtr != NULL) {

	/*
	 * Store the config settings into this connection's structure.
	 */

	srvPtr->certfile = config->certfile;
	srvPtr->keyfile = config->keyfile;
	srvPtr->cachesize = config->cachesize;
	srvPtr->cachetimeout = config->cachetimeout;
	srvPtr->ciphersuite = config->ciphersuite;
	srvPtr->protocols = config->protocols;
	srvPtr->clientverify = config->clientverifymode;

	/*
	 * Set the protocols that the server supports.
	 */

	if (srvPtr->protocols == SSL_PROTOCOL_SSLV2)
	    srvPtr->method = SSLv2_server_method ();
	else
	    srvPtr->method = SSLv23_server_method ();

	/* Create and initialize a new SSL server context.  */

	srvPtr->context = SSL_CTX_new (srvPtr->method);
	if (srvPtr->context == NULL) {
	    Ns_Log (Error, "Could not create new SSL context.");
	    NsSSLDestroyServer (srvPtr);
	    return NULL;
	}

	/* Take out protocols not specified in config file */

	if (!(srvPtr->protocols & SSL_PROTOCOL_SSLV2))
	    SSL_CTX_set_options (srvPtr->context, SSL_OP_NO_SSLv2);
	if (!(srvPtr->protocols & SSL_PROTOCOL_SSLV3))
	    SSL_CTX_set_options (srvPtr->context, SSL_OP_NO_SSLv3);
	if (!(srvPtr->protocols & SSL_PROTOCOL_TLSV1))
	    SSL_CTX_set_options (srvPtr->context, SSL_OP_NO_TLSv1);

	/*
	 * SSL_OP_ALL turns on all compatibility flags for known
	 * protocol implementation bugs in the browsers. You can set
	 * them individually, but it doesn't seem to make sense that
	 * you wouldn't want all broken browser behavior to be handled
	 * properly.
	 */

	SSL_CTX_set_options (srvPtr->context, SSL_OP_ALL);

	/*
	 * SSL_OP_SINGLE_DH_USE prevents a DH key from being created
	 * for SSL_[CTX_]set_tmp_dh; each handshake creates its own
	 * key anyway, so it's a waste to generate here.
	 */

	SSL_CTX_set_options (srvPtr->context, SSL_OP_SINGLE_DH_USE);

	/* Store our SSLConnection as OpenSSL's app data */

	SSL_CTX_set_app_data (srvPtr->context, srvPtr);

	/* Set the cipher suite that we support.  */

	if (SSL_CTX_set_cipher_list (srvPtr->context, srvPtr->ciphersuite) ==
	    0) {
	    Ns_Log (Error, "Unable to configure permitted SSL ciphers (%s).",
		    srvPtr->ciphersuite);
	    NsSSLDestroyServer (srvPtr);
	    return NULL;
	}

	/* Turn on OpenSSL tracing */

	SSL_CTX_set_info_callback (srvPtr->context, NsSSLLogTracingState);

#if 0
	/*
	 * Register a function to handle client certificate verification,
	 * which will override OpenSSL's built-in verification.
	 *
	 * In cases where verification fails, yet I want to give the user some
	 * nice html page explaining the problem: how can I communicate that extra
	 * thing be done? Via a passed in CTX structure? Via a numbered return?
	 */

	Ns_Log (Debug,
		"NsSSLCreateServer: Registering NsSSLClientVerify callback");
	SSL_CTX_set_cert_verify_callback (srvPtr->context, NsSSLClientVerify,
					  NULL);
#endif

	Ns_Log (Debug, "Setting client verify mode");
	SSL_CTX_set_verify (srvPtr->context, srvPtr->clientverify, NULL);

	/*
	 * Set up the trusted CA list. There are a couple of methods
	 * you can use here. The easiest is to concatenate all your
	 * trusted CA certificates into one file and point to
	 * it. Another is to leave each certificate in it's own file
	 * and place all of these files in the same directory; you
	 * have to set up a hash for the files, which I don't fully
	 * understand yet -- see the Apache conf/ssl.crt readme for
	 * more info. Both methods can work at the same time.
	 */

	if (srvPtr->clientverify != SSL_VERIFY_NONE) {
	    if (!SSL_CTX_load_verify_locations
		(srvPtr->context, config->cacertfile, config->cacertpath)) {
		Ns_Log (Error, "Failed to load CA certificates");
		return NULL;
	    }
	}

	/*
	 * Initialize the session cache.  The two valid values for a
	 * server session cache mode are SSL_SESS_CACHE_SERVER or
	 * SSL_SESS_CACHE_OFF.
	 */

	if (srvPtr->cachesize != 0) {

            /*
	     * We must set a session id context. This can be any
	     * string you want.
	     */

	    SSL_CTX_set_session_id_context (srvPtr->context, (void *)
					    &server_session_id_context,
					    sizeof
					    (server_session_id_context));

	    SSL_CTX_set_session_cache_mode (srvPtr->context,
					    SSL_SESS_CACHE_SERVER);

	    srvPtr->cachehash = Ns_CacheCreateSz ("ns_openssl",
						  TCL_STRING_KEYS,
						  srvPtr->cachesize,
						  (Ns_Callback *)
						  NsSSLFreeEntry);

	    /* Set session cache callbacks */

	    SSL_CTX_sess_set_new_cb (srvPtr->context,
				     NsSSLNewSessionCacheEntry);
	    SSL_CTX_sess_set_get_cb (srvPtr->context,
				     NsSSLGetSessionCacheEntry);
#if 1
	    /* TODO: BUG: This is where the caching "breaks". What
	     * happens is that when caching is turned on, each
	     * connections gets a session id and that session is
	     * cached. But when the socket closes after the page has
	     * been retrieved, this callback runs which removes the
	     * session id from the cache, so effectively you get no
	     * caching. This happens when the refcnt of the driver is
	     * 0 and the driver is freed -- maybe this behavior should
	     * change. Do I need this callback, or can I just define
	     * my own scheduled routine to clean it up? */

	    SSL_CTX_sess_set_remove_cb (srvPtr->context,
					NsSSLDelSessionCacheEntry);
#endif
	} else {
	    SSL_CTX_set_session_cache_mode (srvPtr->context,
					    SSL_SESS_CACHE_OFF);
	    Ns_Log (Notice, "Session caching is turned off");
	}

	/*
	 * Load the SSL Certificate and Private Key. If either of these fail then
	 * the server cannot be started.
	 */

	Ns_Log (Notice, "Loading SSL server certificate '%s'",
		config->certfile);
	if (SSL_CTX_use_certificate_file
	    (srvPtr->context, config->certfile, SSL_FILETYPE_PEM) <= 0) {
	    Ns_Log (Error, "Could not load the certificate %s.",
		    config->certfile);
	    NsSSLDestroyServer (srvPtr);
	    return NULL;
	}

	Ns_Log (Notice, "Loading SSL server private key '%s'",
		config->keyfile);
	if (SSL_CTX_use_PrivateKey_file
	    (srvPtr->context, config->keyfile, SSL_FILETYPE_PEM) <= 0) {
	    Ns_Log (Error, "Could not load the private key %s.",
		    config->keyfile);
	    NsSSLDestroyServer (srvPtr);
	    return NULL;
	}

	/*
	 * Check if the private key matches the certificate's public key.
	 */

	Ns_Log (Notice, "Checking SSL private key");
	if (SSL_CTX_check_private_key (srvPtr->context) == 0) {
	    Ns_Log (Error,
		    "Private key does not match the certificate public key");
	    return NULL;
	}

    }

    Ns_Log (Debug, "Leaving NsSSLCreateServer()");

    return srvPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLCreateConn --
 *
 *	Create an SSL connection. The socket has already been accept()ed
 *      and is ready for reading/writing.
 *
 * Results:
 *      An SSLConnection object or NULL. ->server is always guaranteed
 *      filled in.
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

SSLConnection *
NsSSLCreateConn (SOCKET sock, int timeout, SSLServer * server)
{
    SSLConnection *conPtr;
    int err;
    char buf[8194];
    int rd;
    BIO *sbio;
    fd_set readfds;
    int width;
    char *subject, *issuer;
    ASN1_INTEGER *bs, *serial;
    BIO *notbefore, *notafter;
    ASN1_UTCTIME *nob, *noa;
    X509 *clientcert;

    Ns_Log (Debug, "Entering NsSSLCreateConn()");

    if ((conPtr = (SSLConnection *) ns_calloc (1, sizeof (SSLConnection))) ==
	NULL) {
	Ns_Log (Error,
		"NsSSLCreateConn: unable to allocate an SSLConnection structure");
	return NULL;
    }

    /* Remember the server in the connection */

    conPtr->server = server;

    /* 
     * Allocate an SSL structure within the SSLConnection structure
     * and initialize the state engine to request a handshake.
     */

    if ((conPtr->ssl = SSL_new (server->context)) == NULL) {
	Ns_Log (Error,
		"NsSSLCreateConn: Failed to create new SSL context with SSL_new");
	(void) NsSSLDestroyConn (conPtr);
	return NULL;
    }

    SSL_clear (conPtr->ssl);

    conPtr->io = NULL;
    conPtr->ssl_bio = NULL;

    /* Store our SSLConnection as OpenSSL's app data */

    SSL_set_app_data (conPtr->ssl, conPtr);

    /*
     * Create new BIO structure that does SSL on the data read and
     * written to it. The io is a filter BIO that will be stacked on
     * top of ssl_bio.  Remember to BIO_free this structure when done
     * with it.
     */

    conPtr->io = BIO_new (BIO_f_buffer ());
    conPtr->ssl_bio = BIO_new (BIO_f_ssl ());

    if (!BIO_set_write_buffer_size (conPtr->io, Bufsize))
	return (NsSSLAbortConn (conPtr));

#if 0
    /*
     * TODO: TEST STATEMENT: Forcing an abort here cleans up the
     * server-side stuff but leaves the browser spinning. Is there
     * anyway I can get the connection to close cleanly if an abort
     * happens up here?
     */

    NsSSLAbortConn (conPtr);
#endif

    /*
     * Create a socket BIO where all read and write operations refer
     * to the socket.
     */

    sbio = BIO_new_socket (sock, BIO_NOCLOSE);

    /*
     * Set the BIOs that will be used for reading and writing data
     * when calling SSL_read and SSL_write for the specified SSL
     * connection. Argument two is the read bio; argument three is the
     * write bio. The RSA SSL-C docs say that you can refer to the
     * same BIO for read and write; this is probably true with OpenSSL
     * as well.
     */

    SSL_set_bio (conPtr->ssl, sbio, sbio);

    /*
     * Put the SSL connection reference in the accept state; this is
     * how you tell I'm the server and not the client.  When an
     * SSL_do_handshake or an SSL_read or SSL_write is called, the
     * server side of the SSL protocol is initiated.
     */

    SSL_set_accept_state (conPtr->ssl);
    BIO_set_ssl (conPtr->ssl_bio, conPtr->ssl, BIO_CLOSE);

    /* 
     * conPtr->io is a filter BIO; conPtr->ssl_bio is a source/sink
     * BIO. A source/sink BIO takes data from a device or sends data
     * to a device; a filter BIO modifies the data written to or read
     * from a source/sink BIO. A stack of BIOs consist of one
     * source/sink BIO at the bottom of the stack and filter BIOs on
     * top. Writing to any of the filter BIOs causes the data to work
     * its way down the stack with each filter BIO modifying the data
     * until it gets to the source/sink BIO, at which point it goes to
     * the device, and vice versa.
     */

    BIO_push (conPtr->io, conPtr->ssl_bio);

    Ns_Log (Debug, "NsSSLCreateConn: pre-handshake loop");

    /* Connect this connection's descriptor to the SSL connection */

    SSL_set_fd (conPtr->ssl, sock);

    /* 
     * We force the client certificate to be 'accepted' so the
     * connection isn't aborted. We may want the application to handle
     * any invalid or missing client certificates with a friendly
     * error page.
     */

#if 0
    SSL_set_verify_result (conPtr->ssl, X509_V_OK);
#endif

    while (!SSL_is_init_finished (conPtr->ssl)) {

	if ((err = SSL_accept (conPtr->ssl)) <= 0) {

	    Ns_Log (Notice,
		    "Failed to accept SSL connection, err = %d / %d", err,
		    SSL_get_error (conPtr->ssl, err));
	    if (SSL_get_error (conPtr->ssl, err) == SSL_ERROR_ZERO_RETURN) {
		Ns_Log (Notice, "Error: SSL_ERROR_ZERO_RETURN");
		/*
		 * The case where the connection was closed before any data
		 * was transferred. That's not a real error and can occur
		 * sporadically with some clients.
		 */
		Ns_Log (Notice, "handshake stopped: connection was closed");
	    } else if (ERR_GET_REASON (ERR_peek_error ()) ==
		       SSL_R_HTTP_REQUEST) {
		Ns_Log (Notice, "Error: This is an HTTP request");
		/* What to do here? */
	    } else if (SSL_get_error (conPtr->ssl, err) == SSL_ERROR_SYSCALL) {
		Ns_Log (Notice, "Error: SSL_ERROR_SYSCALL");

		/* Let interrupted syscalls continue */
		if (errno == EINTR) {
		    continue;
		}

		if (errno > 0) {
		    Ns_Log (Notice,
			    "SSL handshake interrupted by system; browser stop button?");
		} else {
		    Ns_Log (Notice, "Spurious SSL handshake interrupt");
		}
	    } else {
		Ns_Log (Notice, "Error: Unknown error");
	    }

	    /* For all errors we destroy the connection */

	    return (NsSSLAbortConn (conPtr));

	} else {

	    /*
	     * Successful SSL_accept. This means that the handshake was done
	     * and that the SSL communication channel has been setup.
	     */

	    Ns_Log (Debug, "SSL_accept was successful");

	    /*
	     * Tie the client certificate structure to the
	     * SSLConnection structure if a client cert exists. We
	     * must use X509_free to free the clientcert structure
	     * when we're done with it (see NsSSLDestroyConn).
	     */

	    if ((conPtr->clientcert = SSL_get_peer_certificate (conPtr->ssl))
		!= NULL) {
		subject =
		    X509_NAME_oneline (X509_get_subject_name
				       (conPtr->clientcert), NULL, 0);
		Ns_Log (Debug, "Subject name: %s", subject);
		issuer =
		    X509_NAME_oneline (X509_get_issuer_name
				       (conPtr->clientcert), NULL, 0);
		Ns_Log (Debug, "Issuer name: %s", issuer);
	    } else {
		Ns_Log (Debug, "No client certificate");
	    }

#if 0
	    /*
	     * This is where we check the validity of the client certificate.
	     */

	    if ((err = SSL_get_verify_result (conPtr->ssl)) != X509_V_OK) {
		char *errstr = (char *) X509_verify_cert_error_string (err);
		Ns_Log (Notice,
			"SSL client authentication failed: %s",
			errstr != NULL ? errstr : "unknown reason");

		goto err;
	    } else {
		Ns_Log (Debug, "NsSSLCreateConn: returning\n");
		return conPtr;
	    }
#endif

	}
    }

    Ns_Log (Debug, "Leaving NsSSLCreateConn()");

    return conPtr;
}

static SSLConnection *
NsSSLAbortConn (SSLConnection * conPtr)
{
    Ns_Log (Notice, "NsSSLAbortConn: Aborting connection\n");

    /* TODO: If I force an abort before SSL_accept in NsSSLCreateConn,
     * the browser is left spinning. Is there a way to actually close
     * the connection such that the browser actually gets the message
     * and stops spinning? Maybe do an SSL_accept here and then
     * immediately close the connection???
     */

    SSL_set_shutdown (conPtr->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_smart_shutdown (conPtr->ssl);

    if (conPtr->io != NULL) {
	BIO_free (conPtr->io);
	conPtr->io = NULL;
    }
#if 0
    /* TODO: BUG: Do NOT use SSL_free to free conPtr->ssl or BIO_free
       to free conPtr->ssl_bio here!!! Depending on where in the
       connection process we are when we abort, we can inadvertently
       destroy the connection and hang the server. Behavior: when MSIE
       connects and then breaks the connection to ask the user which
       cert they want to use, the server gets destroyed and no more
       incoming SSL connections. Look up in the area of the handshake
       loop where i check for the SYSCALL error etc.  */

    if (conPtr->ssl_bio != NULL) {
	BIO_free (conPtr->ssl_bio);
	conPtr->ssl_bio = NULL;
    }
#endif

    (void) NsSSLDestroyConn (conPtr);

    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLClientVerify --
 *
 *      Function registered as a callback when verifying client
 *      certificate. For now it simply returns '1'. Later we'll add
 *      more code to do our own verification.
 *
 * Results:
 *      Always 1
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
int
NsSSLClientVerify (int num)
{
    Ns_Log (Debug, "*** IN NsSSLClientVerify !!!");

    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLDestroyServer --
 *
 *      Destroy an SSL Server structure.
 *
 * Results:
 *      Always NS_OK.
 *
 * Side effects:
 *      None.
 *
 * Todo:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
NsSSLDestroyServer (SSLServer * server)
{

    Ns_Log (Debug, "Entering NsSSLDestroyServer()");

    assert (server != NULL);

    if (server->context != NULL) {
	SSL_CTX_free (server->context);
    }

    if (server->certfile != NULL) {
	Ns_Free (server->certfile);
    }

    if (server->keyfile != NULL) {
	Ns_Free (server->keyfile);
    }

    if (server->cachesize != 0) {
	Ns_CacheDestroy (server->cachehash);
    }

    if (server->ciphersuite != NULL) {
	Ns_Free (server->ciphersuite);
    }

    Ns_Free (server);

    Ns_Log (Debug, "Leaving NsSSLDestroyServer()");

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLFlushConn --
 *
 *      Flush the SSL connection.
 *
 * Results:
 *      Always NS_OK.
 *
 * Side effects:
 *      None.
 *
 * Todo:
 *      Implement
 *
 *----------------------------------------------------------------------
 */

int
NsSSLFlush (SSLConnection * conn)
{

    Ns_Log (Debug, "Entering NsSSLFlush()");

    assert (conn != NULL);
    assert (conn->ssl != NULL);

    BIO_flush (SSL_get_wbio (conn->ssl));

    Ns_Log (Debug, "Leaving NsSSLFlush()");

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLDestroyConn --
 *
 *	Destroy an SSL connection.
 *
 * Results:
 *      NS_OK
 *
 * Side effects:
 *      If the SSL connection was open then it will be forced to close
 *      first.
 *
 *----------------------------------------------------------------------
 */

int
NsSSLDestroyConn (SSLConnection * conn)
{

    Ns_Log (Debug, "Entering NsSSLDestroyConn()");

    assert (conn != NULL);

    /*
     * We free these using the same memory allocation routines that created them.
     */

    if (conn->io != NULL) {
	BIO_free (conn->io);
    }

    /*
     * Free the client certificate structure if it exists
     */

    if (conn->clientcert != NULL) {
	X509_free (conn->clientcert);
    }
#if 0
    /* I would have thought this would work, but it doesn't. When I do
       this, the server hangs after the first connection has completed
       -- why? */
    if (conn->ssl_bio != NULL) {
	BIO_free (conn->ssl_bio);
    }
#endif

    if (conn->ssl != NULL) {
	SSL_free (conn->ssl);
    }

    Ns_Free (conn);

    Ns_Log (Debug, "Leaving NsSSLDestroyConn()");

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLRecv --
 *
 *	Read data from an SSL connection
 *
 * Results:
 *	The number of bytes read or a negative number in case of
 *      an error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
NsSSLRecv (SSLConnection * conn, void *buffer, int toread)
{
    int rd, i = 0;
    char *buf = NULL;

    assert (conn != NULL);
    assert (conn->ssl != NULL);
    assert (buffer != NULL);

  again:

    rd = BIO_read (conn->io, buffer, toread);
    if (rd < 0) {

	if (BIO_should_retry (conn->io)) {
	    goto again;
	}
    } else if (rd == 0) {
	rd = 0;
    }
#if 0
    rd = SSL_read (conn->ssl, (char *) buffer, toread);
    switch (SSL_get_error (conn->ssl, rd)) {
    case SSL_ERROR_NONE:
	break;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_X509_LOOKUP:
	Ns_Log (Debug, "NsSSLRecv: WANT_SOMETHING\n");
	SSL_renegotiate (conn->ssl);
	SSL_write (conn->ssl, NULL, 0);
	goto again;
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
	Ns_Log (Debug, "NsSSLRecv: SSL_ERROR_SYSCALL\n");
	break;
    case SSL_ERROR_ZERO_RETURN:
	Ns_Log (Debug, "NsSSLRecv: SSL_ERROR_ZERO_RETURN\n");
	break;
    }
#endif

    return rd;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLSend --
 *
 *	Send data through an SSL connection
 *
 * Results:
 *	The number of bytes send or a negative number in case of
 *      an error.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
NsSSLSend (SSLConnection * conn, void *buffer, int towrite)
{
    int wr;
    assert (conn != NULL);
    assert (conn->ssl != NULL);
    assert (buffer != NULL);

    return SSL_write (conn->ssl, buffer, towrite);
}

void
NsSSLLogTracingState (SSL * ssl, int where, int rc)
{
    SSLConnection *connection;
    SSLServer *server;
    char *str;

    /*
     * Get our server record via the SSL's application data.
     */

    connection = (SSLConnection *) SSL_get_app_data (ssl);
    server = connection->server;

    if (where & SSL_CB_HANDSHAKE_START) {
	Ns_Log (Debug, "%s: Handshake : start", SSL_LIBRARY_NAME);
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
	Ns_Log (Debug, "%s: Handshake : done", SSL_LIBRARY_NAME);
    } else if (where & SSL_CB_LOOP) {
	Ns_Log (Debug, "%s: Loop : %s", SSL_LIBRARY_NAME,
		SSL_state_string_long (ssl));
    } else if (where & SSL_CB_READ) {
	Ns_Log (Debug, "%s: Read : %s", SSL_LIBRARY_NAME,
		SSL_state_string_long (ssl));
    } else if (where & SSL_CB_WRITE) {
	Ns_Log (Debug, "%s: Write : %s", SSL_LIBRARY_NAME,
		SSL_state_string_long (ssl));
    } else if (where & SSL_CB_ALERT) {
	str = (where & SSL_CB_READ) ? "read" : "write";
	Ns_Log (Debug, "%s: Alert : %s:%s:%s", SSL_LIBRARY_NAME,
		str,
		SSL_alert_type_string_long (rc),
		SSL_alert_desc_string_long (rc));
    } else if (where & SSL_CB_EXIT) {
	if (rc == 0) {
	    Ns_Log (Debug, "%s: Exit : failed  in  %s", SSL_LIBRARY_NAME,
		    SSL_state_string_long (ssl));
	} else if (rc < 0) {
	    Ns_Log (Debug, "%s: Exit : error in  %s", SSL_LIBRARY_NAME,
		    SSL_state_string_long (ssl));
	}

    }
}

/*
 *----------------------------------------------------------------------
 *
 * SSL_smart_shutdown --
 *
 *      Close an SSL connection.
 *
 * Results:
 *	OpenSSL Error.
 *
 * Side effects:
 *	None.
 *
 * Copyright:
 *      Taken from mod_ssl; ssl_util_ssl.c / http://www.modssl.org
 *      Copyright (c) 1998-1999 Ralf S. Engelschall. All rights reserved.
 *
 *----------------------------------------------------------------------
 */

static int
SSL_smart_shutdown (SSL * ssl)
{
    int i;
    int rc;

    /*
     * Repeat the calls, because SSL_shutdown internally dispatches through a
     * little state machine. Usually only one or two interation should be
     * needed, so we restrict the total number of restrictions in order to
     * avoid process hangs in case the client played bad with the socket
     * connection and OpenSSL cannot recognize it.
     */
    rc = 0;
    for (i = 0; i < 4 /* max 2x pending + 2x data = 4 */ ; i++) {
	if ((rc = SSL_shutdown (ssl)))
	    break;
    }
    return rc;
}
