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


static const char *RCSID =    "@(#) $Header$, compiled: "    __DATE__ " " __TIME__;


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>

#include "ns.h"
#include "nsopenssl.h"


/*
 *----------------------------------------------------------------------
 *
 * NsSSLNewSessionCacheEntry --
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

int
NsSSLNewSessionCacheEntry (SSL * ssl, SSL_SESSION * session)
{
    SSLConnection *connection;
    SSLServer *server;
    SSLSessionCacheEntry *cacheEntry;
    Ns_Entry *hashEntry;
    int new;
    char key[1024];
    unsigned char data[16 * 1024];	/* How to calc this? Standard base64 size rule on SSL_SESSION? */
    unsigned char *datap, *value;
    int datalength;
    int result = TCL_ERROR;

    Ns_Log (Debug, ">>> NsSSLNewSessionCacheEntry()");

    /*
     * Get our server record via the SSL's application data.
     */

    connection = (SSLConnection *) SSL_get_app_data (ssl);
    server = connection->server;

    /*
     * Convert the session id to a base64 encoded string.
     */

    Ns_HtuuEncode (session->session_id, session->session_id_length, key);

    /*
     * Transform the session into a data stream.
     * XXX Rewrite this. Crappy code.
     */

    datap = data;
    datalength = i2d_SSL_SESSION (session, &datap);

    value = Ns_Malloc (datalength);
    memcpy (value, data, datalength);

    /*
     * Set the timeout for this session.
     */

    Ns_Log(Debug, "NsSSLNewSessionCacheEntry: session timeout set to %d", server->cachetimeout);
    SSL_set_timeout (session, server->cachetimeout);

    /*
     * Now insert the session into the hash.
     */

    cacheEntry =
	(SSLSessionCacheEntry *) Ns_Malloc (sizeof (SSLSessionCacheEntry));
    cacheEntry->time = time (NULL);
    cacheEntry->data = value;
    cacheEntry->size = datalength;

    Ns_CacheLock (server->cachehash);
    {
	hashEntry = Ns_CacheCreateEntry (server->cachehash, key, &new);
	if (!new) {
	    SSLSessionCacheEntry *cacheEntryTmp;

	    Ns_Log (Debug, "Entry exists with Session ID: '%s'", key);
	    cacheEntryTmp = Ns_CacheGetValue (hashEntry);

	    if (
		(strncmp
		 ((char *) cacheEntry->data, (char *) cacheEntryTmp->data,
		  cacheEntry->size)) != 0) {
		Ns_Log (Debug, "Cache Unset of key : '%s'", key);
		Ns_CacheUnsetValue (cacheEntryTmp);
		new = 1;
	    } else {
		Ns_Log (Debug, "Cache entry is the same: key : '%s'", key);
		result = TCL_OK;
	    }

	}

	if (new) {
	    Ns_Log (Debug, "Added New Session ID: '%s'", key);
	    Ns_CacheSetValueSz (hashEntry, cacheEntry, cacheEntry->size);
	    result = TCL_OK;
	} else {
	    Ns_Log (Debug, "Was not able to add New Session ID: '%s'", key);
	    Ns_Free (value);
	    Ns_Free (cacheEntry);
	    result = TCL_ERROR;
	}
    }
    Ns_CacheUnlock (server->cachehash);

    return result;
}

SSL_SESSION *
NsSSLGetSessionCacheEntry (SSL * ssl, unsigned char *id, int id_length,
			   int *copy)
{
    SSLConnection *connection;
    SSLServer *server;
    SSL_SESSION *session = NULL;
    SSLSessionCacheEntry *cacheEntry;
    Ns_Entry *hashEntry;
    char key[1024];

    Ns_Log (Debug, ">>> NsSSLGetSessionCacheEntry()");

    /*
     * Get our server record via the SSL's application data.
     */

    connection = (SSLConnection *) SSL_get_app_data (ssl);
    server = connection->server;

    /*
     * Convert the session id to ascii base64
     */

    Ns_HtuuEncode (id, id_length, key);

    Ns_CacheLock (server->cachehash);
    {
	hashEntry = Ns_CacheFindEntry (server->cachehash, key);
	if (hashEntry == NULL) {
	    Ns_Log (Debug, "SSLCache: Did not find entry for key '%s'", key);
	} else {
	    Ns_Log (Debug, "SSLCache: Found entry for key '%s'", key);
	    cacheEntry = Ns_CacheGetValue (hashEntry);
	    session =
		d2i_SSL_SESSION (NULL, (unsigned char **) &cacheEntry->data,
				 cacheEntry->size);
	}
    }
    Ns_CacheUnlock (server->cachehash);

    *copy = 0;
    return session;
}

void
NsSSLDelSessionCacheEntry (SSL_CTX * ctx, SSL_SESSION * session)
{
    SSLConnection *connection;
    SSLServer *server;
    Ns_Entry *hashEntry;
    SSLSessionCacheEntry *cacheEntry;
    char key[1024];

    Ns_Log (Debug, ">>> NsSSLDelSessionCacheEntry()");

    Ns_Log (Debug, "NsSSLDelSessionCacheEntry: Session hits: '%d'", SSL_CTX_sess_hits (ctx));

    /*
     * Get our server record via the SSL_CTX's application data.
     */

    server = (SSLServer *) SSL_CTX_get_app_data (ctx);

    /*
     * Convert the session id to ascii base64
     */

    Ns_HtuuEncode (session->session_id, session->session_id_length, key);
    Ns_Log (Debug, "Deleting Session ID: '%s'", key);

    Ns_CacheLock (server->cachehash);
    {
	hashEntry = Ns_CacheFindEntry (server->cachehash, key);
	if (hashEntry != NULL) {
	    cacheEntry = Ns_CacheGetValue (hashEntry);
	    if (cacheEntry == NULL) {
		Ns_Log (Debug, "SSLCache: Did not find entry for key '%s'",
			key);
	    } else {
		NsSSLFreeEntry (cacheEntry);
		Ns_CacheDeleteEntry (hashEntry);
	    }
	}
    }
    Ns_CacheUnlock (server->cachehash);
}

void
NsSSLFreeEntry (SSLSessionCacheEntry * cacheEntry)
{
    Ns_Free (cacheEntry->data);
    Ns_Free (cacheEntry);
}

