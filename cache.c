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
 * Copyright (C) 2000 Rob Mayoff
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

#include <time.h>

#include "nsopenssl.h"
#include "cache.h"
#include "config.h"

static int NewEntry(SSL *ssl, SSL_SESSION *session);
static SSL_SESSION *GetEntry(SSL *ssl, unsigned char *id, int id_length,
    int *copy);
static void DeleteEntry(SSL_CTX *ctx, SSL_SESSION *session);
static void FreeValue(void *value);



/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLInitSessionCache --
 *
 *       Initialize the session cache for the SSL server as specified
 *       in the server config.
 *
 * Results:
 *       NS_OK or NS_ERROR.
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

int
NsOpenSSLInitSessionCache(NsOpenSSLDriver *sdPtr)
{
    char *module = sdPtr->module;
    char *path = sdPtr->configPath;
    int   cacheEnabled;
    int   cacheSize;
    long  timeout;

    cacheEnabled = ConfigBoolDefault(module, path, CONFIG_SESSIONCACHE,
	DEFAULT_SESSIONCACHE);

    if (cacheEnabled) {

	timeout = (long) ConfigIntDefault(module, path,
	    CONFIG_SESSIONTIMEOUT, DEFAULT_SESSIONTIMEOUT);
	SSL_CTX_set_timeout(sdPtr->context, timeout);

	SSL_CTX_set_session_cache_mode(sdPtr->context,
	    SSL_SESS_CACHE_SERVER);

	cacheSize = ConfigIntDefault(module, path,
	    CONFIG_SESSIONCACHESIZE, DEFAULT_SESSIONCACHESIZE);

	if (cacheSize > 0) {

	    sdPtr->sessionCache = Ns_CacheCreateSz("ns_openssl",
		TCL_STRING_KEYS, cacheSize,
		(Ns_Callback *) FreeValue);

	    SSL_CTX_sess_set_new_cb(sdPtr->context, NewEntry);
	    SSL_CTX_sess_set_get_cb(sdPtr->context, GetEntry);
	    SSL_CTX_sess_set_remove_cb(sdPtr->context, DeleteEntry);

	}

    } else {

	SSL_CTX_set_session_cache_mode(sdPtr->context, SSL_SESS_CACHE_OFF);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NewEntry --
 *
 *	Store an SSL_SESSION in the session cache.
 *
 * Results:
 *	1 if we kept a reference to the session, else 0.  The caller
 *      already incremented the session reference count for us, so
 *      if we don't keep a reference here we return zero and the caller
 *      will decrement the reference count.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
NewEntry(SSL *ssl, SSL_SESSION *session)
{
    NsOpenSSLConnection *scPtr;
    NsOpenSSLDriver     *sdPtr;
    char                 key[SSL_MAX_SSL_SESSION_ID_LENGTH*2];
    int                  new;
    Ns_Entry            *ePtr;
    SSL_SESSION         *otherSession;
    int                  keptReference;

    scPtr = (NsOpenSSLConnection *) SSL_get_app_data (ssl);
    sdPtr = scPtr->sdPtr;

    /*
    * Ns_Cache uses zero-terminated string keys. The string will be
    * about 1.33 * session_id_length, so SSL_MAX_SSL_SESSION_ID_LENGTH*2
    * is plenty of room even including the terminating NUL.
    */

    Ns_HtuuEncode(session->session_id, session->session_id_length, key);

    Ns_Log(Debug, "%s: cache %p with key %s", sdPtr->module, session, key);

    Ns_CacheLock (sdPtr->sessionCache);
    {
	ePtr = Ns_CacheCreateEntry(sdPtr->sessionCache, key, &new);

	if (new) {

	    Ns_Log(Debug, "%s: new cache entry",
		sdPtr->module, session);
	    keptReference = 1;
	    Ns_CacheSetValueSz(ePtr, session, 1);

	} else {
	    otherSession = (SSL_SESSION *) Ns_CacheGetValue(ePtr);

	    Ns_Log(Debug, "%s: found existing session cache entry %p",
		sdPtr->module, otherSession);

	    keptReference = 0;
	}
    }
    Ns_CacheUnlock (sdPtr->sessionCache);

    return keptReference;
}

static SSL_SESSION *
GetEntry(SSL *ssl, unsigned char *id, int id_length, int *copy)
{
    NsOpenSSLConnection *scPtr;
    NsOpenSSLDriver     *sdPtr;
    char                 key[SSL_MAX_SSL_SESSION_ID_LENGTH*2];
    Ns_Entry            *ePtr;
    SSL_SESSION         *session;

    session = NULL;

    scPtr = (NsOpenSSLConnection *) SSL_get_app_data(ssl);
    sdPtr = scPtr->sdPtr;

    Ns_HtuuEncode (id, id_length, key);

    Ns_Log(Debug, "%s: looking up %s in session cache", sdPtr->module,
	key);

    Ns_CacheLock(sdPtr->sessionCache);
    {
	ePtr = Ns_CacheFindEntry (sdPtr->sessionCache, key);
	if (ePtr == NULL) {
	    Ns_Log (Debug, "%s: key not found", sdPtr->module, key);
	} else {
	    session = (SSL_SESSION *) Ns_CacheGetValue(ePtr);
	    Ns_Log (Debug, "%s: found %p", sdPtr->module, session);
	}
    }
    Ns_CacheUnlock(sdPtr->sessionCache);

    *copy = 0;
    return session;
}

static void
DeleteEntry(SSL_CTX *ctx, SSL_SESSION *session)
{
    NsOpenSSLDriver *sdPtr;
    Ns_Entry        *ePtr;
    char             key[SSL_MAX_SSL_SESSION_ID_LENGTH*2];

    sdPtr = (NsOpenSSLDriver *) SSL_CTX_get_app_data (ctx);

    Ns_HtuuEncode (session->session_id, session->session_id_length, key);

    Ns_Log(Debug, "%s: uncache %p with key %s", sdPtr->module,
	session, key);

    Ns_CacheLock (sdPtr->sessionCache);
    {
	ePtr = Ns_CacheFindEntry(sdPtr->sessionCache, key);
	if (ePtr == NULL) {
	    Ns_Log (Debug, "%s: key not found", sdPtr->module, key);
	} else {
	    Ns_Log (Debug, "%s: found %p", sdPtr->module,
		Ns_CacheGetValue(ePtr));
	    Ns_CacheFlushEntry(ePtr);
	}
    }
    Ns_CacheUnlock (sdPtr->sessionCache);
}

static void
FreeValue(void *value)
{
    SSL_SESSION_free((SSL_SESSION *) value);
}

