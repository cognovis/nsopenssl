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
 *
 * Modifications by Freddie Mendoza to work with AOLserver 3.0 (see ChangeLog)
 * Originally written by Stefan Arentz, stefan.arentz@soze.com
 *
 * This module implements an SSL socket driver using the OpenSSL
 * library.
 *
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
#include "tclcmds.h"

/*
 * Local functions defined in this file
 */

static Ns_ThreadProc SockThread;

static void
  SockFreeConn (SockDrv * sdPtr, ConnData * cdPtr);

static SockDrv *firstSockDrvPtr;
static Ns_Thread sockThread;
static SOCKET trigPipe[2];

static Ns_DriverStartProc SockStart;
static Ns_DriverStopProc SockStop;
static Ns_ConnReadProc SockRead;
static Ns_ConnWriteProc SockWrite;
static Ns_ConnCloseProc SockClose;
static Ns_ConnConnectionFdProc SockConnectionFd;
static Ns_ConnDetachProc SockDetach;
static Ns_ConnPeerProc SockPeer;
static Ns_ConnLocationProc SockLocation;
static Ns_ConnPeerPortProc SockPeerPort;
static Ns_ConnPortProc SockPort;
static Ns_ConnHostProc SockHost;
static Ns_ConnDriverNameProc SockName;
static Ns_ConnInitProc SockInit;

static Ns_DrvProc sockProcs[] = {
    {Ns_DrvIdStart, (void *) SockStart},
    {Ns_DrvIdStop, (void *) SockStop},
    {Ns_DrvIdRead, (void *) SockRead},
    {Ns_DrvIdWrite, (void *) SockWrite},
    {Ns_DrvIdClose, (void *) SockClose},
    {Ns_DrvIdHost, (void *) SockHost},
    {Ns_DrvIdPort, (void *) SockPort},
    {Ns_DrvIdName, (void *) SockName},
    {Ns_DrvIdPeer, (void *) SockPeer},
    {Ns_DrvIdPeerPort, (void *) SockPeerPort},
    {Ns_DrvIdLocation, (void *) SockLocation},
    {Ns_DrvIdConnectionFd, (void *) SockConnectionFd},
    {Ns_DrvIdDetach, (void *) SockDetach},
    {Ns_DrvIdInit, (void *) SockInit},
    {0, NULL}
};

#ifndef NS_EXPORT
# define NS_EXPORT
#endif

static int
  NsSSLInterpInit (Tcl_Interp * interp, void *ignored);

NS_EXPORT int Ns_ModuleVersion = 1;

/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *	Sock module init routine. We read in parameters from the
 *	config file and pass them to NsSSLCreateServer.
 *
 * Results:
 *	NS_OK if initialized ok, NS_ERROR otherwise.
 *
 * Side effects:
 *	Calls Ns_RegisterLocation as specified by this instance
 *	in the config file.
 *
 *---------------------------------------------------------------------- */

NS_EXPORT int
Ns_ModuleInit (char *server, char *module)
{
    struct stat st;
    char *path, *address, *host, *bindaddr;
    int n;
    Ns_DString ds;
    struct in_addr ia;
    struct hostent *he;
    SockDrv *sdPtr;
    SSLConf *config;
    char *certfile, *keyfile, *ciphersuite, *protocol_list;
    char *cacertfile, *cacertpath;
    int cache, cachesize, cachetimeout;
    int tmp;
    char *p;
    int i, count;
    int protocol, protocol_opt;
    char **name;

    config = (SSLConf *) ns_calloc (1, sizeof (SSLConf));

    path = Ns_ConfigGetPath (server, module, NULL);

    Ns_Log (Debug, "Entering Ns_ModuleInit() - Initializing global SSL stuff");

    /*
     * Global SSL Initialization.
     */

    SSL_load_error_strings ();
    SSLeay_add_ssl_algorithms ();
    SSL_library_init ();
    X509V3_add_standard_extensions ();

    /*
     * Determine the hostname used for the local address to bind
     * to and/or the HTTP location string.
     */

    host = Ns_ConfigGetValue (path, "hostname");
    bindaddr = address = Ns_ConfigGetValue (path, "address");

    /*
     * If the listen address was not specified, attempt to determine it
     * through a DNS lookup of the specified hostname or the server's
     * primary hostname.
     */

    if (address == NULL) {
	he = gethostbyname (host ? host : Ns_InfoHostname ());

	/*
	 * If the lookup suceeded but the resulting hostname does not
	 * appear to be fully qualified, attempt a reverse lookup on the
	 * address which often return the fully qualified name.
	 *
	 * NB: This is a common, but sloppy configuration for a Unix
	 * network.
	 */

	if (he != NULL && he->h_name != NULL
	    && strchr (he->h_name, '.') == NULL) {
	    he = gethostbyaddr (he->h_addr, he->h_length, he->h_addrtype);
	}

	/*
	 * If the lookup suceeded, use the first address in host entry list.
	 */

	if (he == NULL || he->h_name == NULL) {
	    Ns_Log (Error, "nsopenssl(%s):  Could not resolve '%s':  %s",
		    module, host ? host : Ns_InfoHostname (),
		    strerror (errno));
	    return NS_ERROR;
	}
	if (*(he->h_addr_list) == NULL) {
	    Ns_Log (Error,
		    "nsopenssl(%s): NULL address list in (derived) "
		    "host entry for '%s'", module, he->h_name);
	    return NS_ERROR;
	}
	memcpy (&ia.s_addr, *(he->h_addr_list), sizeof (ia.s_addr));
	address = ns_inet_ntoa (ia);

	/*
	 * Finally, if no hostname was specified, set it to the hostname
	 * derived from the lookup(s) above.
	 */

	if (host == NULL) {
	    host = he->h_name;
	}
    }

    /*
     * If the hostname was not specified and not determined by the lookups
     * above, set it to the specified or derived IP address string.
     */

    if (host == NULL) {
	host = address;
    }

    /*
     * Determine the port and then set the HTTP location string either
     * as specified in the config file or constructed from the
     * hostname and port.
     */

    sdPtr = ns_calloc (1, sizeof (SockDrv));

    /*
     * Create the module specific directory.
     */

    Ns_DStringInit (&ds);

    Ns_ModulePath (&ds, server, module, NULL, NULL);
    Ns_Log (Debug, "Module path: %s", Ns_DStringValue (&ds));

    if (mkdir (Ns_DStringValue (&ds), 0755) != 0 && errno != EEXIST) {
	Ns_Log (Error, "mkdir(%s) failed: %s", Ns_DStringValue (&ds),
		strerror (errno));
	return NS_ERROR;
    }

    /*
     * Determine the path to the SSL certificate file. If path is not
     * absolute then we assume that the certificate is is in the
     * module-specific ../server1/modules/nsopenssl directory.
     */

    config->certfile = Ns_ConfigGetValue (path, CONFIG_CERTFILE);
    if (config->certfile == NULL) {
	config->certfile = DEFAULT_CERTFILE;
    }

    if (Ns_PathIsAbsolute (config->certfile) == NS_FALSE) {
	Ns_DStringTrunc (&ds, 0);
	Ns_ModulePath (&ds, server, module, config->certfile, NULL);
	config->certfile = Ns_DStringExport (&ds);
    } else {
	config->certfile = Ns_StrDup (certfile);
    }

    Ns_Log (Debug, "Cert file: %s", config->certfile);

    /*
     * Determine the path to the SSL public(?) key file. If path is
     * not absolute then we assume that the key file is is in the
     * module-specific ../server1/modules/nsopenssl directory.
     */

    config->keyfile = Ns_ConfigGetValue (path, CONFIG_KEYFILE);
    if (config->keyfile == NULL) {
	config->keyfile = DEFAULT_KEYFILE;
    }

    if (Ns_PathIsAbsolute (config->keyfile) == NS_FALSE) {
	Ns_DStringTrunc (&ds, 0);
	Ns_ModulePath (&ds, server, module, config->keyfile, NULL);
	config->keyfile = Ns_DStringExport (&ds);
    } else {
	config->keyfile = Ns_StrDup (config->keyfile);
    }

    Ns_Log (Debug, "Key file: %s", config->keyfile);

    /*
     * Determine the Cache settings.
     */

    cachesize = 0;
    cachetimeout = 0;

    if (Ns_ConfigGetBool (path, CONFIG_SESSIONCACHE, &cache) == NS_FALSE) {
	cache = DEFAULT_SESSIONCACHE;
    }

    if (cache == NS_TRUE) {
	if (Ns_ConfigGetInt
	    (path, CONFIG_SESSIONCACHETIMEOUT, &cachetimeout) == NS_FALSE) {
	    cachetimeout = DEFAULT_SESSIONCACHETIMEOUT;
	}

	if (Ns_ConfigGetInt (path, CONFIG_SESSIONCACHESIZE, &cachesize) ==
	    NS_FALSE) {
	    cachesize = DEFAULT_SESSIONCACHESIZE;
	}

	config->cachesize = cachesize;
	config->cachetimeout = cachetimeout;

	Ns_Log (Debug,
		"\nSessionCacheSize = '%d'; SessionCacheTimout = '%d'",
		config->cachesize, config->cachetimeout);
    }

    /*
     * Determine the cipher suite. ciphersuite is a pointer to the
     * config data in memory; we mustn't change the config data, so
     * copy the string to where we can modify it. Ns_StrDup allocates
     * memory, copies string into it, and returns pointer to the new
     * location
     */

    config->ciphersuite = Ns_ConfigGetValue (path, CONFIG_CIPHERSUITE);
    if (config->ciphersuite == NULL) {
	Ns_Log (Notice,
		"Using default ciphersuite: %s; see CipherSuite parameter in config file",
		DEFAULT_CIPHERSUITE);
	Ns_DStringTrunc (&ds, 0);
	Ns_DStringAppend (&ds, DEFAULT_CIPHERSUITE);
	config->ciphersuite = Ns_DStringExport (&ds);
    } else {
	config->ciphersuite = Ns_StrDup (config->ciphersuite);
    }

    Ns_Log (Debug, "CipherSuite = '%s'", config->ciphersuite);

    /*
     * Determine the protocols to use
     */

    protocol_list = Ns_ConfigGetValue (path, CONFIG_PROTOCOL_LIST);
    if (protocol_list == NULL) {
	Ns_Log (Notice,
		"Using default protocols: %s; see Protocols parameter in config file",
		DEFAULT_PROTOCOL_LIST);
	Ns_DStringTrunc (&ds, 0);
	Ns_DStringAppend (&ds, DEFAULT_PROTOCOL_LIST);
	protocol_list = Ns_DStringExport (&ds);
    } else {
	protocol_list = Ns_StrDup (protocol_list);
    }

    /* TODO: BUG: if no protocol parameter is specified in the config
     * file, then the default is taken. When that happens, the server
     * "dies" after printing this with no error message. It's a string
     * thing, I'm sure. Track it down later.
     */

    Ns_Log (Notice, "SSL Protocols = '%s'\n", protocol_list);

    /* Let's not care whether the admin used upper, lower or mixed case */

    protocol_list = Ns_StrToLower (protocol_list);

    /* Extract the protocols specified */

    count = 1;
    p = protocol_list;
    while ((p = (strchr (p, ','))) != NULL) {
	++count;
	++p;
    }
    name = Ns_Malloc (sizeof (char *) * count);
    for (i = 0; i < count; ++i) {
	p = strchr (protocol_list, ',');
	if (p != NULL) {
	    *p++ = '\0';
	}
	name[i] = protocol_list;
	name[i] = Ns_StrTrim (name[i]);
	protocol_list = p;
    }

    config->protocols = SSL_PROTOCOL_NONE;

    /*
     * Extract each protocol type from the text list. Apache allows
     * you to specify protocols as "SSLv2 -SSLv3 +TLSv1", but are the
     * '+' and '-' really necessary? We'll keep it simple for now, but
     * if we ever do per-server SSL, like in virtual hosting, we might
     * revisit this.
     */

    for (i = 0; i < count; ++i) {
	if (STREQ (name[i], "sslv2")) {
	    Ns_Log (Debug, "Protocol = '%s'", name[i]);
	    config->protocols |= SSL_PROTOCOL_SSLV2;
	} else if (STREQ (name[i], "sslv3")) {
	    Ns_Log (Debug, "Protocol = '%s'", name[i]);
	    config->protocols |= SSL_PROTOCOL_SSLV3;
	} else if (STREQ (name[i], "tlsv1")) {
	    Ns_Log (Debug, "Protocol = '%s'", name[i]);
	    config->protocols |= SSL_PROTOCOL_TLSV1;
	} else if (STREQ (name[i], "all")) {
	    Ns_Log (Debug, "Protocol = '%s'", name[i]);
	    config->protocols |= SSL_PROTOCOL_ALL;
	    break;
	} else {
	    Ns_Log (Error, "Protocol not valid: %s", name[i]);
	    return NS_ERROR;
	}
    }
    Ns_Free (name);

    /* Check to be sure we really do have protocols set... */

    if (config->protocols == SSL_PROTOCOL_NONE) {
	Ns_Log (Error,
		"No protocols set in the config file, and using defaults failed");
	return NS_ERROR;
    }

    /*
     * Determine the CAs
     */

    /* TODO: Feature: add check here to see if no CAs specified yet
       client verification is mandatory */

    /* TODO: Feature: add a default set of CAs, including Verisign et
       al. */

    /* TODO: Feature: run make in the ssl.ca directory at server start time? */

    /* TODO: add DEFAULT_CACERTPATH and DEFAULT_CACERTFILE ... */

    /* Path to CA Certificate directory */

    config->cacertpath = Ns_ConfigGetValue (path, CONFIG_CACERTPATH);

    if (config->cacertpath != NULL) {
	if (Ns_PathIsAbsolute (config->cacertpath) == 0) {
	    Ns_DStringTrunc (&ds, 0);
	    Ns_ModulePath (&ds, server, module, config->cacertpath, NULL);
	    config->cacertpath = Ns_DStringExport (&ds);
	} else {
	    config->cacertpath = Ns_StrDup (config->cacertpath);
	}

	if (stat (config->cacertpath, &st) != 0) {
	    Ns_Fatal ("nsopenssl: stat(%s) failed: %s", config->cacertpath,
		      strerror (errno));
	}
	if (S_ISDIR (st.st_mode) == 0) {
	    Ns_Fatal ("nsopenssl: not a directory: %s", config->cacertpath);
	}
    } else {
	if (Ns_PathIsAbsolute (DEFAULT_CACERTPATH) == 0) {
	    Ns_DStringTrunc (&ds, 0);
	    Ns_ModulePath (&ds, server, module, DEFAULT_CACERTPATH, NULL);
	    config->cacertpath = Ns_DStringExport (&ds);
	} else {
	    config->cacertpath = DEFAULT_CACERTPATH;
	}

	if (stat (config->cacertpath, &st) != 0) {
	    Ns_Log (Notice, "Cannot find %s, %s", config->cacertpath,
		      strerror (errno));
	    config->cacertpath = NULL;
	}
	if (S_ISDIR (st.st_mode) == 0) {
	    Ns_Log (Notice, "Not a directory: %s", config->cacertpath);
	    config->cacertpath = NULL;
	}
    }

    Ns_Log (Debug, "%s = '%s'", CONFIG_CACERTPATH, config->cacertpath);

    /* Path to a CA Certificate file */

    config->cacertfile = Ns_ConfigGetValue (path, CONFIG_CACERTFILE);

    if (config->cacertfile != NULL) {
	if (Ns_PathIsAbsolute (config->cacertfile) == 0) {
	    Ns_DStringTrunc (&ds, 0);
	    Ns_ModulePath (&ds, server, module, config->cacertfile, NULL);
	    config->cacertfile = Ns_DStringExport (&ds);
	} else {
	    config->cacertfile = Ns_StrDup (config->cacertfile);
	}

	if (stat (config->cacertfile, &st) != 0) {
	    Ns_Fatal ("nsopenssl: stat(%s) failed: %s", config->cacertfile,
		      strerror (errno));
	}
	if (S_ISDIR (st.st_mode) != 0) {
	    Ns_Fatal ("nsopenssl: not a file: %s", config->cacertfile);
	}
    } else {
	if (Ns_PathIsAbsolute (DEFAULT_CACERTFILE) == 0) {
	    Ns_DStringTrunc (&ds, 0);
	    Ns_ModulePath (&ds, server, module, DEFAULT_CACERTFILE, NULL);
	    config->cacertfile = Ns_DStringExport (&ds);
	} else {
	    config->cacertfile = DEFAULT_CACERTFILE;
	}

	if (stat (config->cacertfile, &st) != 0) {
	    Ns_Log (Notice, "Cannot find %s, %s", config->cacertfile,
		      strerror (errno));
	    config->cacertfile = NULL;
	}
	if (S_ISDIR (st.st_mode) != 0) {
	    Ns_Log (Notice, "Not a file: %s", config->cacertfile,
		      strerror (errno));
	    config->cacertfile = NULL;
	}
    }

    Ns_Log (Debug, "%s = '%s'", CONFIG_CACERTFILE, config->cacertfile);

    /*
     * Figure out how the server should deal with client certificates
     */

    /*
     * Set client verification mode. Affects the SSL handshake
     * process.
     *
     * SSL_VERIFY_NONE: the result of any certificate verification is
     * ignored and processing continues
     *
     * SSL_VERIFY_PEER: causes server to request a client certificate
     *
     * SSL_VERIFY_FAIL_IF_NO_PEER_CERT: server requests client cert;
     * if none returned, abort connection
     *
     * SSL_VERIFY_CLIENT_ONCE: don't request client cert if reusing
     * session-id and a client cert was sent to the server previously
     *
     * The last argument is a pointer to a callback function that can
     * override the verification result of the built-in verification
     */

    if (Ns_ConfigGetBool (path, CONFIG_CLIENTVERIFY, &tmp) == NS_TRUE && tmp == NS_TRUE) {
        Ns_Log (Notice, "Client certificate processing is turned on");
	config->clientverifymode = SSL_VERIFY_PEER;
	if (Ns_ConfigGetBool (path, CONFIG_CLIENTVERIFYONCE, &tmp) == NS_TRUE) {
	    config->clientverifymode |= SSL_VERIFY_CLIENT_ONCE;
	    Ns_Log (Notice,
		    "Client certificate will not be re-verified for each connection if session caching is enabled");
	} else {
	    Ns_Log (Notice,
		    "Client certificate will be re-verified for each connection even if you are using session caching");
	}

        /* Get verification depth */

        /* TODO: how do I point to the address of an int type inside
        of a structure, so I can get rid of the tmp variable? */

	config->clientverifydepth = DEFAULT_CLIENTVERIFYDEPTH;
	tmp = 0;
	if (Ns_ConfigGetInt (path, CONFIG_CLIENTVERIFYDEPTH, &tmp) == NS_TRUE) {
	    config->clientverifydepth = tmp;
	}
	Ns_Log (Notice, "Client verify depth is set to %d", config->clientverifydepth);

	/* Get client verify default */

	/* The idea behind this is that if a client has no certificate
           or their certificate is invalid, we might not simply want
           to abort the connection, but instead set a couple of flags
           in SSLConnection struct and continue processing. This
           effectively passes the decision of what to do to from
           nsopenssl to the application's code. e.g. you might want to
           offer the end user a nice error page instead of chopping
           him off at the knees -- he might not know his cert is
           invalid. */

	config->clientverifydefault = NS_FALSE;
        tmp = NS_FALSE;
	if (Ns_ConfigGetBool (path, CONFIG_CLIENTVERIFYDEFAULT, &tmp) == NS_TRUE) {
	    config->clientverifydefault = tmp;
	}

	if (config->clientverifydefault == NS_TRUE) {
	    Ns_Log (Notice,
		    "Connection will not be aborted if clients has no certificate or certificate is invalid");
	    Ns_Log (Notice,
		    "This means your application will have to handle these cases!!!");
	}
    } else {
	config->clientverifymode = SSL_VERIFY_NONE;
        Ns_Log (Notice, "Client certificate processing is turned off");
    }

    /* If no cacertfile and no cacertpath and clientverify is set, then warn */
    /* TODO: BUG: you're not checking the clientverify here yet... */
    if (config->cacertpath == NULL && config->cacertfile == NULL && (config->clientverifymode & SSL_VERIFY_PEER)) {
	Ns_Log (Notice,
		"No CAs loaded, which means you will not be able to verify client certificates");
    }

    /*
     * Create a new SSL server with the characteristics from the
     * config file.
     */

    sdPtr->server = NsSSLCreateServer (config);
    if (sdPtr->server == NULL) {
	ns_free (sdPtr);
	return NS_ERROR;
    }

    sdPtr->bufsize = 0;

    sdPtr->refcnt = 1;
    sdPtr->lsock = INVALID_SOCKET;
    sdPtr->name = module;
    sdPtr->bindaddr = bindaddr;
    sdPtr->address = ns_strdup (address);
    if (!Ns_ConfigGetInt (path, "port", &sdPtr->port)) {
	sdPtr->port = DEFAULT_PORT;
    }
    sdPtr->location = Ns_ConfigGetValue (path, "location");
    if (sdPtr->location != NULL) {
	sdPtr->location = ns_strdup (sdPtr->location);
    } else {
	Ns_DStringTrunc (&ds, 0);
	Ns_DStringVarAppend (&ds, DEFAULT_PROTOCOL "://", host, NULL);
	if (sdPtr->port != DEFAULT_PORT) {
	    Ns_DStringPrintf (&ds, ":%d", sdPtr->port);
	}
	sdPtr->location = Ns_DStringExport (&ds);
    }
    if (!Ns_ConfigGetInt (path, "socktimeout", &n) || n < 1) {
	n = 30;
    }
    sdPtr->timeout = n;
    sdPtr->driver = Ns_RegisterDriver (server, module, sockProcs, sdPtr);
    if (sdPtr->driver == NULL) {
	SockFreeConn (sdPtr, NULL);
	return NS_ERROR;
    }
    sdPtr->nextPtr = firstSockDrvPtr;
    firstSockDrvPtr = sdPtr;

    /* Initialize Tcl Interp (is this the right place for this?) */
#if 0
    /* TODO: BUG: This returns an error -- should I be testing for NS_OK? */
    if (!Ns_TclInitInterps (server, NsSSLInterpInit, NULL)) {
	Ns_Log (Fatal, "NsModuleInit: Ns_TclInitInterps failed");
	return NS_ERROR;
    }
#endif
    Ns_TclInitInterps (server, NsSSLInterpInit, NULL);

    Ns_Log (Debug, "Leaving NsModuleInit");

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLInterpInit
 *
 *      Add Tcl commands for SSL functions.
 *
 * Results:
 *      NS_OK
 *
 * Side effects:
 *      Adds Tcl commands to the interp.
 *
 *----------------------------------------------------------------------
 */
static int
NsSSLInterpInit (Tcl_Interp * interp, void *ignored)
{

    Tcl_CreateCommand (interp, "ssl", SSLCmd, NULL, NULL);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * NsSSLGetConn --
 *
 *      Return the SSL connection.  Used by SSL Tcl.
 *
 * Results:
 *      Pointer to SSL connection or NULL.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
SSLConnection *
NsSSLGetConn (Ns_Conn * conn)
{
    ConnData *cdPtr;
    char *name;

    if (conn != NULL) {
	name = Ns_ConnDriverName (conn);
	if (name != NULL && STREQ (name, DRIVER_NAME)) {
	    cdPtr = Ns_ConnDriverContext (conn);
	    if (cdPtr != NULL) {
		return cdPtr->conn;
	    }
	}
    }
    return NULL;
}

/*----------------------------------------------------------------------
 *
 * SockStart --
 *
 *	Configure and then start the SockThread servicing new
 *	connections.  This is the final initializiation routine
 *	called from main().
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	SockThread is created.
 *
 *----------------------------------------------------------------------
 */

static int
SockStart (char *server, char *label, void **drvDataPtr)
{
    SockDrv *sdPtr = *((SockDrv **) drvDataPtr);

    sdPtr->lsock = Ns_SockListen (sdPtr->bindaddr, sdPtr->port);
    if (sdPtr->lsock == INVALID_SOCKET) {
	Ns_Log (Error, "%s: could not listen on %s:%d: %s",
		sdPtr->name, sdPtr->address ? sdPtr->address : "*",
		sdPtr->port, ns_sockstrerror (ns_sockerrno));
	return NS_ERROR;
    }
    if (sockThread == NULL) {
	if (ns_sockpair (trigPipe) != 0) {
	    Ns_Fatal ("ns_sockpair() failed: %s",
		      ns_sockstrerror (ns_sockerrno));
	}
	Ns_ThreadCreate (SockThread, NULL, 0, &sockThread);
    }
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SockFreeConn --
 *
 *	Return a connection to the free list, decrement the driver
 *	refcnt, and free the driver if no longer in use.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void
SockFreeConn (SockDrv * sdPtr, ConnData * cdPtr)
{
    int refcnt;

    Ns_Log (Debug, "Entering SockFreeConn");

    Ns_MutexLock (&sdPtr->lock);
    if (cdPtr != NULL) {
	cdPtr->nextPtr = sdPtr->firstFreePtr;
	sdPtr->firstFreePtr = cdPtr;
    }
    refcnt = --sdPtr->refcnt;
    Ns_MutexUnlock (&sdPtr->lock);

    if (refcnt == 0) {
	ns_free (sdPtr->location);
	ns_free (sdPtr->address);
	while ((cdPtr = sdPtr->firstFreePtr) != NULL) {
	    sdPtr->firstFreePtr = cdPtr->nextPtr;
	    ns_free (cdPtr);
	}

	Ns_Log (Debug, "...calling NsSSLDestroyServer");

	NsSSLDestroyServer (sdPtr->server);

	Ns_MutexDestroy (&sdPtr->lock);
	ns_free (sdPtr);
    }

    Ns_Log (Debug, "Leaving SockFreeConn");
}

/*
 *----------------------------------------------------------------------
 *
 * SockThread --
 *
 *	Main listening socket driver thread.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Connections are accepted on the configured listen sockets
 *	and placed on the run queue to be serviced.
 *
 *----------------------------------------------------------------------
 */

static void
SockThread (void *ignored)
{
    fd_set set, watch;
    char c;
    int slen, n, stop;
    SockDrv *sdPtr, *nextPtr;
    ConnData *cdPtr;
    struct sockaddr_in sa;
    SOCKET max, sock;

    Ns_ThreadSetName ("-nsopenssl-");
    Ns_Log (Notice, "waiting for startup");
    Ns_WaitForStartup ();

    Ns_Log (Notice, "starting");
    FD_ZERO (&watch);
    FD_SET (trigPipe[0], &watch);
    max = trigPipe[0];
    sdPtr = firstSockDrvPtr;
    firstSockDrvPtr = NULL;
    while (sdPtr != NULL) {
	nextPtr = sdPtr->nextPtr;
	if (sdPtr->lsock != INVALID_SOCKET) {
	    Ns_Log (Notice, "%s: listening on %s (%s:%d)",
		    sdPtr->name, sdPtr->location,
		    sdPtr->address ? sdPtr->address : "*", sdPtr->port);
	    if (max < sdPtr->lsock) {
		max = sdPtr->lsock;
	    }
	    FD_SET (sdPtr->lsock, &watch);
	    Ns_SockSetNonBlocking (sdPtr->lsock);
	    sdPtr->nextPtr = firstSockDrvPtr;
	    firstSockDrvPtr = sdPtr;
	}
	sdPtr = nextPtr;
    }
    ++max;

    Ns_Log (Notice, "accepting connections");
    stop = 0;
    do {
	memcpy (&set, &watch, sizeof (fd_set));
	do {
	    n = select (max, &set, NULL, NULL, NULL);
	}
	while (n < 0 && ns_sockerrno == EINTR);
	if (n < 0) {
	    Ns_Fatal ("select() failed: %s", ns_sockstrerror (ns_sockerrno));
	} else if (FD_ISSET (trigPipe[0], &set)) {
	    if (recv (trigPipe[0], &c, 1, 0) != 1) {
		Ns_Fatal ("trigger recv() failed: %s",
			  ns_sockstrerror (ns_sockerrno));
	    }
	    stop = 1;
	    --n;
	}

	sdPtr = firstSockDrvPtr;
	while (n > 0 && sdPtr != NULL) {
	    if (FD_ISSET (sdPtr->lsock, &set)) {
		--n;
		slen = sizeof (sa);
		sock = accept (sdPtr->lsock, (struct sockaddr *) &sa, &slen);
		if (sock != INVALID_SOCKET) {
		    Ns_MutexLock (&sdPtr->lock);
		    ++sdPtr->refcnt;
		    cdPtr = sdPtr->firstFreePtr;
		    if (cdPtr != NULL) {
			sdPtr->firstFreePtr = cdPtr->nextPtr;
		    }
		    Ns_MutexUnlock (&sdPtr->lock);
		    if (cdPtr == NULL) {
			cdPtr =
			    ns_malloc (sizeof (ConnData) + sdPtr->bufsize);
		    }
		    cdPtr->sdPtr = sdPtr;
		    cdPtr->sock = sock;
		    cdPtr->port = ntohs (sa.sin_port);

		    cdPtr->conn = NULL;

		    strcpy (cdPtr->peer, ns_inet_ntoa (sa.sin_addr));
		    if (Ns_QueueConn (sdPtr->driver, cdPtr) != NS_OK) {
			Ns_Log (Debug,
				"...calling SockClose in SockThread() - couldn't queue new connection");
			(void) SockClose (cdPtr);
		    }
		}
	    }
	    sdPtr = sdPtr->nextPtr;
	}
    }
    while (!stop);

    while ((sdPtr = firstSockDrvPtr) != NULL) {
	firstSockDrvPtr = sdPtr->nextPtr;
	Ns_Log (Notice, "%s: closing %s", sdPtr->name, sdPtr->location);
	ns_sockclose (sdPtr->lsock);
	SockFreeConn (sdPtr, NULL);
    }

    ns_sockclose (trigPipe[0]);
    ns_sockclose (trigPipe[1]);
}

/*
 *----------------------------------------------------------------------
 *
 * SockStop --
 *
 *	Trigger the SockThread to shutdown.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	SockThread will close ports.
 *
 *----------------------------------------------------------------------
 */

static void
SockStop (void *arg)
{
    SockDrv *sdPtr = (SockDrv *) arg;

    if (sockThread != NULL) {
	Ns_Log (Notice, DEFAULT_NAME ":  exiting: triggering shutdown");
	if (send (trigPipe[1], "", 1, 0) != 1) {
	    Ns_Fatal ("trigger send() failed: %s",
		      ns_sockstrerror (ns_sockerrno));
	}
	Ns_ThreadJoin (&sockThread, NULL);
	sockThread = NULL;
	Ns_Log (Notice, DEFAULT_NAME ":  exiting: shutdown complete");
    }
}

/*
 *----------------------------------------------------------------------
 *
 * SockClose --
 *
 *	Close the socket 
 *
 * Results:
 *	NS_OK/NS_ERROR 
 *
 * Side effects:
 *	Socket will be closed and buffer returned to free list.
 *
 *----------------------------------------------------------------------
 */

static int
SockClose (void *arg)
{
    ConnData *cdPtr = arg;
    SockDrv *sdPtr = cdPtr->sdPtr;

    Ns_Log (Debug, "Entering SockClose");

    if (cdPtr->sock != INVALID_SOCKET) {
	if (cdPtr->conn != NULL) {
	    (void) NsSSLFlush (cdPtr->conn);
	    NsSSLDestroyConn (cdPtr->conn);
	    cdPtr->conn = NULL;
	}
	ns_sockclose (cdPtr->sock);
	cdPtr->sock = INVALID_SOCKET;
    }

    SockFreeConn (cdPtr->sdPtr, cdPtr);

    Ns_Log (Debug, "Leaving SockClose");

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SockRead --
 *
 *	Read from the socket 
 *
 * Results:
 *	# bytes read 
 *
 * Side effects:
 *	Will read from socket 
 *
 *----------------------------------------------------------------------
 */

static int
SockRead (void *arg, void *vbuf, int toread)
{
    ConnData *cdPtr = arg;

    return NsSSLRecv (cdPtr->conn, vbuf, toread);
}

/*
 *----------------------------------------------------------------------
 *
 * SockWrite --
 *
 *	Writes data to a socket.
 *	NOTE: This may not write all of the data you send it!
 *
 * Results:
 *	Number of bytes written, -1 for error 
 *
 * Side effects:
 *	Bytes may be written to a socket
 *
 *----------------------------------------------------------------------
 */

static int
SockWrite (void *arg, void *buf, int towrite)
{
    ConnData *cdPtr = arg;

    return NsSSLSend (cdPtr->conn, buf, towrite);
}

/*
 *----------------------------------------------------------------------
 *
 * SockHost --
 *
 *	Return the host (addr) I'm bound to 
 *
 * Results:
 *	String hostname 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static char *
SockHost (void *arg)
{
    ConnData *cdPtr = arg;

    return cdPtr->sdPtr->address;
}

/*
 *----------------------------------------------------------------------
 *
 * SockPort --
 *
 *	Get the port I'm listening on.
 *
 * Results:
 *	A TCP port number 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static int
SockPort (void *arg)
{
    ConnData *cdPtr = arg;

    return cdPtr->sdPtr->port;
}

/*
 *----------------------------------------------------------------------
 *
 * SockName --
 *
 *	Return the name of this driver 
 *
 * Results:
 *	"nsopenssl" (the standard socket)
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static char *
SockName (void *arg)
{
    ConnData *cdPtr = arg;

    return cdPtr->sdPtr->name;
}

/*
 *----------------------------------------------------------------------
 *
 * SockPeer --
 *
 *	Return the string name of the peer address 
 *
 * Results:
 *	String peer (ip) addr 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static char *
SockPeer (void *arg)
{
    ConnData *cdPtr = arg;

    return cdPtr->peer;
}

/*
 *----------------------------------------------------------------------
 *
 * SockConnectionFd --
 *
 *	Get the socket fd 
 *
 * Results:
 *	The socket fd 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static int
SockConnectionFd (void *arg)
{
    ConnData *cdPtr = arg;

    if (cdPtr->conn == NULL || !NsSSLFlush (cdPtr->conn)) {
	return -1;
    }

    return (int) cdPtr->sock;
}

/*
 *----------------------------------------------------------------------
 *
 * SockDetach --
 *
 *	Detach the connection data from this conneciton for keep-alive.
 *
 * Results:
 *	Pointer to connection data.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void *
SockDetach (void *arg)
{
    return arg;
}

/*
 *----------------------------------------------------------------------
 *
 * SockPeerPort --
 *
 *	Get the peer's originating tcp port 
 *
 * Results:
 *	A tcp port 
 *
 * Side effects:
 *	None 
 *
 *----------------------------------------------------------------------
 */

static int
SockPeerPort (void *arg)
{
    ConnData *cdPtr = arg;

    return cdPtr->port;
}

/*
 *----------------------------------------------------------------------
 *
 * SockLocation --
 *
 *	Returns the location, suitable for making anchors 
 *
 * Results:
 *	String location 
 *
 * Side effects:
 *	none 
 *
 *----------------------------------------------------------------------
 */

static char *
SockLocation (void *arg)
{
    ConnData *cdPtr = arg;

    return cdPtr->sdPtr->location;
}

/*
 *----------------------------------------------------------------------
 *
 * SockInit --
 *
 *      Initialize the SSL connection.
 *
 * Results:
 *	NS_OK/NS_ERROR
 *
 * Side effects:
 *	Stuff may be written to a socket.
 *
 *----------------------------------------------------------------------
 */

static int
SockInit (void *arg)
{
    ConnData *cdPtr = arg;

    Ns_Log (Debug, "Entering SockInit");

    if (cdPtr->conn == NULL) {
	cdPtr->conn = NsSSLCreateConn (cdPtr->sock, cdPtr->sdPtr->timeout,
				       cdPtr->sdPtr->server);
	if (cdPtr->conn == NULL) {
	    Ns_Log (Notice, "SockInit: cdPtr->conn was null\n");
	    return NS_ERROR;
	}
    }

    Ns_Log (Debug, "Leaving SockInit");

    return NS_OK;
}
