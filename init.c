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
 * Copyright (C) 2000-2002 Scott S. Goodwin
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

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef WIN32
#include <dirent.h>
#endif
#include "nsopenssl.h"
#include "config.h"
#include "thread.h"


//static Tcl_HashTable NsOpenSSLServers;

static int InitOpenSSL (void);
static int LoadSSLContexts (char *server, char *module, Server *thisServer);

/*
 * For generating temporary RSA keys. Temp RSA keys are REQUIRED if
 * you want 40-bit encryption to work in old export browsers.
 */

static int SeedPRNG (void);


extern int
NsOpenSSLInitModule (char *server, char *module)
{
    static int globalInit = 0;
    Server *thisServer;
    Tcl_HashEntry *hPtr;
    int new;

    /* Initialize one-time global stuff */

    if (!globalInit) {
        if (InitOpenSSL () == NS_ERROR) {
            Ns_Log(Error, "%s: OpenSSL failed to initialize", MODULE);
            return NS_ERROR;
        }
        Tcl_InitHashTable(&NsOpenSSLServers, TCL_STRING_KEYS);
        globalInit = 1;
    }

    /* Initialize this server's hash table */

    thisServer = ns_malloc(sizeof(Server));
    thisServer->server = server;
    // XXX Ns_RWLockInit(&thisServer->lock);
    hPtr = Tcl_CreateHashEntry(&NsOpenSSLServers, server, &new);
    Tcl_SetHashValue(hPtr, thisServer);
    Tcl_InitHashTable(&thisServer->sslContexts, TCL_STRING_KEYS);
    Tcl_InitHashTable(&thisServer->sslDrivers, TCL_STRING_KEYS);

    /* 
     * Create the Tcl commands for this virtual server's interps. We want the
     * Tcl API available even if this virtual server doesn't use SSL in case
     * this server accidentally runs these commands. If the server doesn't
     * define any SSL contexts and no drivers are started for it (see further
     * down), the Tcl API commands will issue useful errors in the log file for
     * you. If we didn't define these commands and you had "command not found"
     * errors in the logs you'd be scratching your head.
     */
    
    if (Ns_TclInitInterps (server, NsOpenSSLCreateCmds, NULL) != NS_OK)
            return NS_ERROR;

    /* 
     * Load SSL contexts from the configuration file. If there aren't any, we
     * don't start any drivers but continue to run normally as some virtual
     * servers may not use this module.
     */

    LoadSSLContexts(server, module, thisServer);

    /*
     * Load and start the driver(s) for this virtual server.  Each driver must
     * be associated with a specific, named SSL context.  A driver manages one
     * SSL port; to get multiple SSL ports in one virtual server, you define a
     * driver for each port in the virtual server's config area.
     */


    //StartSSLDrivers(server, module);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * LoadSSLContexts --
 *
 *       Load the SSL contexts that are defined for this server from the
 *       configuration file.
 *
 * Results:
 *       NS_OK or NS_ERROR
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
LoadSSLContexts (char *server, char *module, Server *thisServer)
{
    char *path, *name, *subpath, *role;
    int i, new;
    Ns_Set *sslContexts;
    Ns_OpenSSLContext *sslContext;
    Tcl_HashEntry *hPtr;
    
    path = Ns_ConfigGetPath(server, module, "sslcontexts", NULL);
    sslContexts = Ns_ConfigGetSection(path);

    if (sslContexts == NULL) {
        /* Can't have an SSL driver if there's no SSL context */
        Ns_Log (Notice, "%s: %s: no SSL contexts defined for server; no SSL drivers will be started",
                MODULE, server);
        return NS_OK;
    }

    for (i = 0; i < Ns_SetSize(sslContexts); ++i) {
        name = Ns_SetKey(sslContexts, i);
        Ns_Log(Notice, "%s: %s: loading SSL context '%s'", MODULE, server,
                name);
        subpath = Ns_ConfigGetPath(server, module, "sslcontext", name, NULL);
        if (subpath == NULL) {
            Ns_Log(Error, "%s: %s: failed to find SSL context '%s' in configuration file",
                    MODULE, server, name);
            return NULL;
        }
    
        role = Ns_ConfigGetValue(subpath, "role");
        if (role == NULL) {
            Ns_Log(Error, "%s: %s: role parameter is not defined for SSL context '%s'",
                    MODULE, server, name);
            return NULL;
        }

        sslContext = Ns_OpenSSLContextCreate (server, module, name);
        if (sslContext == NULL)
            continue;
        
        hPtr = Tcl_CreateHashEntry(&thisServer->sslContexts, name, &new);
        if (!new) {
            Ns_Log(Error, "%s: %s: duplicate SSL context name: %s",
                    MODULE, server, name);
        // XXX   Ns_OpenSSLContextDestroy(sslContext);
        } else {
            Tcl_SetHashValue(hPtr, sslContext);
        }
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * InitOpenSSL --
 *
 *       Initializes the OpenSSL library prior to first use.
 *
 * Results:
 *       NS_OK
 *
 * Side effects:
 *       None.
 *
 *----------------------------------------------------------------------
 */

static int
InitOpenSSL (void)
{
    int count = 0;

    /* Initialize OpenSSL library */

    SSL_load_error_strings ();
    OpenSSL_add_ssl_algorithms ();
    SSL_library_init ();
    X509V3_add_standard_extensions ();

    /* Initialize OpenSSL threading */

    if (NsOpenSSLInitThreads () == NS_ERROR) {
        Ns_Log(Error, "%s: OpenSSL threads failed to initialize", MODULE);
        return NS_ERROR;
    }

    /* Initialize OpenSSL's Pseudo-Random Number Generator */

        SeedPRNG ();
    while (! RAND_status () && count < 3) {
        count++;
        Ns_Log (Notice, "%s: Seeding OpenSSL's PRNG", MODULE);
        SeedPRNG ();
    }
    if (! RAND_status ()) {
        Ns_Log (Warning, "%s: PRNG fails to have enough entropy after %d tries",
                MODULE, count);
    }

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SeedPRNG --
 *
 *       Seed OpenSSL's PRNG. Note that OpenSSL will seed the PRNG
 *       transparently if /dev/urandom is available, which it is
 *       on Linux.
 *
 * Results:
 *       NS_TRUE or NS_FALSE.
 *
 * Side effects:
 *       An NS_FALSE will result in the connection failing. This function
 *       might be called at any time by the temporary key generating
 *       function if the PRNG is not sufficiently entropinous (yes, I
 *       made that word up).
 *       
 *
 *----------------------------------------------------------------------
 */

static int
SeedPRNG (void)
{
    int i, seedBytes, readBytes, maxSeedBytes;
    double *buf_ptr = NULL;
    double *bufoffset_ptr = NULL;
    char *path, *randomFile;
    size_t size;

    if (RAND_status ()) 
          return NS_TRUE;

    Ns_Log (Notice, "%s: Seeding OpenSSL's PRNG", MODULE);

    path = Ns_ConfigGetPath (NULL, MODULE, NULL);

    if (Ns_ConfigGetInt(path, "seedbytes", &seedBytes) == NS_FALSE) {
        seedBytes = DEFAULT_SEED_BYTES;
    }

    if (Ns_ConfigGetInt(path, "maxseedbytes", &maxSeedBytes) == NS_FALSE) {
        maxSeedBytes = DEFAULT_MAX_SEED_BYTES;
    }

    randomFile = Ns_ConfigGetValue(path, "randomfile");

    /*
     * Try to use the file specified by the user. If PRNG fails to seed here,
     * you might try increasing the seedBytes parameter in nsd.tcl.
     */

    if (randomFile != NULL && access (randomFile, F_OK) == 0) {
    	if ((readBytes = RAND_load_file (randomFile, maxSeedBytes))) {
	        Ns_Log (Notice, "%s: Obtained %d random bytes from %s",
		        MODULE, readBytes, randomFile);
	    } else {
	        Ns_Log (Warning, "%s: Unable to retrieve any random data from %s",
		        MODULE, randomFile);
	    }
    } else {
        Ns_Log(Warning, "%s: No randomFile set and/or found", MODULE);
    }

    if (RAND_status ()) 
	    return NS_TRUE;

    Ns_Log (Notice, "%s: PRNG seeding from file failed; let's try Ns_DRand()",
            MODULE);

    /*
     * Use Ns_DRand(); I have no idea how to measure the amount of entropy, so for
     * now I just pass seedBytes as the 2nd arg to RAND_add. Not all of the
     * buffer is used. It's on my list of research topics.
     */

    size          = sizeof(double) * seedBytes;
    buf_ptr       = Ns_Malloc (size);
    bufoffset_ptr = buf_ptr;

    for (i = 0; i < seedBytes; i++) {
       *bufoffset_ptr = Ns_DRand ();
	bufoffset_ptr++;
    }

    RAND_add (buf_ptr, seedBytes, (double) seedBytes);
    Ns_Free (buf_ptr);

    if (RAND_status ()) {
        Ns_Log (Notice, "%s: PRNG successfully seeded with %d bytes from Ns_DRand",
	    MODULE, seedBytes);
    } else {
        Ns_Log (Warning, "%s: PRNG failed to be seeded with Ns_DRand", MODULE);
        return NS_FALSE;
    }

    return NS_TRUE;
}
