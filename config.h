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
 * Copyright (C) 1999 Stefan Arentz.
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

/* @(#) $Header$ */

#define DEFAULT_PORT                443
#define DEFAULT_PROTOCOL            "https"
#define DEFAULT_NAME                "nsopenssl"

#define CONFIG_CLIENT_TRACE                "ClientTrace"
#define DEFAULT_CLIENT_TRACE               NS_FALSE

#define CONFIG_SERVER_TRACE                "ServerTrace"
#define DEFAULT_SERVER_TRACE               NS_FALSE

#define CONFIG_SERVER_CIPHERSUITE          "ServerCipherSuite"
#define CONFIG_CLIENT_CIPHERSUITE          "ClientCipherSuite"
#define DEFAULT_CIPHERSUITE                SSL_DEFAULT_CIPHER_LIST

#define	CONFIG_SERVER_PROTOCOL             "ServerProtocol"
#define	CONFIG_CLIENT_PROTOCOL             "ClientProtocol"

#define CONFIG_SERVER_CERTFILE             "ServerCertFile"
#define DEFAULT_SERVER_CERTFILE            "servercert.pem"

#define CONFIG_SERVER_KEYFILE              "ServerKeyFile"
#define DEFAULT_SERVER_KEYFILE             "serverkey.pem"

#define CONFIG_CLIENT_CERTFILE             "ClientCertFile"
#define DEFAULT_CLIENT_CERTFILE            "clientcert.pem"

#define CONFIG_CLIENT_KEYFILE              "ClientKeyFile"
#define DEFAULT_CLIENT_KEYFILE             "Clientkey.pem"

#define CONFIG_SERVER_CAFILE               "ServerCAFile"
#define DEFAULT_SERVER_CAFILE              "serverca.pem"

#define CONFIG_SERVER_CADIR                "ServerCADir"
#define DEFAULT_SERVER_CADIR               "serverca"

#define CONFIG_CLIENT_CAFILE               "ClientCAFile"
#define DEFAULT_CLIENT_CAFILE              "clientca.pem"

#define CONFIG_CLIENT_CADIR                "ClientCADir"
#define DEFAULT_CLIENT_CADIR               "clientca"

#define CONFIG_SERVER_SESSIONCACHE         "ServerSessionCache"
#define DEFAULT_SERVER_SESSIONCACHE        NS_TRUE

#define CONFIG_SERVER_SESSIONCACHESIZE     "ServerSessionCacheSize"
#define DEFAULT_SERVER_SESSIONCACHESIZE    128

#define CONFIG_SERVER_SESSIONTIMEOUT       "ServerSessionTimeout"
#define DEFAULT_SERVER_SESSIONTIMEOUT      300

#define CONFIG_CLIENT_SESSIONCACHE         "ClientSessionCache"
#define DEFAULT_CLIENT_SESSIONCACHE        NS_TRUE

#define CONFIG_CLIENT_SESSIONCACHESIZE     "ClientSessionCacheSize"
#define DEFAULT_CLIENT_SESSIONCACHESIZE    128

#define CONFIG_CLIENT_SESSIONTIMEOUT       "ClientSessionTimeout"
#define DEFAULT_CLIENT_SESSIONTIMEOUT      300

#define CONFIG_SERVER_SOCKTIMEOUT          "ServerSockTimeout"
#define DEFAULT_SERVER_SOCKTIMEOUT         30

#define CONFIG_SERVER_BUFFERSIZE           "ServerBufferSize"
#define DEFAULT_SERVER_BUFFERSIZE          16384

#define CONFIG_CLIENT_SOCKTIMEOUT          "ClientSockTimeout"
#define DEFAULT_CLIENT_SOCKTIMEOUT         30

#define CONFIG_CLIENT_BUFFERSIZE           "ClientBufferSize"
#define DEFAULT_CLIENT_BUFFERSIZE          16384

#define CONFIG_CLIENT_VERIFIES_PEER        "ClientVerifiesPeer"
#define DEFAULT_CLIENT_VERIFIES_PEER       NS_FALSE

#define CONFIG_SERVER_VERIFIES_PEER        "ServerVerifiesPeer"
#define DEFAULT_SERVER_VERIFIES_PEER       NS_FALSE

#define CONFIG_RANDOMFILE                  "RandomFile"

/* If PRNG fails to seed, up this number in your nsd.tcl */
#define CONFIG_SEEDBYTES                   "SeedBytes"
#define DEFAULT_SEEDBYTES                  1024

char *ConfigStringDefault(char *module, char *path, char *name,
    char *def);
int ConfigBoolDefault(char *module, char *path, char *name,
    int def);
int ConfigIntDefault(char *module, char *path, char *name,
    int def);
char *ConfigPathDefault(char *module, char *path, char *name,
    char *dir, char *def);

