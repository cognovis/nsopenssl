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
 * tclcmds.c --
 *
 *   Tcl API for nsopenssl
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include "nsopenssl.h"

static int 
CreateTclChannel(NsOpenSSLConn *sslconn, Tcl_Interp *interp);

static int
ChanCloseProc(ClientData arg, Tcl_Interp *interp);

static int
ChanInputProc(ClientData arg, char *buf, int bufSize, int *errorCodePtr);

static int
ChanOutputProc(ClientData arg, char *buf, int toWrite, int *errorCodePtr);

static void
ChanWatchProc(ClientData arg, int mask);

static int
ChanFlushProc(ClientData arg);

static int
ChanGetHandleProc(ClientData arg, int direction, ClientData *handlePtr);

static void 
SetResultToX509Name(Tcl_Interp *interp, X509_NAME *name);

static void
SetResultToObjectName(Tcl_Interp *interp, ASN1_OBJECT *obj);

static char *
ValidTime(ASN1_UTCTIME *tm);

static char *
PEMCertificate(X509 *peercert);

static int
EnterSock(Tcl_Interp *interp, SOCKET sock);

static int
EnterDup(Tcl_Interp *interp, SOCKET sock);

static int
EnterDupedSocks(Tcl_Interp *interp, SOCKET sock);

static int
GetSet(Tcl_Interp * interp, char *flist, int write, fd_set ** setPtrPtr,
        fd_set * setPtr, SOCKET * maxPtr);

static void
AppendReadyFiles (Tcl_Interp * interp, fd_set * setPtr, int write,
        char *flist, Tcl_DString * dsPtr);

static Ns_SockProc
SSLSockListenCallbackProc;

static Ns_SockProc
SSLSockCallbackProc;

/*
 * Define a Tcl channel so we can use standard Tcl commands to read and write on the connection.
 */

static Tcl_ChannelType opensslChannelType = {
    "openssl",                  /* Type name. */
    TCL_CHANNEL_VERSION_2,      /* channel version 2 */
    ChanCloseProc,              /* Close proc. */
    ChanInputProc,              /* Input proc. */
    ChanOutputProc,             /* Output proc. */
    NULL,                       /* Seek proc. */
    NULL,                       /* Set option proc. */
    NULL,                       /* Get option proc. */
    ChanWatchProc,              /* Watch proc. (mandatory) */
    ChanGetHandleProc,          /* Get Handle */
    NULL,                       /* Close2 proc */
    NULL,                       /* Set blocking/nonblocking mode. */
    ChanFlushProc,              /* Flush proc */
    NULL,                       /* Handler proc */
};

static Ns_TclInterpInitProc 
AddCmds;

/* XXX check that all are here */
extern Tcl_ObjCmdProc
    NsTclOpenSSLObjCmd,
    NsTclOpenSSLSockAcceptObjCmd,
    NsTclOpenSSLSockOpenObjCmd,
    NsTclOpenSSLSockListenObjCmd,
    NsTclOpenSSLSockListenCallbackObjCmd,
    NsTclOpenSSLSockCallbackObjCmd,
    NsTclOpenSSLGetUrlObjCmd;

/* XXX check that all are here */
extern Tcl_CmdProc
    NsTclOpenSSLGetUrlCmd,
    NsTclOpenSSLSockCheckCmd,
    NsTclOpenSSLSockNReadCmd,
    NsTclOpenSSLSockSelectCmd;

typedef struct Cmd {
    char *name;
    Tcl_CmdProc *proc;
    Tcl_ObjCmdProc *objProc;
} Cmd;

static Cmd nsopensslCmds[] = {
    {"ns_openssl",                    NULL,                              NsTclOpenSSLObjCmd                     },
    {"ns_openssl_sockopen",           NULL,                              NsTclOpenSSLSockOpenObjCmd             },
    {"ns_openssl_geturl",             NULL,                              NsTclOpenSSLGetUrlObjCmd               },
    {"ns_openssl_sockaccept",         NULL,                              NsTclOpenSSLSockAcceptObjCmd           },
    {"ns_openssl_socklisten",         NULL,                              NsTclOpenSSLSockListenObjCmd           },
    {"ns_openssl_sockcallback",       NULL,                              NsTclOpenSSLSockCallbackObjCmd         },
    {"ns_openssl_socklistencallback", NULL,                              NsTclOpenSSLSockListenCallbackObjCmd   },
/* XXX following are untested, perhaps unused ? */
//  {"ns_openssl_socknread",          NsTclOpenSSLSockNReadCmd,          NULL                                   },
//  {"ns_openssl_sockselect",         NsTclOpenSSLSockSelectCmd,         NULL                                   },
//  {"ns_openssl_sockcheck",          NsTclOpenSSLSockCheckCmd,          NULL                                   },
#if 0  /* these ns_openssl_sock* commands are not implemented */
    {"ns_openssl_socketpair",         NsTclSSLSocketPairCmd,             NULL                                   },
    {"ns_openssl_hostbyaddr",         NsTclSSLGetByCmd,                  NULL                                   },
    {"ns_openssl_addrbyhost",         NsTclSSLGetByCmd,                  (ClientData) 1                         },
#endif
    {NULL, NULL, NULL}
};

typedef struct SockListenCallback {
    char *server;
    NsOpenSSLContext *sslcontext;
    char *script;
} SockListenCallback;

typedef struct SockCallback {
    char *server;
    int when;
    char script[1];
} SockCallback;


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLTclInit --
 *
 *      Initialize Tcl API for a virtual server. The last argument of Ns_TclInitInterps is a pointer to a function that 
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

void
NsOpenSSLTclInit(char *server)
{
    Server *thisServer = NsOpenSSLServerGet(server);

#if 0
    Ns_Log(Debug, "NsOpenSSLTclInit: thisServer = (%p); thisServer->server = (%s)",
	    thisServer, thisServer->server);
#endif

    Ns_TclInitInterps(server, AddCmds, (void *) thisServer);
}


/*
 *----------------------------------------------------------------------
 *
 * AddCmds --
 *
 *      Add nsopenssl commands to Tcl interpreter.
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
AddCmds(Tcl_Interp *interp, void *arg)
{
    Cmd *cmd = (Cmd *) &nsopensslCmds;

    while (cmd->name != NULL) {

#if 0
        Ns_Log(Debug, "AddCmds: adding (%s)", cmd->name);
#endif
        if (cmd->objProc != NULL) {
            Tcl_CreateObjCommand(interp, cmd->name, cmd->objProc, arg, NULL);
        } else {
            Tcl_CreateCommand(interp, cmd->name, cmd->proc, arg, NULL);
        }
        ++cmd;
    }

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLObjCmd --
 *
 *      Implements ns_openssl command, which returns information about clients
 *      connected to the nsopenssl server, including client certificates.
 *
 * Results:
 *      Tcl string result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
NsTclOpenSSLObjCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj **objv)
{
    // XXX Server *thisServer      = (Server *) arg;
    NsOpenSSLConn *sslconn  = NULL;
    X509 *peercert          = NULL;
    SSL_CIPHER *cipher      = NULL;
    Ns_Conn *conn           = NULL;
    char *string            = NULL;
    char *name              = NULL;
    int integer             = 0;
    int status              = TCL_OK;

    static CONST char *opts[] = {
        "info", "module", "protocol", "port", "peerport", "cipher",
        "clientcert" 
    };
    enum ISubCmdIdx {
        CInfoIdx, CModuleIdx, CProtocolIdx, CPortIdx, CPeerPortIdx, CCipherIdx,
        CClientCertIdx 
    } opt;


    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "option");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], opts, "option", 0,
                (int *) &opt) != TCL_OK) {
        return TCL_ERROR;
    }

    if (opt == CInfoIdx) {
        Tcl_SetResult(interp, OPENSSL_VERSION_TEXT, TCL_STATIC);
        return TCL_OK;
    }

    /* 
     * AOLserver stashes a pointer to the conn in the interp. We then use that
     * to get a pointer to our SSL conn through the core driver's context. If
     * conn is NULL, it means our connection is not driver by the comm API, so
     * we need to get the connection information back another way.
     */

    conn = Ns_TclGetConn(interp);
    if (conn == NULL) {
        Tcl_AppendResult(interp, "this is not a connection thread", NULL);
        return TCL_ERROR;
    } else {
        name = Ns_ConnDriverName(conn);
        if (name != NULL && STREQ(name, MODULE)) {
            sslconn = (NsOpenSSLConn *) Ns_ConnDriverContext(conn);
        }
        if (sslconn == NULL) {
            Tcl_AppendResult(interp, "this is a connection thread, but not an SSL connection thread", NULL);
            return TCL_ERROR;
        }
    }

    switch (opt) {

        case CModuleIdx:

            /*
             * Implement:
             * ns_openssl module name
             * ns_openssl module port
             */

            if (objc != 3) {
                Tcl_WrongNumArgs(interp, 2, objv, "option");
                return TCL_ERROR;
            }

            if (STREQ(Tcl_GetString(objv[2]), "name")) {
                Tcl_SetResult(interp, MODULE, TCL_VOLATILE);
            } else if (STREQ(Tcl_GetString(objv[2]), "port")) {
                /* XXX peerport is the port this conn came in on -- clean up */
                sprintf(interp->result, "%d", sslconn->peerport);
            }
            break;

        case CProtocolIdx:

#if 0
            Ns_Log(Debug, "*** sslconn->ssl = (%d)", &sslconn->ssl->session->ssl_version);
#endif

            switch (sslconn->ssl->session->ssl_version) {
                case SSL2_VERSION:
                    string = "SSLv2";
                    break;
                case SSL3_VERSION:
                    string = "SSLv3";
                    break;
                case TLS1_VERSION:
                    string = "TLSv1";
                    break;
                default:
                    string = "UNKNOWN";
            }
            Tcl_SetResult(interp, string, TCL_VOLATILE);
            break;

        case CPortIdx:
        case CPeerPortIdx:

            sprintf(interp->result, "%d", sslconn->peerport);
            break;

        case CCipherIdx:

            cipher = SSL_get_current_cipher(sslconn->ssl);

            if (objc != 3) {
                Tcl_WrongNumArgs(interp, 2, objv, "option");
                return TCL_ERROR;
            }

            if (STREQ(Tcl_GetString(objv[2]), "name")) {
                string =
                    (sslconn->ssl != NULL ? (char *) SSL_CIPHER_get_name(cipher) : NULL);
                Tcl_SetResult(interp, string, TCL_VOLATILE);
            } else if (STREQ(Tcl_GetString(objv[2]), "strength")) {
                integer = SSL_CIPHER_get_bits(cipher, &integer);
                sprintf(interp->result, "%d", integer);
            }
            break;

        case CClientCertIdx:

            /*
             * Implement:
             * ns_openssl clientcert exists
             * ns_openssl clientcert version
             * ns_openssl clientcert serial
             * ns_openssl clientcert subject
             * ns_openssl clientcert issuer
             * ns_openssl clientcert notbefore
             * ns_openssl clientcert notafter
             * ns_openssl clientcert signaturealgorithm
             * ns_openssl clientcert key_algorithm
             * ns_openssl clientcert pem
             * ns_openssl clientcert valid
             */

            if (objc != 3) {
                Tcl_WrongNumArgs(interp, 2, objv, "option");
                return TCL_ERROR;
            }

            peercert = (sslconn == NULL) ? NULL : SSL_get_peer_certificate(sslconn->ssl);

            if (STREQ(Tcl_GetString(objv[2]), "exists")) {
                Tcl_SetResult(interp, peercert == NULL ? "0" : "1",
                        TCL_STATIC);
            } else if (STREQ(Tcl_GetString(objv[2]), "version")) {
                sprintf(interp->result, "%lu",
                        peercert == NULL
                        ? 0 : X509_get_version(peercert) + 1);
            } else if (STREQ(Tcl_GetString(objv[2]), "serial")) {
                sprintf(interp->result, "%ld",
                        peercert == NULL
                        ? 0
                        :
                        ASN1_INTEGER_get(X509_get_serialNumber(peercert)));
            } else if (STREQ(Tcl_GetString(objv[2]), "subject")) {
                if (peercert != NULL) {
                    SetResultToX509Name(interp,
                            X509_get_subject_name(peercert));
                }
            } else if (STREQ(Tcl_GetString(objv[2]), "issuer")) {
                if (peercert != NULL) {
                    SetResultToX509Name(interp, X509_get_issuer_name(peercert));
                }
            } else if (STREQ(Tcl_GetString(objv[2]), "notbefore")) {
                if (peercert != NULL) {
                    string = ValidTime(X509_get_notBefore(peercert));
                    if (string == NULL) {
                        Tcl_SetResult(interp, "error getting notbefore",
                                TCL_STATIC);
                        status = TCL_ERROR;
                    } else {
                        Tcl_SetResult(interp, string, TCL_DYNAMIC);
                    }
                }
            } else if (STREQ(Tcl_GetString(objv[2]), "notafter")) {
                if (peercert != NULL) {
                    string = ValidTime(X509_get_notAfter(peercert));
                    if (string == NULL) {
                        Tcl_SetResult(interp, "error getting notafter",
                                TCL_STATIC);
                        status = TCL_ERROR;
                    } else {
                        Tcl_SetResult(interp, string, TCL_DYNAMIC);
                    }
                }
            } else if (STREQ(Tcl_GetString(objv[2]), "signature_algorithm")) {
                if (peercert != NULL) {
                    SetResultToObjectName(interp,
                            peercert->cert_info->signature->
                            algorithm);
                }
            } else if (STREQ(Tcl_GetString(objv[2]), "key_algorithm")) {
                if (peercert != NULL) {
                    SetResultToObjectName(interp,
                            peercert->cert_info->key->algor->
                            algorithm);
                }
            } else if (STREQ(Tcl_GetString(objv[2]), "pem")) {
                if (peercert != NULL) {
                    string = PEMCertificate(peercert);
                    if (string == NULL) {
                        Tcl_SetResult(interp, "error getting pem", TCL_STATIC);
                        status = TCL_ERROR;
                    } else {
                        Tcl_SetResult(interp, string, TCL_DYNAMIC);
                    }
                }
            } else if (STREQ(Tcl_GetString(objv[2]), "valid")) {
                sprintf(interp->result, "%d",
                        peercert != NULL
                        && SSL_get_verify_result(sslconn->ssl) == X509_V_OK);

            } else {
            /* XXX revalidate the list below (see if Tcl has a better library function for this) */
                Tcl_AppendResult(interp, "unknown command \"", Tcl_GetString(objv[2]),
                        "\": should be one of: exists version serial subject issuer notbefore notafter signature_algorithm key_algorithm pem valid",
                        NULL);
                return TCL_ERROR;
            }
            break;

        case CInfoIdx:
            /* NEVER REACHED */
            break;
    }

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSockOpenObjCmd --
 *
 *	Open a tcp connection to a host/port via SSL. 
 *
 * Results:
 *	Tcl result. 
 *
 * Side effects:
 *	Will open a connection and register two Tcl channels.
 *
 *----------------------------------------------------------------------
 */

int
NsTclOpenSSLSockOpenObjCmd(ClientData arg, Tcl_Interp *interp, int objc,
        Tcl_Obj *CONST objv[])
{
    Server            *thisServer = (Server *) arg;
    NsOpenSSLConn     *sslconn    = NULL;
    NsOpenSSLContext  *sslcontext = NULL;
    char              *name       = NULL;
    int                first      = 1;
    int                async      = 0;
    int                timeout    = -1;
    int                sslctx     = 0;
    int                port       = 0;
    CONST char         *args      = "?-nonblock|-timeout seconds? host port ?sslcontext?";

    /*
     * (3) ns_sockopen                    host port
     * (4) ns_sockopen -nonblock          host port
     * (5) ns_sockopen -timeout   seconds host port

     * (4) ns_sockopen                    host port sslcontext
     * (5) ns_sockopen -nonblock          host port sslcontext
     * (6) ns_sockopen -timeout   seconds host port sslcontext
     */

    /*
     * Works out to this matrix where the # is the number of args:
     *
     *              sslcontext?
     *
     *                Y    N
     *               ---------
     *  no '-'        4    3
     *  -nonblock     5    4
     *  -timeout      6    5
     */

    if (objc < 3 || objc > 6) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-nonblock|-timeout seconds? host port ?sslcontext?"); 
        return TCL_ERROR;
    }

    // XXX first   = 1;
    // XXX async   = 0;
    // XXX sslctx  = 0;
    // XXX timeout = -1;

    if (STREQ(Tcl_GetString(objv[1]), "-nonblock")) {

        if (objc == 4) {
            sslctx = 0;
        } else if (objc == 5) {
            sslctx = 1;
        } else {
            Tcl_WrongNumArgs(interp, 1, objv, args);
            return TCL_ERROR;
        }

        first = 2;
        async = 1;

    } else if (STREQ(Tcl_GetString(objv[1]), "-timeout")) {

        if (objc == 5) {
            sslctx = 0;
        } else if (objc == 6) {
            sslctx = 1;
        } else {
            Tcl_WrongNumArgs(interp, 1, objv, args);
            return TCL_ERROR;
        }

        if (Tcl_GetIntFromObj(interp, objv[2], &timeout) != TCL_OK) {
            return TCL_ERROR;
        }

        first = 3;

    } else {

        if (objc == 3) {
            sslctx = 0;
        } else if (objc == 4) {
            sslctx = 1;
        } else {
            Tcl_WrongNumArgs(interp, 1, objv, args);
            return TCL_ERROR;
        }

    }

    if (Tcl_GetIntFromObj(interp, objv[first + 1], &port) != TCL_OK) {
        return TCL_ERROR;
    }

    /*
     * Get the named SSL context. If there is no named SSL context, attempt to
     * use the default.
     */

    if (sslctx) {
        name = (char *) Tcl_GetString(objv[first + 2]);
        sslcontext = Ns_OpenSSLServerSSLContextGet(thisServer->server, name);
    } else {
        sslcontext = NsOpenSSLContextClientDefaultGet(thisServer->server);
    }

    if (sslcontext == NULL) {
        Tcl_SetResult(interp, "failed to use either named or default client SSL context", 
                TCL_STATIC);
        return TCL_ERROR;
    }

    /*
     * Perform the connection.
     */

    sslconn = Ns_OpenSSLSockConnect(
            thisServer->server,
            Tcl_GetString(objv[first]),
            port,
            async,
            timeout, 
            sslcontext
            );

    if (sslconn == NULL) {
        Tcl_AppendResult(interp, "could not connect to \"",
                Tcl_GetString(objv[first]), ":", Tcl_GetString(objv[first + 1]), "\"", NULL);
        return TCL_ERROR;
    }

#if 0
    Ns_Log(Debug, "NsTclOpenSSLSockOpenObjCmd: sslconn = (%p)", sslconn);
#endif

    /*
     * Create the Tcl channel that let's us use gets, puts etc. and layer it on
     * top of the conn.
     */

    if (CreateTclChannel(sslconn, interp) != NS_OK) {
        Ns_Log(Warning, "%s: %s: Tcl channel not available",
                MODULE, sslconn->server);
#if 0
        Ns_Log(Debug, "--->>> BEFORE ConnDestroy: SockOpen");
#endif
        NsOpenSSLConnDestroy(sslconn);
        return TCL_ERROR;
    }

    /*
     * Append "1" as the third element returned if peer's certificate is valid;
     * "0" otherwise.
     */

    if (Ns_OpenSSLIsPeerCertValid(sslconn)) {
        Tcl_AppendElement(interp, "1");
    } else {
        Tcl_AppendElement(interp, "0");
    }

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSockListenObjCmd --
 *
 *      Listen on a TCP port.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      Will listen on a port.
 *
 *----------------------------------------------------------------------
 */

extern int
NsTclOpenSSLSockListenObjCmd(ClientData arg, Tcl_Interp *interp, int objc,
        Tcl_Obj **objv)
{
    Server *thisServer = (Server *) arg;
    SOCKET  socket     = INVALID_SOCKET;
    char   *addr       = NULL;
    int     port       = 0;

    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "address port");
        return TCL_ERROR;
    }

    addr = Tcl_GetString(objv[1]);
    if (STREQ(addr, "*")) {
        addr = NULL;
    }

    if (Tcl_GetIntFromObj(interp, objv[2], &port) != TCL_OK) {
        return TCL_ERROR;
    }

    socket = Ns_OpenSSLSockListen(addr, port);

#if 0
    Ns_Log(Debug, "NsTclOpenSSLSockListenObjCmd: socket = (%d)", socket);
#endif

    if (socket == INVALID_SOCKET) {
        Tcl_AppendResult(interp, "could not listen on \"",
                addr, ":", Tcl_GetString(objv[2]), "\"", NULL);
        return TCL_ERROR;
    }

    return EnterSock(interp, socket);
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSockAcceptObjCmd --
 *
 *      Accept a connection from a listening socket.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

/* XXX SSL context needs to be passed */

extern int
NsTclOpenSSLSockAcceptObjCmd(ClientData arg, Tcl_Interp *interp, int objc,
        Tcl_Obj **objv)
{
    Server           *thisServer = (Server *) arg;
    NsOpenSSLConn    *sslconn    = NULL;
    NsOpenSSLContext *sslcontext = NULL;
    SOCKET            socket     = INVALID_SOCKET;

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "sockId");
        return TCL_ERROR;
    }

    if (Ns_TclGetOpenFd(interp, Tcl_GetString(objv[1]), 0, (int *) &socket) != TCL_OK) {
        return TCL_ERROR;
    }

    /* Do normal accept on the socket */
    socket = Ns_SockAccept(socket, NULL, 0);

    if (socket == INVALID_SOCKET) {
        Tcl_AppendResult(interp, "accept failed: ", SockError(interp), NULL);
        return TCL_ERROR;
    }

    /* Figure out which SSL context to use in creating the SSL connection */
    /* XXX update API to accept last arg of sslcontext */
    //if (sslctx) {
    //    name = (char *) Tcl_GetString(objv[first + 2]);
    //    sslcontext = Ns_OpenSSLServerSSLContextGet(thisServer->server, module, name);
    //} else {
    sslcontext = NsOpenSSLContextServerDefaultGet(thisServer->server);
    //}

    if (sslcontext == NULL) {
        Tcl_SetResult(interp, "failed to use either named or default client SSL context", 
                TCL_STATIC);
        return TCL_ERROR;
    }

    sslconn = Ns_OpenSSLSockAccept(socket, sslcontext);
    if (sslconn == NULL) {
        Tcl_SetResult(interp, "SSL accept failed", TCL_STATIC);
        return TCL_ERROR;
    }

    if (CreateTclChannel(sslconn, interp) != NS_OK) {
        Ns_Log(Error, "%s (%s): Tcl channel not available",
                MODULE, sslconn->server);
        //Ns_Log(Debug, "--->>> BEFORE ConnDestroy: SockAccept");
        NsOpenSSLConnDestroy(sslconn);
        return TCL_ERROR;
    }

    /*
     * Append "1" as the third element returned if peer certificate
     * is found to be valid; "0" otherwise. Is this the best way to do
     * it? 
     */

    if (Ns_OpenSSLIsPeerCertValid(sslconn)) {
        Tcl_AppendElement(interp, "1");
    } else {
        Tcl_AppendElement(interp, "0");
    }

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLGetUrlObjCmd --
 *
 *      Implements ns_geturl.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      See docs.
 *
 *----------------------------------------------------------------------
 */

/* XXX SSL context needs to be passed */
/* XXX restructure this function to not use the 'done' label */

extern int
NsTclOpenSSLGetUrlObjCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj **objv)
{
    Server           *thisServer = (Server *) arg;
    NsOpenSSLContext *sslcontext = NULL;
    Ns_DString        ds;
    Ns_Set           *headers    = NULL;
    int               status     = TCL_ERROR;
    char             *url        = NULL;

    Ns_DStringInit(&ds);

    if ((objc != 3) && (objc != 2)) {
        Tcl_WrongNumArgs(interp, 1, objv, " url ?headersSetIdVar?");
        goto done;
    }

    if (objc == 2) {
        headers = NULL;
    } else {
        headers = Ns_SetCreate(NULL);
    }

    url = Tcl_GetString(objv[1]);

    if (url == '/') {

        if (Ns_FetchPage(&ds, url, Ns_TclInterpServer(interp)) != NS_OK) {
            Tcl_AppendResult(interp, "Could not get contents of URL \"",
                    url, "\"", NULL);
            goto done;
        }

    } else {

        /* Figure out which SSL context to use in creating the SSL connection */
        /* XXX update API to accept last arg of sslcontext */
        //if (sslctx) {
        //    name = (char *) Tcl_GetString(objv[first + 2]);
        //    sslcontext = Ns_OpenSSLServerSSLContextGet(thisServer->server, module, name);
        //} else {
        sslcontext = NsOpenSSLContextClientDefaultGet(thisServer->server);
        //}

        if (Ns_OpenSSLFetchUrl(thisServer->server, &ds, url, headers, sslcontext) != NS_OK) {
            Tcl_AppendResult(interp, "Could not get contents of URL \"",
                    url, "\"", NULL);
            if (headers != NULL) {
                Ns_SetFree(headers);
            }
            goto done;
        }

    }

    if (objc == 3) {
        Ns_TclEnterSet(interp, headers, 1);
        /* XXX there's probably a Tcl_Obj way of doing the following */
        Tcl_SetVar(interp, Tcl_GetString(objv[2]), interp->result, 0);
    }

    Tcl_SetResult(interp, ds.string, TCL_VOLATILE);

    status = TCL_OK;

done:
    Ns_DStringFree(&ds);

    return status;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSockNReadCmd --
 *
 *      Gets the number of bytes that a socket has waiting to be
 *      read.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      None.
 *   
 *----------------------------------------------------------------------
 */

/* XXX needs to be tested */

extern int
NsTclOpenSSLSockNReadCmd(ClientData arg, Tcl_Interp *interp, 
        int argc, char **argv)
{ 
    Server      *thisServer = (Server *) arg;
    Tcl_Channel  chan       = NULL;
    SOCKET       socket     = INVALID_SOCKET;   
    int          nread      = 0;
    int          status     = TCL_ERROR;

    if (argc != 2) {
        Tcl_AppendResult(interp, "wrong # args: should be \"",
                argv[0], " sockId\"", NULL);
        goto done;
    }

    chan = Tcl_GetChannel(interp, argv[1], NULL);
    if (
	    chan == NULL || 
	    Ns_TclGetOpenFd(interp, argv[1], 0, (int *) &socket) != TCL_OK
       ) {
	goto done;
    }                    

    if (ns_sockioctl(socket, FIONREAD, &nread) != 0) {
        Tcl_AppendResult(interp, "ns_sockioctl failed: ",
                SockError(interp), NULL);
        goto done;
    }

    nread += Tcl_InputBuffered(chan);
    sprintf(interp->result, "%d", nread);      
    status = TCL_OK;

done:
    return status;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSockCheckCmd --
 *
 *      Check if a socket is still connected, useful for nonblocking.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

/* XXX needs to be tested */
/* XXX do I need this wrapper? Can't I use ns_sockcheck directly? */

extern int
NsTclOpenSSLSockCheckCmd(ClientData arg, Tcl_Interp *interp, int argc, char **argv)
{
    Server *thisServer = (Server *) arg;
    SOCKET  socket     = INVALID_SOCKET;
    int     status     = TCL_ERROR;

    if (argc != 2) {
        Tcl_AppendResult(interp, "wrong # of args: should be \"",
                argv[0], " sockId\"", NULL);
        goto done;
    }

    if (Ns_TclGetOpenFd(interp, argv[1], 1, (int *) &socket) != TCL_OK) {
        goto done;
    }

#if 0
    Ns_Log(Debug, "#### SOCKET socket = %d", socket);
#endif

    if (send(socket, NULL, 0, 0) != 0) {
        interp->result = "0";
    } else {
        interp->result = "1";
    }

    status = TCL_OK;

done:
    return status;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSelectCmd --
 *
 *      Imlements ns_sockselect: basically a tcl version of
 *      select(2).
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      See docs.
 *
 *----------------------------------------------------------------------
 */

/* XXX needs to be tested */
/* XXX can we use ns_sockselect directly and get rid of this command? */
/* XXX can we make this a wrapper that calls core ns_sockselect? */
/* XXX this routine is too complicated; returns sprinkled throughout... */

extern int
NsTclOpenSSLSockSelectCmd(ClientData arg, Tcl_Interp *interp, 
        int argc, char **argv) 
{
    Server         *thisServer = (Server *) arg;
    /* XXX not initialized */
    fd_set          rset;
    fd_set          wset;
    fd_set          eset;
    fd_set          *rPtr      = NULL; 
    fd_set          *wPtr      = NULL;
    fd_set          *ePtr      = NULL;
    SOCKET          maxfd      = INVALID_SOCKET;
    Tcl_Channel     chan       = NULL;
    Tcl_DString     dsRfd;
    Tcl_DString     dsNbuf;
    /* XXX not initialized */
    struct timeval  tv;
    struct timeval *tvPtr      = NULL;
    char          **fargv      = NULL;
    int             fargc      = 0;
    int             i;
    int             status     = TCL_ERROR;
    int             first;

    Tcl_DStringInit(&dsRfd);
    Tcl_DStringInit(&dsNbuf);

    if (argc != 6 && argc != 4) {
        Tcl_AppendResult(interp, "wrong # args: should be \"",
                argv[0], " ?-timeout sec? rfds wfds efds\"", NULL);
        return TCL_ERROR;
    }

    if (argc == 4) {
        tvPtr = NULL;
        first = 1;
    } else {
        tvPtr = &tv;
        if (strcmp(argv[1], "-timeout") != 0) {
            Tcl_AppendResult(interp, "wrong # args: should be \"",
                    argv[0], " ?-timeout sec? rfds wfds efds\"",
                    NULL);
            return TCL_ERROR;
        }
        tv.tv_usec = 0;
        if (Tcl_GetInt(interp, argv[2], &i) != TCL_OK) {
            return TCL_ERROR;
        }
        tv.tv_sec = i;
        first = 3;
    }

    /*
     * Readable fd's are treated differently because they may
     * have buffered input. Before doing a select, see if they
     * have any waiting data that's been buffered by the channel.
     */

    if (Tcl_SplitList(interp, argv[first++], &fargc, &fargv) != TCL_OK) {
        return TCL_ERROR;
    }

    for (i = 0; i < fargc; ++i) {
        chan = Tcl_GetChannel(interp, fargv[i], NULL);
        if (chan == NULL) {
            goto done;
        }
        if (Tcl_InputBuffered(chan) > 0) {
            Tcl_DStringAppendElement(&dsNbuf, fargv[i]);
        } else {
            Tcl_DStringAppendElement(&dsRfd, fargv[i]);
        }
    }

    if (dsNbuf.length > 0) {
        /*
         * Since at least one read fd had buffered input,
         * turn the select into a polling select just
         * to pick up anything else ready right now.
         */

        tv.tv_sec = 0;
        tv.tv_usec = 0;
        tvPtr = &tv;
    }

    maxfd = 0;
    if (GetSet(interp, dsRfd.string, 0, &rPtr, &rset, &maxfd) != TCL_OK) {
        goto done;
    }
    if (GetSet(interp, argv[first++], 1, &wPtr, &wset, &maxfd) != TCL_OK) {
        goto done;
    }
    if (GetSet(interp, argv[first++], 0, &ePtr, &eset, &maxfd) != TCL_OK) {
        goto done;
    }

    /*
     * Return immediately if we're not doing a select on anything.
     */

    if (dsNbuf.length == 0 &&
            rPtr == NULL &&
            wPtr == NULL &&
            ePtr == NULL &&
            tvPtr == NULL) {

        status = TCL_OK;

    } else {

        /*
         * Actually perform the select.
         */

        do {
            i = select(maxfd + 1, rPtr, wPtr, ePtr, tvPtr);
        } while (i < 0 && ns_sockerrno == EINTR);

        if (i == -1) {
            Tcl_AppendResult(interp, "select failed: ",
                    SockError(interp), NULL);
        } else {
            if (i == 0) {
                /*
                 * The sets can have any random value now
                 */

                if (rPtr != NULL) {
                    FD_ZERO(rPtr);
                }
                if (wPtr != NULL) {
                    FD_ZERO(wPtr);
                }
                if (ePtr != NULL) {
                    FD_ZERO(ePtr);
                }
            }
            AppendReadyFiles(interp, rPtr, 0, dsRfd.string, &dsNbuf);
            first -= 2;
            AppendReadyFiles(interp, wPtr, 1, argv[first++], NULL);
            AppendReadyFiles(interp, ePtr, 0, argv[first++], NULL);
            status = TCL_OK;
        }
    }

done:
    Tcl_DStringFree(&dsRfd);
    Tcl_DStringFree(&dsNbuf);
    ckfree((char *) fargv);

    return status;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSockCallbackObjCmd --
 *
 *      Register a Tcl callback to be run when a certain state exists
 *      on a socket.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      A callback will be registered.
 *
 *----------------------------------------------------------------------
 */

/* XXX this is identical to core command, but that the callback sets up SSL layer */
/* XXX is there any way to reduce the duplication here and use core capability directly? */

extern int
NsTclOpenSSLSockCallbackObjCmd(ClientData arg, Tcl_Interp *interp, int objc,
        Tcl_Obj **objv)
{
    Server       *thisServer = (Server *) arg;
    SockCallback *cbPtr      = NULL;
    SOCKET        socket     = INVALID_SOCKET;
    // XXX int           sockid;
    int           when       = 0;
    char         *s          = NULL;

    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "sockId script when");
        return TCL_ERROR;
    }

    s = Tcl_GetString(objv[3]);
    /* XXX use STREQ here with switch ??? */
    while (*s != '\0') {
        if (*s == 'r') {
            when |= NS_SOCK_READ;
        } else if (*s == 'w') {
            when |= NS_SOCK_WRITE;
        } else if (*s == 'e') {
            when |= NS_SOCK_EXCEPTION;
        } else if (*s == 'x') {
            when |= NS_SOCK_EXIT;
        } else {
            Tcl_AppendResult(interp, "invalid when specification \"",
                    Tcl_GetString(objv[3]), "\": should be one or more of r, w, e, or x", NULL);
            return TCL_ERROR;
        }
        ++s;
    }

    if (when == 0) {
        Tcl_AppendResult(interp, "invalid when specification \"", Tcl_GetString(objv[3]),
                "\": should be one or more of r, w, e, or x", NULL);
        return TCL_ERROR;
    }

    if (Ns_TclGetOpenFd(interp, Tcl_GetString(objv[1]), (when & NS_SOCK_WRITE),
                (int *) &socket) != TCL_OK) {
        return TCL_ERROR;
    }

    socket = ns_sockdup(socket);

    if (socket == INVALID_SOCKET) {
        Tcl_AppendResult(interp, "dup failed: ", SockError(interp), NULL);
        return TCL_ERROR;
    }

    cbPtr = ns_malloc(sizeof(SockCallback) + strlen(Tcl_GetString(objv[2])));
    cbPtr->server = thisServer->server;
    cbPtr->when = when;
    strcpy(cbPtr->script, Tcl_GetString(objv[2]));

    if (Ns_SockCallback(socket, SSLSockCallbackProc, cbPtr, when | NS_SOCK_EXIT) != NS_OK) {
        interp->result = "could not register callback";
        ns_sockclose(socket);
        ns_free(cbPtr);
        return TCL_ERROR;
    }

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLSockListenCallbackObjCmd --
 *
 *      Listen on a socket and register a callback to run when
 *      connections arrive.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      Will register a callback and listen on a socket.
 *
 *----------------------------------------------------------------------
 */

int
NsTclOpenSSLSockListenCallbackObjCmd(ClientData arg, Tcl_Interp *interp, int objc,
        Tcl_Obj *CONST objv[])
{
    Server             *thisServer = (Server *) arg;
    SockListenCallback *lcbPtr     = NULL;
    int                 port       = 0;
    char               *addr       = NULL;

    /*
     * ns_openssl_socklistencallback host port script
     * ns_openssl_socklistencallback host port script sslcontext
     */

    if (objc != 4 && objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "address port script ?sslcontext?");
        return TCL_ERROR;
    }

    if (Tcl_GetIntFromObj(interp, objv[2], &port) != TCL_OK) {
        return TCL_ERROR;
    }

    addr = Tcl_GetString(objv[1]);
    if (STREQ(addr, "*")) {
        addr = NULL;
    }

    // XXX lcbPtr = ns_malloc(sizeof(SockListenCallback) + Tcl_GetCharLength(objv[3]));
    lcbPtr = ns_malloc(sizeof(SockListenCallback));
    lcbPtr->server = thisServer->server;
#if 0
    Ns_Log(Debug, "NsTclOpenSSLSockListenCallbackCmd: objv[3] = (%s)", Tcl_GetString(objv[3]));
#endif
    // XXX (security problem?) strcpy(lcbPtr->script, Tcl_GetString(objv[3]));
    lcbPtr->script = strdup(Tcl_GetString(objv[3]));

    if (objc == 5) {
        // XXX name = (char *) Tcl_GetString(objv[5]);
        lcbPtr->sslcontext = Ns_OpenSSLServerSSLContextGet(thisServer->server, (char *) Tcl_GetString(objv[5]));
    } else {
        lcbPtr->sslcontext = NsOpenSSLContextServerDefaultGet(thisServer->server);
    }

#if 0
    Ns_Log(Debug, "NsTclOpenSSLSockListenCallbackCmd: sslcontext = (%p)", lcbPtr->sslcontext);
#endif

    if (Ns_SockListenCallback(addr, port, SSLSockListenCallbackProc, lcbPtr) != NS_OK) {
        Ns_Log(Error, "NsTclOpenSSLSockListenCallbackCmd: COULD NOT REGISTER CALLBACK");
        Tcl_SetResult(interp, "could not register callback", TCL_STATIC);
        ns_free(lcbPtr);
        return TCL_ERROR;
    }

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * EnterSock, EnterDup --
 *
 *      Append a socket handle to the tcl result and register its
 *      channel.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      Will create channel, append handle to result.
 *
 *----------------------------------------------------------------------
 */

static int
EnterSock(Tcl_Interp *interp, SOCKET sock)
{
    Tcl_Channel chan = NULL;

    chan = Tcl_MakeTcpClientChannel((ClientData) sock);
    if (chan == NULL) {
        Tcl_AppendResult(interp, "could not open socket", NULL);
        ns_sockclose(sock);
        return TCL_ERROR;
    }
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    Tcl_RegisterChannel(interp, chan);
    sprintf(interp->result, "%s", Tcl_GetChannelName(chan));

    return TCL_OK;
}

static int
EnterDup(Tcl_Interp *interp, SOCKET sock)
{
    sock = ns_sockdup(sock);
    if (sock == INVALID_SOCKET) {
        Tcl_AppendResult(interp, "could not dup socket: ",
                ns_sockstrerror(ns_sockerrno), NULL);
        return TCL_ERROR;
    }

    return EnterSock(interp, sock);
}

static int
EnterDupedSocks(Tcl_Interp *interp, SOCKET sock)
{
    if (EnterSock(interp, sock) != TCL_OK ||
            EnterDup(interp, sock) != TCL_OK) {
        return TCL_ERROR;
    }                    
    return TCL_OK;
}   


/*
 *----------------------------------------------------------------------
 *
 * SetResultToX509Name --
 *
 *      Set the Tcl interpreter's result to the string form of the
 *      specified X.509 name.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

/* XXX move to x509.c? Make part of C API? */
/* XXX can write a C / Tcl to get this and all other cert info and load into Ns_Set */
/* XXX or store in sslconn directly. Extra work might make it slower */

static void
SetResultToX509Name(Tcl_Interp *interp, X509_NAME *name)
{
    char *string = NULL;

    string = X509_NAME_oneline(name, NULL, 0);
    Tcl_SetResult(interp, string, TCL_VOLATILE);
    OPENSSL_free(string);
}


/*
 *----------------------------------------------------------------------
 *
 * SetResultToObjectName --
 *
 *      Set the Tcl interpreter's result to the string form of the
 *      specified ASN.1 object name.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

/* XXX move to x509.c? Make part of C API? */
/* XXX can write a C / Tcl to get this and all other cert info and load into Ns_Set */
/* XXX or store in sslconn directly. Extra work might make it slower */

static void
SetResultToObjectName(Tcl_Interp *interp, ASN1_OBJECT *obj)
{
    int   nid    = 0;
    char *string = NULL;

    nid = OBJ_obj2nid(obj);
    if (nid == NID_undef) {
        Tcl_SetResult(interp, "UNKNOWN", TCL_STATIC);
    } else {
        string = (char *) OBJ_nid2ln(nid);
        if (string == NULL) {
            Tcl_SetResult(interp, "ERROR", TCL_STATIC);
        } else {
            Tcl_SetResult(interp, string, TCL_VOLATILE);
        }
    }
}

/* XXX move to x509.c? Make part of C API? */
/* XXX can write a C / Tcl to get this and all other cert info and load into Ns_Set */
/* XXX or store in sslconn directly. Extra work might make it slower */


/*
 *----------------------------------------------------------------------
 *
 * ValidTime --
 *
 *      Takes an ASN1_UTCTIME value and converts it into a string of
 *      the form "Aug 28 20:00:38 2002 GMT"
 *
 * Results:
 *      Pointer to null-terminated string allocated by Tcl_Alloc.
 *
 * Side effects:
 *      None.
 *
 *---------------------------------------------------------------------- */

/* XXX export to public API? */
/* XXX will use them in a separate openssl.so library */
/* XXX move to x509.c? Make part of C API? */
/* XXX can write a C / Tcl to get this and all other cert info and load into Ns_Set */
/* XXX or store in sslconn directly. Extra work might make it slower */

static char *
ValidTime(ASN1_UTCTIME *tm)
{
    char         *result = NULL;
    BIO          *bio    = NULL;
    unsigned int  n      = 0;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;

    ASN1_UTCTIME_print(bio, tm);
    n = BIO_pending(bio);
    result = Tcl_Alloc(n + 1);
    n = BIO_read(bio, result, (signed int) n);
    result[n] = '\0';
    BIO_free(bio);
    return result;
}


/*
 *----------------------------------------------------------------------
 *
 * PEMCertificate --
 *
 *      Retrieves the certificate in PEM format
 *
 * Results:
 *      Pointer to null-terminated string that contains the PEM
 *      certificate, allocated by Tcl_Alloc.
 *
 * Side effects:
 *      None.
 *
 *---------------------------------------------------------------------- */

/* XXX move this to x509.c */
/* XXX try using dstrings for result, exporting it */
/* XXX make this part of the connection process and store string in conn struct */
/* XXX that way it can be free'd properly when conn goes away */
static char *
PEMCertificate(X509 *peercert)
{
    char         *result = NULL;
    BIO          *bio    = NULL;
    unsigned int  n      = 0;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;

    PEM_write_bio_X509(bio, peercert);

    n = BIO_pending(bio);
    result = Tcl_Alloc(n + 1);
    n = BIO_read(bio, result, (signed int) n);
    result[n] = '\0';
    BIO_free(bio);
    return result;
}


/*
 *----------------------------------------------------------------------
 *
 * CreateTclChannel --
 *
 *	Dup connection sock and wrap read and write Tcl channels
 *      around them.
 *
 * Results:
 *	Tcl result. 
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
CreateTclChannel(NsOpenSSLConn *sslconn, Tcl_Interp *interp)
{
    Tcl_Channel chan = NULL;
    Tcl_DString ds;
    /* XXX not initialized */
    char        channelName[16 + TCL_INTEGER_SPACE];

    Tcl_DStringInit(&ds);

    /* channel for reading */
    sprintf(channelName, "openssl%d", sslconn->socket);

    /*
     * Although it's the read channel we make it writable
     * so we can do an ns_openssl_sockcheck on it to see if
     * it's still alive.
     */

    chan = Tcl_CreateChannel(
            &opensslChannelType,
            channelName,
            (ClientData) sslconn,
            (TCL_READABLE | TCL_WRITABLE)
            );

    if (chan == (Tcl_Channel) NULL) {
        Ns_Log(Error, "%s: %s: could not create new Tcl channel",
                MODULE, sslconn->server);
        Tcl_AppendResult (interp, "could not create new Tcl channel", NULL);
        return TCL_ERROR;
    }

    Tcl_SetChannelBufferSize(chan, BUFSIZ);
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    Tcl_RegisterChannel(interp, chan);
    Tcl_DStringAppendElement(&ds, Tcl_GetChannelName (chan));

    /* channel for writing */
    sslconn->wsock = ns_sockdup(sslconn->socket);

    sprintf(channelName, "openssl%d", sslconn->wsock);

    chan = 
        Tcl_CreateChannel(
                &opensslChannelType, 
                channelName, 
                (ClientData) sslconn, 
                TCL_WRITABLE
                );

    if (chan == (Tcl_Channel) NULL) {
        Ns_Log(Error, "%s: %s: could not create new Tcl channel",
                MODULE, sslconn->server);
        Tcl_AppendResult(interp, "could not create new Tcl channel", NULL);
        return TCL_ERROR;
    }

    /* 
     * Although we've wrapped two channels around the conn, we only increment
     * the conn's reference count once because refcnt is already set to 1 from
     * when the SSL conn was created.
     */

    sslconn->refcnt++;

    Tcl_SetChannelBufferSize(chan, BUFSIZ);
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    Tcl_RegisterChannel(interp, chan);
    Tcl_DStringAppendElement (&ds, Tcl_GetChannelName (chan));
    Tcl_DStringResult(interp, &ds);

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * ChanOutputProc --
 *
 *	Callback activated by Tcl puts and write commands. Sends data
 *      to the connected system.
 *
 * Results:
 *	Tcl result. 
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */

static int
ChanOutputProc(ClientData arg, char *buf, int toWrite,
		int *errorCodePtr)
{
    NsOpenSSLConn *sslconn = (NsOpenSSLConn *) arg;
    int            rc      = 0;

    rc = NsOpenSSLConnSend(sslconn->bio, (void *) buf, toWrite);

#if 0
    Ns_Log(Debug, "ChanOutputProc: puts (%d) bytes -- supposed to puts (%d) bytes",
            rc, toWrite);
#endif

    return rc;
}


/*
 *----------------------------------------------------------------------
 *
 * ChanInputProc --
 *
 *	Callback activated by Tcl gets and read on the Tcl channel. Reads
 *      data from the connected system.
 *
 * Results:
 *	Number of bytes read.
 *
 * Side effects:
 *	Places read data into buf, may set errorCodePtr, and adjusts
 *      connection state's read buffer pointer.
 *
 *----------------------------------------------------------------------
 */

static int
ChanInputProc(ClientData arg, char *buf, int bufSize,
	       int *errorCodePtr)
{
    NsOpenSSLConn *sslconn = (NsOpenSSLConn *) arg;
    int            rc      = 0;

    rc = NsOpenSSLConnRecv(sslconn->bio, (void *) buf, bufSize);

#if 0
    Ns_Log(Debug, "ChanInputProc: gets got (%d) bytes; sslconn = (%p)",
            rc, sslconn);
#endif

    return rc;
}


/*
 *----------------------------------------------------------------------
 *
 * ChanCloseProc --
 *
 *	Close down the Tcl channels and clean up the connection state
 *      data.
 *
 * Results:
 *	Tcl result. 
 *
 * Side effects:
 *	Will call functions to shutdown the SSL connection and free all
 *      data associated with the connection.
 *
 *      Note that this proc is called twice, once for the read channel
 *      and once for the write channel, so we need to check and see if
 *      conn has already been freed.
 *
 *----------------------------------------------------------------------
 */

static int
ChanCloseProc(ClientData arg, Tcl_Interp *interp)
{
    NsOpenSSLConn *sslconn = (NsOpenSSLConn *) arg;

    Ns_Log(Debug, "ChanCloseProc: enter: sslconn = (%p)", sslconn);
    //Ns_Log(Debug, "--->>> BEFORE ConnDestroy: ChanCloseProc");
    NsOpenSSLConnDestroy(sslconn);

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * ChanFlushProc --
 *
 *	Flush the date in the connection buffers.
 *
 * Results:
 *	TCL_OK.
 *
 * Side effects:
 *	Will open a connection and register two Tcl channels.
 *
 *----------------------------------------------------------------------
 */

static int
ChanFlushProc (ClientData arg)
{
    NsOpenSSLConn *sslconn = (NsOpenSSLConn *) arg;

    NsOpenSSLConnFlush(sslconn);

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * ChanGetHandleProc --
 *
 *	Return the read or write socket.
 *
 * Results:
 *	TCL_OK
 *
 * Side effects:
 *	
 *
 *----------------------------------------------------------------------
 */

static int
ChanGetHandleProc(ClientData arg, int direction, ClientData *handlePtr)
{
    NsOpenSSLConn *sslconn = (NsOpenSSLConn *) arg;

    if (direction == TCL_READABLE) {
        *handlePtr = (ClientData) sslconn->socket;
    } else {
        *handlePtr = (ClientData) sslconn->wsock;
    }

    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * ChanWatchProc --
 *
 *	Callback proc used by the Tcl channels. Doesn't do anything for
 *      us at the moment, but it is still required to be defined.
 *      Not having it causes a segfault when Tcl tries to
 *      work with it. Go read the Tcl_CreateChannel man page for Tcl 8.3+.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	
 *
 *----------------------------------------------------------------------
 */

static void
ChanWatchProc(ClientData arg, int mask)
{
#if 0				/* XXX ChanWatchProc: arg isn't used here yet */
    NsOpenSSLConn *sslconn = (NsOpenSSLConn *) arg;
#endif

    return;
}


/*
 *----------------------------------------------------------------------
 *
 * SSLSockListenCallbackProc --
 *
 *      This is the C wrapper callback that is registered from
 *      ns_openssl_socklistencallback.
 *
 * Results:
 *      NS_TRUE or NS_FALSE on error
 *
 * Side effects:
 *      Will run Tcl script.
 *
 *----------------------------------------------------------------------
 */

static int
SSLSockListenCallbackProc(SOCKET sock, void *arg, int why)
{
    SockListenCallback  *lcbPtr    = arg;
    NsOpenSSLConn       *sslconn   = NULL;
    Tcl_Interp          *interp    = NULL;
    /* XXX not initialized */
    Tcl_DString          script;
    Tcl_Obj             *listPtr   = NULL;
    Tcl_Obj            **objv      = NULL;
    int                  status    = TCL_ERROR;
    int                  objc      = 0;

    interp = Ns_TclAllocateInterp(lcbPtr->server);

    sslconn = Ns_OpenSSLSockAccept(sock, lcbPtr->sslcontext);
    if (sslconn == NULL) {
        Tcl_AppendResult(interp, "SSL accept failed \"", NULL);
        return TCL_ERROR;
    }

    status = CreateTclChannel(sslconn, interp);

    if (status == TCL_OK) {
        listPtr = Tcl_GetObjResult(interp);
        if (Tcl_ListObjGetElements(interp, listPtr, &objc, &objv) == TCL_OK && objc == 2) {
            Tcl_DStringInit(&script);
            Tcl_DStringAppend(&script, lcbPtr->script, -1);
            Tcl_DStringAppendElement(&script, Tcl_GetString(objv[0]));
            Tcl_DStringAppendElement(&script, Tcl_GetString(objv[1]));
            /* XXX shouldn't we use TCL_EVAL_DIRECT or TCL_EVAL_GLOBAL as flag? */
            status = Tcl_EvalEx(interp, script.string, script.length, 0);
            Tcl_DStringFree(&script);
        }
    }

    if (status != TCL_OK) {
        Ns_TclLogError(interp);
    }

    Ns_TclDeAllocateInterp(interp);

    return NS_TRUE;
}


/*
 *----------------------------------------------------------------------
 *
 * AppendReadyFiles --
 *
 *      Find files in an fd_set that are selected and append them to
 *      the tcl result, and also an optional passed-in dstring.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Ready files will be appended to pds if not null, and also
 *      interp->result.
 *
 *----------------------------------------------------------------------
 */

static void
AppendReadyFiles (Tcl_Interp * interp, fd_set * setPtr, int write,
        char *flist, Tcl_DString * dsPtr)
{
    int           fargc  = 0;
    char        **fargv  = NULL;
    SOCKET        socket = INVALID_SOCKET;
    Tcl_DString   ds;

    Tcl_DStringInit(&ds);

    if (dsPtr == NULL) {
        dsPtr = &ds;
    }
    Tcl_SplitList(interp, flist, &fargc, &fargv);
    while (fargc--) {
        Ns_TclGetOpenFd(interp, fargv[fargc], write, (int *) &socket);
        if (FD_ISSET(socket, setPtr)) {
            Tcl_DStringAppendElement(dsPtr, fargv[fargc]);
        }
    }

    /*
     * Append the ready files to the tcl interp.
     */

    Tcl_AppendElement(interp, dsPtr->string);
    ckfree((char *) fargv);
    Tcl_DStringFree(&ds);
}


/*
 *----------------------------------------------------------------------
 *
 * GetSet --
 *
 *      Take a Tcl list of files and set bits for each in the list in
 *      an fd_set.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      Will set bits in fd_set. ppset may be NULL on error, or
 *      a valid fd_set on success. Max fd will be returned in *maxPtr.
 *
 *----------------------------------------------------------------------
 */

static int
GetSet(Tcl_Interp * interp, char *flist, int write, fd_set ** setPtrPtr,
        fd_set * setPtr, SOCKET * maxPtr)
{
    SOCKET   socket = INVALID_SOCKET;
    int      fargc  = 0;
    char   **fargv  = NULL;
    int      status = TCL_ERROR;

    if (Tcl_SplitList(interp, flist, &fargc, &fargv) != TCL_OK) {
        return TCL_ERROR;
    }
    if (fargc == 0) {

        /*
         * Tcl_SplitList failed, so abort.
         */

        ckfree((char *) fargv);
        *setPtrPtr = NULL;
        return TCL_OK;
    } else {
        *setPtrPtr = setPtr;
    }

    FD_ZERO(setPtr);
    status = TCL_OK;

    /*
     * Loop over each file, try to get its FD, and set the bit in
     * the fd_set.
     */

    while (fargc--) {
        if (Ns_TclGetOpenFd(interp, fargv[fargc], write,
                    (int *) &socket) != TCL_OK) {
            status = TCL_ERROR;
            break;
        }
        if (socket > *maxPtr) {
            *maxPtr = socket;
        }
        FD_SET(socket, setPtr);
    }
    ckfree((char *) fargv);

    return status;
}


/*
 *----------------------------------------------------------------------
 *
 * SSLSockCallbackProc --
 *
 *     Callback that is registered from ns_sockcallback.
 *
 * Results:
 *     NS_TRUE or NS_FALSE on error
 *
 * Side effects:
 *     Will run Tcl script.
 *
 *----------------------------------------------------------------------
 */

static int
SSLSockCallbackProc(SOCKET sock, void *arg, int why)
{
    SockCallback *cbPtr   = arg;
    Tcl_Interp   *interp  = NULL;
    /* XXX not initialized */
    Tcl_DString   script;
    char         *w       = NULL;
    int           status  = TCL_ERROR;

    if (why != NS_SOCK_EXIT || (cbPtr->when & NS_SOCK_EXIT)) {

	interp = Ns_TclAllocateInterp(cbPtr->server);
	status = EnterDup(interp, sock);

	if (status == TCL_OK) {

	    Tcl_DStringInit (&script);
	    Tcl_DStringAppend (&script, cbPtr->script, -1);
	    Tcl_DStringAppendElement (&script, interp->result);

	    if (why == NS_SOCK_READ) {
		w = "r";
	    } else if (why == NS_SOCK_WRITE) {
		w = "w";
	    } else if (why == NS_SOCK_EXCEPTION) {
		w = "e";
	    } else {
		w = "x";
	    }

	    Tcl_DStringAppendElement(&script, w);
            status = Tcl_EvalEx(interp, script.string, script.length, 0);
	    Tcl_DStringFree(&script);

	}

	if (status != TCL_OK) {
	    Ns_TclLogError(interp);
	} else if (!STREQ(interp->result, "1")) {
	    why = NS_SOCK_EXIT;
	}

	Ns_TclDeAllocateInterp(interp);

    }

    if (why == NS_SOCK_EXIT) {
	ns_sockclose(sock);
	ns_free(cbPtr);
	return NS_FALSE;
    }

    return NS_TRUE;
}
