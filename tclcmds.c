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

/*
 * Local functions defined in this file.
 */

static void SetResultToX509Name(Tcl_Interp *interp, X509_NAME *name);
static void SetResultToObjectName(Tcl_Interp *interp, ASN1_OBJECT *obj);
static char *ValidTime(ASN1_UTCTIME *tm);
static char *PEMCertificate(X509 *peercert);
static int SSLSockSetBlocking(char *value, Tcl_Interp *interp, int argc,
			       char **argv);

typedef struct TclCmd {
    char         *name;
    Tcl_CmdProc  *proc;
    ClientData   clientData;
} TclCmd;

static Ns_TclInterpInitProc AddCmds;

/* XXX can i preload the iso8859-1 char set before any ns_openssl commands are called? */
/* XXX if I don't, there is a slight delay while the server loads it on first conn */

static TclCmd nsopensslCmds[] = {
#if 0
    {"ns_openssl_conn", NsTclOpenSSLConnCmd, (ClientData) NULL},
#endif
    {"ns_openssl", NsTclOpenSSLCmd, (ClientData) NULL},
    {NULL, NULL, NULL}
};


/*
 *----------------------------------------------------------------------
 *
 * NsOpenSSLTclInit --
 *
 *      Initialize Tcl API for a virtual server
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
    Ns_TclInitInterps(server, AddCmds, NULL);
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
    TclCmd *cmd = &nsopensslCmds;

    while (cmd->name != NULL) {
        Tcl_CreateCommand(interp, cmd->name, cmd->proc, cmd->clientData, NULL);
        ++cmd;
    }
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLConnCmd --
 *
 *      Counterpart to the ns_conn command but reports information specific to
 *      SSL.
 *
 * Results:
 *      Tcl string result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

#if 0

int
NsTclOpenSSLConnCmd(ClientData arg, Tcl_Interp *interp, int argc, char **argv)
{
    Ns_OpenSSLConn *sslconn;

    if (argc < 2) {
        Tcl_AppendResult(interp, "wrong # args:  should be \"",
        argv[0], " command \"", NULL);
        return TCL_ERROR;
    }

    /*
     * Get the connection information. We can't use Ns_Conn functions here
     * because we may not be going through the core driver for this connection.
     * We have to rely on the connection information stored in the SSL
     * connection structure.
     */

    sslconn = NsOpenSSLGetConn(interp);
    if (sslconn == NULL) {
        Tcl_AppendResult(interp, "no SSL connection", NULL);
        return TCL_ERROR;
    }

    if (STREQ(argv[1], "protocol")) {
        Tcl_AppendResult(interp, "tclapi: you asked for the protocol", NULL);
        return TCL_OK;
    } else if (STREQ(argv[1], "cipher")) {
        Tcl_AppendResult(interp, "tclapi: you asked for the cipher", NULL);
        return TCL_OK;
    } else if (STREQ(argv[1], "strength")) {
        Tcl_AppendResult(interp, "tclapi: you asked for the strength", NULL);
        return TCL_OK;
    } else if (STREQ(argv[1], "peercert")) {
        Tcl_AppendResult(interp, "tclapi: you asked for the peercert", NULL);
        return TCL_OK;
    } else {
        Tcl_AppendResult(interp, "tclapi: unknown command", NULL);
        return TCL_ERROR;
    }
}
#endif


/*
 *----------------------------------------------------------------------
 *
 * NsTclOpenSSLCmd --
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
NsTclOpenSSLCmd(ClientData arg, Tcl_Interp *interp, int argc, char **argv)
{
    Ns_OpenSSLConn *sslconn = NULL;
    X509 *peercert          = NULL;
    SSL_CIPHER *cipher      = NULL;
    Ns_Conn *conn           = NULL;
    char *string            = NULL;
    char *name              = NULL;
    int integer             = 0;
    int status              = TCL_OK;

    if (argc < 2) {
        Tcl_AppendResult(interp, "wrong # args:  should be \"",
            argv[0], " command \"", NULL);
        return TCL_ERROR;
    }

    /*
     * ns_openssl info
     */

    if (STREQ(argv[1], "info")) {
        Tcl_AppendElement(interp, OPENSSL_VERSION_TEXT);
        Tcl_AppendElement(interp, OPENSSL_VERSION_TEXT);
        Tcl_AppendElement(interp, OPENSSL_VERSION_TEXT);
        Tcl_AppendElement(interp, OPENSSL_VERSION_TEXT);
        return TCL_OK;
    }

    /* 
     * AOLserver stashes a pointer to the conn in the interp. We then use that
     * to get a pointer to our SSL conn through the core driver's context.
     */

    /* XXX create an Ns_OpenSSLConnIsConnected call */
    conn = Ns_TclGetConn(interp);
    if (conn != NULL) {
        name = Ns_ConnDriverName(conn);
        if (name != NULL && STREQ(name, MODULE)) {
            sslconn = (Ns_OpenSSLConn *) Ns_ConnDriverContext(conn);
        }
    }
    if (sslconn == NULL) {
        Tcl_AppendResult(interp, "no SSL connection", NULL);
        return TCL_ERROR;
    }

    /*
     * Implement:
     # ns_openssl module name
     * ns_openssl module port
     */

    if (STREQ(argv[1], "module")) {
        if (argc != 3) {
            Tcl_AppendResult(interp, "wrong # args:  should be \"", argv[0],
            argv[1], " name\"", NULL);
            status = TCL_ERROR;
        } else if (STREQ(argv[2], "name")) {
            Tcl_SetResult(interp, MODULE, TCL_VOLATILE);
        } else if (STREQ(argv[2], "port")) {
            sprintf(interp->result, "%d", sslconn->ssldriver->port);
        }

    /*
     * Implement:
     * ns_openssl protocol
     */

    } else if (STREQ(argv[1], "protocol")) {
        Ns_Log(Debug, "*** sslconn->ssl = (%d)", &sslconn->ssl->session->ssl_version);
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

    /*
     * Implement:
     * ns_openssl port
     * ns_openssl peerport
     */

    } else if ((STREQ(argv[1], "port")) || (STREQ(argv[1], "peerport"))) {
        sprintf(interp->result, "%d", sslconn->peerport);

    /*
     * Implement:
     * ns_openssl cipher name
     * ns_openssl cipher strength
     */

    } else if (STREQ(argv[1], "cipher")) {
        cipher = SSL_get_current_cipher(sslconn->ssl);
        if (STREQ(argv[2], "name")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " name\"", NULL);
                status = TCL_ERROR;
            } else {
                string =
                    (sslconn->ssl != NULL ? (char *) SSL_CIPHER_get_name(cipher) : NULL);
                Tcl_SetResult(interp, string, TCL_VOLATILE);
            }
        } else if (STREQ(argv[2], "strength")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " strength\"", NULL);
                status = TCL_ERROR;
            } else {
                integer = SSL_CIPHER_get_bits(cipher, &integer);
                sprintf(interp->result, "%d", integer);
            }
        }

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
     
    } else if (STREQ(argv[1], "clientcert")) {
        peercert = (sslconn == NULL) ? NULL : sslconn->peercert;
        if (STREQ(argv[2], "exists")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " exists\"", NULL);
                status = TCL_ERROR;
            } else {
                Tcl_SetResult(interp, peercert == NULL ? "0" : "1",
                        TCL_STATIC);
            }
        } else if (STREQ(argv[2], "version")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " version\"", NULL);
                status = TCL_ERROR;
            } else {
                sprintf(interp->result, "%lu",
                        peercert == NULL
                        ? 0 : X509_get_version(peercert) + 1);
            }

        } else if (STREQ(argv[2], "serial")) {

            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " serial\"", NULL);
                status = TCL_ERROR;
            } else {
                sprintf(interp->result, "%ld",
                        peercert == NULL
                        ? 0
                        :
                        ASN1_INTEGER_get(X509_get_serialNumber(peercert)));
            }
        } else if (STREQ(argv[2], "subject")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " subject\"", NULL);
                status = TCL_ERROR;

            } else if (peercert != NULL) {
                SetResultToX509Name(interp,
                        X509_get_subject_name(peercert));
            }
        } else if (STREQ(argv[2], "issuer")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " issuer\"", NULL);
                status = TCL_ERROR;

            } else if (peercert != NULL) {
                SetResultToX509Name(interp, X509_get_issuer_name(peercert));
            }
        } else if (STREQ(argv[2], "notbefore")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " notbefore\"", NULL);
                status = TCL_ERROR;
            } else if (peercert != NULL) {
                string = ValidTime(X509_get_notBefore(peercert));
                if (string == NULL) {
                    Tcl_SetResult(interp, "error getting notbefore",
                            TCL_STATIC);
                    status = TCL_ERROR;
                } else {
                    Tcl_SetResult(interp, string, TCL_DYNAMIC);
                }
            }
        } else if (STREQ(argv[2], "notafter")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " notafter\"", NULL);
                status = TCL_ERROR;
            } else if (peercert != NULL) {
                string = ValidTime(X509_get_notAfter(peercert));
                if (string == NULL) {
                    Tcl_SetResult(interp, "error getting notafter",
                            TCL_STATIC);
                    status = TCL_ERROR;
                } else {
                    Tcl_SetResult(interp, string, TCL_DYNAMIC);
                }
            }
        } else if (STREQ(argv[2], "signature_algorithm")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " signature_algorithm\"",
                NULL);
                status = TCL_ERROR;
            } else if (peercert != NULL) {
                SetResultToObjectName(interp,
                        peercert->cert_info->signature->
                        algorithm);
            }
        } else if (STREQ(argv[2], "key_algorithm")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " key_algorithm\"", NULL);
                status = TCL_ERROR;
            } else if (peercert != NULL) {
                SetResultToObjectName(interp,
                        peercert->cert_info->key->algor->
                        algorithm);
            }
        } else if (STREQ(argv[2], "pem")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " pem\"", NULL);
                status = TCL_ERROR;
            } else if (peercert != NULL) {
                string = PEMCertificate(peercert);
                if (string == NULL) {
                    Tcl_SetResult(interp, "error getting pem", TCL_STATIC);
                    status = TCL_ERROR;
                } else {
                    Tcl_SetResult(interp, string, TCL_DYNAMIC);
                }
            }
        } else if (STREQ(argv[2], "valid")) {
            if (argc != 3) {
                Tcl_AppendResult(interp, "wrong # args:  should be \"",
                argv[0], argv[1], " valid\"", NULL);
                status = TCL_ERROR;
            } else {
                sprintf(interp->result, "%d",
                        peercert != NULL
                        && SSL_get_verify_result(sslconn->ssl) == X509_V_OK);
            }
        } else {
            Tcl_AppendResult(interp, "unknown command \"", argv[2],
            "\": should be one of: exists version serial subject issuer notbefore notafter signature_algorithm key_algorithm pem valid",
            NULL);
            status = TCL_ERROR;
        }
    } else {
        Tcl_AppendResult(interp, "unknown command \"", argv[1],
        "\": should be one of: info clientcert", NULL);
        status = TCL_ERROR;
    }
    return status;
}


/*
 *----------------------------------------------------------------------
 *
 * NsTclSSLSockCheckCmd --
 *
 *      Implements ns_openssl_sockcheck, which checks to see if a socket is
 *      still connected (useful for non-blocking connections)..
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int
NsTclSSLSockCheckCmd(ClientData arg, Tcl_Interp *interp, int argc,
		      char **argv)
{
    SOCKET sock;

    if (argc != 2) {
        Tcl_AppendResult(interp, "wrong # of args: should be \"",
        argv[0], " sockId\"", NULL);
        return TCL_ERROR;
    }
    if (Ns_TclGetOpenFd(interp, argv[1], 1, (int *) &sock) != TCL_OK) {
        return TCL_ERROR;
    }
    Ns_Log(Debug, "#### SOCKET sock = %d", sock);
    if (send(sock, NULL, 0, 0) != 0) {
        interp->result = "0";
    } else {
        interp->result = "1";
    }
    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SockSetBlocking --
 *
 *      Set a socket blocking.
 *
 * Results:
 *      Tcl result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
SSLSockSetBlocking(char *value, Tcl_Interp *interp, int argc, char **argv)
{
    Tcl_Channel chan;

    if (argc != 2) {
        Tcl_AppendResult(interp, "wrong # args: should be \"",
        argv[0], " sockId\"", NULL);
        return TCL_ERROR;
    }
    chan = Tcl_GetChannel(interp, argv[1], NULL);
    if (chan == NULL) {
        return TCL_ERROR;
    }
    return Tcl_SetChannelOption(interp, chan, "-blocking", value);
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

static void
SetResultToX509Name(Tcl_Interp *interp, X509_NAME *name)
{
    char *string;

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

static void
SetResultToObjectName(Tcl_Interp *interp, ASN1_OBJECT *obj)
{
    int nid;
    char *string;

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

/* XXX change these static funcs to OpenSSL prefix and export */
/* XXX will use them in a separate openssl.so library */

static char *
ValidTime(ASN1_UTCTIME *tm)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;

    ASN1_UTCTIME_print(bio, tm);
    n = BIO_pending(bio);
    result = Tcl_Alloc(n + 1);
    n = BIO_read(bio, result, n);
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

static char *
PEMCertificate(X509 *peercert)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;

    PEM_write_bio_X509(bio, peercert);

    n = BIO_pending(bio);
    result = Tcl_Alloc(n + 1);
    n = BIO_read(bio, result, n);
    result[n] = '\0';
    BIO_free(bio);
    return result;
}

