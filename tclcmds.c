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

/*
 * Provides a Tcl interface to nsopenssl
 */

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
 * Local Functions
 */

static char *ValidTime (ASN1_UTCTIME * tm);

static char *SerialNumber (X509 * clientcert);

static char *PEMCertificate (X509 * clientcert);

/*
 *----------------------------------------------------------------------
 *
 * SSLCmd --
 *
 *      Returns information about nsopenssl, client certificates.
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
SSLCmd (ClientData dummy, Tcl_Interp * interp, int argc, char **argv)
{
    Ns_Conn *conn;
    SSLConnection *sslconn;
    char *result;
    int status;
    Ns_DString ds;
    int nid;

    if (argc < 2) {
	Tcl_AppendResult (interp, "wrong # args:  should be \"",
			  argv[0], " command \"", NULL);
	return TCL_ERROR;
    }

    /* The SSL connection structure is buried in the conn connection structure */

    conn = Ns_TclGetConn (NULL);
    sslconn = NsSSLGetConn (conn);

    Ns_DStringInit (&ds);

    status = TCL_OK;

    if (STREQ (argv[1], "info")) {
	Ns_DStringPrintf (&ds, "{%s} ", SSL_LIBRARY_NAME);
	Ns_DStringPrintf (&ds, "{%s} ", SSL_LIBRARY_VERSION);
	Ns_DStringPrintf (&ds, "{%s} ", SSL_CRYPTO_LIBRARY_NAME);
	Ns_DStringPrintf (&ds, "{%s} ", SSL_CRYPTO_LIBRARY_VERSION);

    } else if (STREQ (argv[1], "clientcert")) {

	if (STREQ (argv[2], "version")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " version\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		Ns_DStringPrintf (&ds, "%lu ",
				  X509_get_version (sslconn->clientcert) + 1);
	    } else {
		Ns_DStringPrintf (&ds, "%lu ", 0);
	    }

	} else if (STREQ (argv[2], "serial")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " serial\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		Ns_DStringPrintf (&ds, "%s ",
				  SerialNumber (sslconn->clientcert));
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }

	} else if (STREQ (argv[2], "subject")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " subject\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		result = X509_NAME_oneline (X509_get_subject_name
					    (sslconn->clientcert), NULL, 0);
		Ns_DStringPrintf (&ds, "%s ", result);
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }

	} else if (STREQ (argv[2], "issuer")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " issuer\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		result =
		    X509_NAME_oneline (X509_get_issuer_name
				       (sslconn->clientcert), NULL, 0);
		Ns_DStringPrintf (&ds, "%s ", result);
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }

	} else if (STREQ (argv[2], "notbefore")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " notbefore\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		result = ValidTime (X509_get_notBefore (sslconn->clientcert));
		Ns_DStringPrintf (&ds, "%s ", result);
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }

	} else if (STREQ (argv[2], "notafter")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " notafter\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		result = ValidTime (X509_get_notAfter (sslconn->clientcert));
		Ns_DStringPrintf (&ds, "%s ", result);
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }

	} else if (STREQ (argv[2], "signature_algorithm")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " signature_algorithm\"",
				  NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		nid =
		    OBJ_obj2nid (sslconn->clientcert->cert_info->signature->
				 algorithm);
		if (nid == NID_undef) {
		    Ns_DStringPrintf (&ds, "UNKNOWN ");
		} else {
		    Ns_DStringPrintf (&ds, "%s ", OBJ_nid2ln (nid));
		}
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }

	} else if (STREQ (argv[2], "key_algorithm")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " key_algorithm\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		nid =
		    OBJ_obj2nid (sslconn->clientcert->cert_info->key->algor->
				 algorithm);
		if (nid == NID_undef) {
		    Ns_DStringPrintf (&ds, "UNKNOWN ");
		} else {
		    Ns_DStringPrintf (&ds, "%s ", OBJ_nid2ln (nid));
		}
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }
	} else if (STREQ (argv[2], "pem")) {
	    if (argc != 3) {
		Tcl_AppendResult (interp, "wrong # args:  should be \"",
				  argv[0], argv[1], " pem\"", NULL);
		status = TCL_ERROR;
	    } else if (sslconn->clientcert != NULL) {
		Ns_DStringPrintf (&ds, "%s ",
				  PEMCertificate (sslconn->clientcert));
	    } else {
		Ns_DStringPrintf (&ds, "%s ", "");
	    }
	}

    } else {
	Tcl_AppendResult (interp, "unknown command \"",
			  argv[1], "\": should be info, clientcert", NULL);
	status = TCL_ERROR;
    }

    if (status != TCL_ERROR)
	Tcl_SetResult (interp, ds.string, TCL_VOLATILE);

    Ns_DStringFree (&ds);

    return status;
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
 *      Pointer to null-terminated string.
 *
 * Side effects:
 *      None.
 *
 *---------------------------------------------------------------------- */

static char *
ValidTime (ASN1_UTCTIME * tm)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new (BIO_s_mem ())) == NULL)
	return NULL;

    ASN1_UTCTIME_print (bio, tm);
    n = BIO_pending (bio);
    result = ns_calloc (1, n + 1);
    n = BIO_read (bio, result, n);
    result[n] = '\0';
    BIO_free (bio);

    return result;
}

/*
 *----------------------------------------------------------------------
 *
 * SerialNumber --
 *
 *      Retrieves the certificate's serial number
 *
 * Results:
 *      Pointer to null-terminated string.
 *
 * Side effects:
 *      None.
 *
 *---------------------------------------------------------------------- */

static char *
SerialNumber (X509 * clientcert)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new (BIO_s_mem ())) == NULL)
	return NULL;

    i2a_ASN1_INTEGER (bio, X509_get_serialNumber (clientcert));

    n = BIO_pending (bio);
    result = ns_calloc (1, n + 1);
    n = BIO_read (bio, result, n);
    result[n] = '\0';
    BIO_free (bio);

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
 *      certificate.
 *
 * Side effects:
 *      None.
 *
 *---------------------------------------------------------------------- */

static char *
PEMCertificate (X509 * clientcert)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new (BIO_s_mem ())) == NULL)
	return NULL;

    PEM_write_bio_X509 (bio, clientcert);

    n = BIO_pending (bio);
    result = ns_calloc (1, n + 1);
    n = BIO_read (bio, result, n);
    result[n] = '\0';
    BIO_free (bio);

    return result;
}
