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
 * x509.c --
 *
 *     Implements functions that work with X509 certificates.
 */

static const char *RCSID =
    "@(#) $Header$, compiled: "
    __DATE__ " " __TIME__;

#include "nsopenssl.h"



/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLX509CertGetFromSSL --
 *
 *     Return the X509 certificate for the given SSL instance.
 *
 * Results:
 *      A pointer to an X509 certificate or NULL if there is no certificate.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

extern X509 *
Ns_OpenSSLX509CertGetFromSSL(SSL *ssl)
{
    return SSL_get_peer_certificate(ssl);
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLX509CertPEM --
 *
 *     Return the PEM-formatted certificate. 
 *
 * Results:
 *      A pointer to the PEM-formatted certificate.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

extern char *
Ns_OpenSSLX509CertPEM(X509 *certificate)
{
    char         *result = NULL;
    BIO          *bio    = NULL;
    unsigned int  n      = 0;

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, certificate);
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
 * Ns_OpenSSLX509CertVerify --
 *
 *     Determine if the certificate associated with the given SSL instance is
 *     valid. You only call this function if you already KNOW that a
 *     certificate exists.  From the SSL_get_verify_result() man page: If no
 *     peer certificate was presented, the returned result code is X509_V_OK.
 *     This is because no verification error occurred, it does however not
 *     indicate success.  SSL_get_verify_result() is only useful in connection
 *     with SSL_get_peer_certificate(3).
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
Ns_OpenSSLX509CertVerify(SSL *ssl)
{
    switch(SSL_get_verify_result(ssl)) {
        case X509_V_OK:
            return NS_TRUE;
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            Ns_Log(Warning, "X509 certificate: unable to get issuer certificate");
            break;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            Ns_Log(Warning, "X509 certificate: unable to get CRL");
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            Ns_Log(Warning, "X509 certificate: unable to decrypt certificate signature");
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
            Ns_Log(Warning, "X509 certificate: unable to decrypt CRL signature");
            break;
        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
            Ns_Log(Warning, "X509 certificate: unable to decode issuer public key");
            break;
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            Ns_Log(Warning, "X509 certificate: certificate signature failure");
            break;
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            Ns_Log(Warning, "X509 certificate: CRL signature failure");
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
            Ns_Log(Warning, "X509 certificate: certificate not yet valid");
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
            Ns_Log(Warning, "X509 certificate: certificate has expired");
            break;
        case X509_V_ERR_CRL_NOT_YET_VALID:
            Ns_Log(Warning, "X509 certificate: CRL not yet valid");
            break;
        case X509_V_ERR_CRL_HAS_EXPIRED:
            Ns_Log(Warning, "X509 certificate: CRL has expired");
            break;
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            Ns_Log(Warning, "X509 certificate: error in certificate 'not before' field");
            break;
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            Ns_Log(Warning, "X509 certificate: error in certificate 'not after' field");
            break;
        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
            Ns_Log(Warning, "X509 certificate: error in CRL 'last update' field");
            break;
        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            Ns_Log(Warning, "X509 certificate: error in CRL 'next update' field");
            break;
        case X509_V_ERR_OUT_OF_MEM:
            Ns_Log(Warning, "X509 certificate: out of memory");
            break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            Ns_Log(Warning, "X509 certificate: depth zero self-signed certificate");
            break;
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            Ns_Log(Warning, "X509 certificate: self-signed certificate in chain");
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            Ns_Log(Warning, "X509 certificate: unable to get issuer certificate locally");
            break;
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            Ns_Log(Warning, "X509 certificate: unable to verify leaf signature");
            break;
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            Ns_Log(Warning, "X509 certificate: certificate chain too long");
            break;
        case X509_V_ERR_CERT_REVOKED:
            Ns_Log(Warning, "X509 certificate: certificate revoked");
            break;
        case X509_V_ERR_APPLICATION_VERIFICATION:
            Ns_Log(Warning, "X509 certificate: application verification");
            break;
        default:
            Ns_Log(Error, "X509 certificate: unknown result from SSL certificate verification result");
            break;
    }

    return NS_FALSE;
}


#if 0

/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLX509CertSubject --
 *
 *     Return the subject field of the given certificate.
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
Ns_OpenSSLX509CertSubject(SSL *ssl)
{
    if (peercert != NULL) {
        SetResultToX509Name(interp, X509_get_subject_name(peercert));
    }

    return NS_TRUE;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLX509CertNotBefore --
 *
 *     Return the 'not before' date of the certificate.
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
Ns_OpenSSLX509CertNotBefore(SSL *ssl)
{
    return NS_TRUE;
}



/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLX509CertNotAfter --
 *
 *     Return the 'not after' date of the certificate.
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
Ns_OpenSSLX509CertNotAfter(SSL *ssl)
{
    return NS_TRUE;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLX509CertSerial --
 *
 *     Return the serial number of the given certificate.
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
Ns_OpenSSLX509CertSerial(SSL *ssl)
{
    return NS_TRUE;
}


/*
 *----------------------------------------------------------------------
 *
 * Ns_OpenSSLX509CertVersion --
 *
 *     Return the version of the given certificate.
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
Ns_OpenSSLX509CertVersion(SSL *ssl)
{
    return NS_TRUE;
}
#endif



