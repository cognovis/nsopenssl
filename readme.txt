
$Header$


Intro
-----

This is an experimental version of the SSL module for AOLServer 3.0b3.

PLEASE NOTE THAT THIS SOFTWARE IS STILL PRE-ALPHA QUALITY AND SHOULD NOT
BE USED IN A PRODUCTION ENVIRONMENT.


Feature Highlights
------------------

 * Open Source software (AOLServer Public License)
 * Useable for both commercial and non-commercial use
 * 128-bit strong cryptography world-wide
 * Support for SSLv2, SSLv3 and TLSv1 protocols
 * Support for both RSA and Diffie-Hellman ciphers
 * Clean reviewable ANSI C source code
 * Support for the OpenSSL+RSAref US-situation


Compiling the code
------------------

To compile this code, you will have to move the openssl directory into
the AOLServer 3.0 source tree. You will also need to have OpenSSL 0.9.4
installed in it's default place (/usr/local/ssl/{bin,include}.

To compile, simply do a:

 $ cd PATHTOAOLSERVERSOURCES/nsopenssl/
 $ make
 $ make install

A prebuild binary for RedHat 6.0 is in the distribution archive, so you
can skip the 'make' step if you want.

To test the server, do a:

 $ mkdir ../root/servers/server1/nsopenssl
 $ cp snakeoil/*.pem ../root/servers/server1/nsopenss
 $ cd ../root/
 $ bin/nsd -f ../nsopenssl/nsd.tcl

And go to https://localhost:8080/

To test the server I've included the default mod_ssl key and certificate
for the non-existent 'SnakeOil' company. Do not use these on a real server,
they are for testing only.


Development Environment
-----------------------

The code was developed under RedHat 6.0 with OpenSSL 0.9.4. It will
probably run without too many problems on different flavours of a UNIX
like operating system.

See nsd.tcl for a webserver configuration that uses SSL on port 8080.


Configuration Options
---------------------

Here's an overview of all the configuration options for this module.

ns_section "ns/server/server1/module/nsopenssl"
ns_param Port                8080
ns_param Hostname            localhost
ns_param CertFile            certificate.pem
ns_param KeyFile             key.pem
ns_param Debug               on
ns_param SessionCacheSize    512
ns_param SessionCacheTimeout 300
ns_param Protocol            "SSLv2, SSLv3, TLSv1"
ns_param CipherSuite         "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"

A minimal configuration will be like this:

ns_section "ns/server/server1/module/nsopenssl"
ns_param Port                8080
ns_param Hostname            localhost
ns_param CertFile            certificate.pem
ns_param KeyFile             key.pem

See nsd.tcl for more info. Real documentation will appear when the
featureset is stable. Don't worry :-)


Open Issues
-----------

Here's some things on my list.

 - Session caching seems to be flakey
 - Enable and test keepalive
 - Integrate and test with AOLServer 3.0b4
 - Create a TCL interface to access information about SSL connections
 - Write Good Documentation
 - Create a tool to create a Certificate Signing Request
 - Figure out how to distribute this
 ...


Copyright Notices
-----------------

The nsopenssl module is written and Copyrighted by Stefan Arentz. It is
distributed under the AOLServer Public License. See the file license.txt
for more information.

This product includes software developed by the OpenSSL Project for use
in the OpenSSL Toolkit. (http://www.openssl.org/)

This product includes cryptographic software written by Eric Young
(eay@cryptsoft.com).


Related Links
-------------

  http://www.aolserver.com  AOLServer homepage
  http://www.openssl.org    OpenSSL toolkit homepage
  http://www.modssl.org     OpenSSL module for Apache
  http://www.thawte.com     For getting test certificates


