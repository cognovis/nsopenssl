
$Header$


SSL v3 Module
-------------

This is an experimental version of an SSL module for AOLserver.

PLEASE NOTE THAT THIS SOFTWARE IS STILL PRE-ALPHA QUALITY AND SHOULD NOT
BE USED IN A PRODUCTION ENVIRONMENT.


Feature Highlights
------------------

 * Open Source software (AOLserver Public License)
 * Useable for both commercial and non-commercial use
 * 128-bit strong cryptography world-wide
 * Support for SSLv2, SSLv3 and TLSv1 protocols
 * Support for both RSA and Diffie-Hellman ciphers
 * Clean reviewable ANSI C source code
 * Support for the OpenSSL+RSAref US-situation


Compiling the code
------------------

To compile this code, just type:

gmake OPENSSL=/usr/local/ssl

or:

export OPENSSL=/usr/local/ssl
gmake
gmake install INST=/usr/local/aolserver

To compile with BSAFE make sure your OpenSSL library has been compiled
with BSAFE, and type:

gmake OPENSSL=/usr/local/openssl-bsafe BSAFE=/path/to/bsafe

(for more information on how to compile with BSAFE, see
http://scottg.net/aolserver).

To test the server, put the sample configuration from nsd.tcl into
your server's nsd.tcl, copy the sample *.pem files to
$INST/servers/server1/modules/nsopenssl, and start your server.  Visit
https://hostname:8443/.

The default key and certificate for the non-existent 'SnakeOil'
company are included for testing purposes. Do not use these on a real
server -- they are for testing only.


Development Environment
-----------------------

The code was developed under RedHat 6.0 with OpenSSL 0.9.4. It will
probably run without too many problems on different flavours of a UNIX
like operating system.

OpenSSL must be compiled as position-independent, but it does not
build that way in the configuration that comes from the OpenSSL
distribution.  The OpenSSL 0.9.5a release doesn't appear to have an
option for this so you'll have to include it in your compile step.

gmake CC="gcc -fPIC"

In addition, some operating systems (Solaris x86) may not support
position-independent code that has inline assembler.  The
configuration that seems to work on these platforms is:

./config no-asm
Then, followed by the same gmake step as before:
gmake CC="gcc -fPIC"

See nsd.tcl for a sample configuration that uses SSL on port 8443.


Configuration Options
---------------------

ns_section "ns/server/${servername}/module/nsopenssl"
ns_param port                $httpsport
ns_param hostname            $hostname
ns_param certfile            $sslcertfile
ns_param keyfile             $sslkeyfile
ns_param debug               off
ns_param sessioncachesize    512
ns_param sessioncachetimeout 300
ns_param protocol            "SSLv2, SSLv3, TLSv1"
#ns_param ciphersuite         "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"

ns_section "ns/server/${servername}/modules"
ns_param nsopenssl    ${bindir}/nsopenssl.so


Open Issues
-----------

Here's some things on my list.

 - Session caching seems to be flakey
 - Enable and test keepalive
 - done: Integrate and test with AOLserver 3.0b4
 - Create a TCL interface to access information about SSL connections
 - Write Good Documentation
 - Create a tool to create a Certificate Signing Request
 - done: Figure out how to distribute this
 ...


Copyright Notices
-----------------

The nsopenssl module is written and Copyrighted by Stefan Arentz. It
is distributed under the AOLserver Public License. See the file
license.txt for more information.

This product includes software developed by the OpenSSL Project for
use in the OpenSSL Toolkit. (http://www.openssl.org/)

This product includes cryptographic software written by Eric Young
(eay@cryptsoft.com).


Related Links
-------------

  http://www.aolserver.com  AOLserver homepage
  http://www.openssl.org    OpenSSL toolkit homepage
  http://www.modssl.org     OpenSSL module for Apache
  http://www.thawte.com     For getting test certificates

