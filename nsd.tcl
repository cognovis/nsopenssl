###############################################################################
#
# Sample configurations for nsopenssl
#
# This file contains three sets of configuration examples, one for each of 1.x,
# 2.x and 3.x versions of nsopenssl.
#
# Parameters followed by the comment "# default" show the default values if you
# don't specify that parameter.
#
# Parameters followed by the comment "# mandatory" indicate that you must
# specify a value for that parameter.
#
# $Header$

###############################################################################
#
# nsopenssl version 3.x configuration
#

#
# Global nsopenssl settings
#

ns_section "ns/server/module/nsopenssl"
ns_param RandomFile /some/file
ns_param SeedBytes  1024

#
# Virtual Server specific nsopenssl configurations
#

# SSL contexts. Each SSL context is intended to be a complete definition
# of an SSL instance. An SSL context may be used by multiple drivers,
# sockservers and sockclients.

ns_section "ns/server/${servername}/module/nsopenssl/contexts"
ns_param user                  "SSL context used for regular user access"
ns_param admin                 "SSL context used for administrator access"

ns_section "ns/server/${servername}/module/nsopenssl/context/user"
ns_param Role                  server                                             # mandatory
ns_param ModuleDir             /path/to/dir                                       # default
ns_param CertFile              servercertfile.pem                                 # mandatory
ns_param KeyFile               serverkeyfile.pem                                  # mandatory
ns_param CADir                 serverca                                           # default
ns_param CAFile                serverca.pem                                       # default
ns_param Protocols             "SSLv2, SSLv3, TLSv1"                              # default
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"  # default
ns_param PeerVerify            false                                              # default
ns_param PeerVerifyDepth       3                                                  # default
ns_param Trace                 false                                              # default
ns_param SessionCache          true                                               # default
ns_param SessionCacheSize      128                                                # default
ns_param SessionCacheTimeout   300                                                # default

ns_section "ns/server/${servername}/module/nsopenssl/context/admin"
ns_param Role                  server
ns_param ModuleDir             /path/to/dir
ns_param CertFile              servercertfile.pem
ns_param KeyFile               serverkeyfile.pem
ns_param CADir                 serverca
ns_param CAFile                serverca.pem
ns_param Protocols             "SSLv2, SSLv3, TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param PeerVerify            false
ns_param PeerVerifyDepth       3
ns_param Trace                 false
ns_param SessionCache          true
ns_param SessionCacheSize      128
ns_param SessionCacheTimeout   300

ns_section "ns/server/${servername}/module/nsopenssl/context/sockclient"
ns_param Role                  client
ns_param ModuleDir             /path/to/dir
ns_param CertFile              clientcertfile.pem
ns_param KeyFile               clientkeyfile.pem
ns_param CADir                 clientca
ns_param CAFile                clientca.pem
ns_param Protocols             "SSLv2, SSLv3, TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param PeerVerify            true
ns_param PeerVerifyDepth       3
ns_param Trace                 false
ns_param SessionCache          true
ns_param SessionCacheSize      128
ns_param SessionCacheTimeout   300

# SSL drivers. Each driver defines a port and a named SSL context to associate
# with it.

ns_section "ns/server/${servername}/module/nsopenssl/contexts"
ns_param users                 "Driver for regular user access"
ns_param admins                "Driver for administrator access"

ns_section "ns/server/${servername}/module/nsopenssl/driver/users"
ns_param context               user
ns_param port                  443
ns_param hostname              127.0.0.1
ns_param address               127.0.0.1

ns_section "ns/server/${servername}/module/nsopenssl/driver/admins"
ns_param context               admin
ns_param port                  8443
ns_param hostname              127.0.0.1
ns_param address               127.0.0.1



###############################################################################
#
# DEPRECATED: nsopenssl version 2.x configuration
#

ns_section "ns/server/${servername}/module/nsopenssl"

# NSD-driven connections:
ns_param ServerPort                      $httpsport
ns_param ServerHostname                  $hostname
ns_param ServerAddress                   $address
ns_param ServerCertFile                  certfile.pem
ns_param ServerKeyFile                   keyfile.pem
ns_param ServerProtocols                 "SSLv2, SSLv3, TLSv1"
ns_param ServerCipherSuite               "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param ServerSessionCache              false
ns_param ServerSessionCacheID            1
ns_param ServerSessionCacheSize          128
ns_param ServerSessionCacheTimeout       300
ns_param ServerPeerVerify                true
ns_param ServerPeerVerifyDepth           3
ns_param ServerCADir                     ca
ns_param ServerCAFile                    ca.pem
ns_param ServerTrace                     false

# For listening and accepting SSL connections via Tcl/C API:
ns_param SockServerCertFile              certfile.pem
ns_param SockServerKeyFile               keyfile.pem
ns_param SockServerProtocols             "SSLv2, SSLv3, TLSv1"
ns_param SockServerCipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SockServerSessionCache          false
ns_param SockServerSessionCacheID        2
ns_param SockServerSessionCacheSize      128
ns_param SockServerSessionCacheTimeout   300
ns_param SockServerPeerVerify            true
ns_param SockServerPeerVerifyDepth       3
ns_param SockServerCADir                 internal_ca
ns_param SockServerCAFile                internal_ca.pem
ns_param SockServerTrace                 false

# Outgoing SSL connections
ns_param SockClientCertFile              clientcertfile.pem
ns_param SockClientKeyFile               clientkeyfile.pem
ns_param SockClientProtocols             "SSLv2, SSLv3, TLSv1"
ns_param SockClientCipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SockClientSessionCache          false
ns_param SockClientSessionCacheID        3
ns_param SockClientSessionCacheSize      128
ns_param SockClientSessionCacheTimeout   300
ns_param SockClientPeerVerify            true
ns_param SockServerPeerVerifyDepth       3
ns_param SockClientCADir                 ca
ns_param SockClientCAFile                ca.pem
ns_param SockClientTrace                 false

# Typically where you store your certificates
# Defaults to $AOLSERVER/servers/${servername}/modules/nsopenssl
ns_param ModuleDir                       /path/to/dir

# OpenSSL library support:
ns_param RandomFile                      /some/file
ns_param SeedBytes                       1024


###############################################################################
#
# DEPRECATED: nsopenssl 1.x configuration
#

ns_section "ns/server/${servername}/module/nsopenssl"   
ns_param address                  $address
ns_param port                     $httpsport
ns_param hostname                 $hostname
ns_param CertFile                 certfile.pem
ns_param KeyFile                  keyfile.pem
ns_param Protocol                 All
#ns_param Protocol                 SSLv2
#ns_param Protocol                 SSLv3
#ns_param Protocol                 TLSv1
ns_param CipherSuite              "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SessionCache             true
ns_param SessionCacheSize         128
ns_param SessionCacheTimeout      300
ns_param ClientVerify             true
ns_param CADir                    ca
ns_param CAFile                   ca.pem
ns_param Trace                    false
ns_param RandomFile               /some/file

ns_section "ns/server/${servername}/modules"
ns_param nsopenssl    ${bindir}/nsopenssl${ext}

