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

# SSL contexts. Each SSL context is a template that SSL connections are created
# from.  A single SSL context may be used by multiple drivers, sockservers and
# sockclients. 

ns_section "ns/server/${servername}/module/nsopenssl/sslcontexts"
ns_param users        "SSL context used for regular user access"
ns_param admins       "SSL context used for administrator access"
ns_param client       "SSL context used for outgoing script socket connections"

# We explicitly tell the server which SSL contexts to use as defaults when an
# SSL context is not specified for a particular client or server SSL
# connection. Driver connections do not use defaults; they must be explicitly
# specificied in the driver section. The Tcl API will use the defaults as there
# is currently no provision to specify which SSL context to use for a
# particular connection via an ns_openssl Tcl command.

ns_section "ns/server/${servername}/module/nsopenssl/defaults"
ns_param server               users
ns_param client               client

ns_section "ns/server/${servername}/module/nsopenssl/sslcontext/users"
ns_param Role                  server
#ns_param ModuleDir             /path/to/dir
ns_param CertFile              server/server.crt 
ns_param KeyFile               server/server.key 
ns_param CADir                 ca-client/dir
ns_param CAFile                ca-client/ca-client.crt
ns_param Protocols             "SSLv3, TLSv1" 
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP" 
ns_param PeerVerify            false
ns_param PeerVerifyDepth       3
ns_param Trace                 false

ns_section "ns/server/${servername}/module/nsopenssl/sslcontext/admins"
ns_param Role                  server
#ns_param ModuleDir             /path/to/dir
ns_param CertFile              server/server.crt 
ns_param KeyFile               server/server.key 
ns_param CADir                 ca-client/dir 
ns_param CAFile                ca-client/ca-client.crt
ns_param Protocols             "All"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP" 
ns_param PeerVerify            false
ns_param PeerVerifyDepth       3
ns_param Trace                 false

ns_section "ns/server/${servername}/module/nsopenssl/sslcontext/client"
ns_param Role                  client
#ns_param ModuleDir             /path/to/dir
ns_param CertFile              client/client.crt 
ns_param KeyFile               client/client.key 
ns_param CADir                 ca-server/dir 
ns_param CAFile                ca-server/ca-server.crt
ns_param Protocols             "SSLv2, SSLv3, TLSv1" 
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP" 
ns_param PeerVerify            false
ns_param PeerVerifyDepth       3
ns_param Trace                 false

# SSL drivers. Each driver defines a port to listen on and an explitictly named
# SSL context to associate with it. Note that you can now have multiple driver
# connections within a single virtual server, which can be tied to different
# SSL contexts. Isn't that cool?

ns_section "ns/server/${servername}/module/nsopenssl/ssldrivers"
ns_param users         "Driver for regular user access"
ns_param admins        "Driver for administrator access"

ns_section "ns/server/${servername}/module/nsopenssl/ssldriver/users"
ns_param sslcontext            users
ns_param port                  $httpsport_users
ns_param hostname              $hostname
ns_param address               $address

ns_section "ns/server/${servername}/module/nsopenssl/ssldriver/admins"
ns_param sslcontext            admins
ns_param port                  $httpsport_admins
ns_param hostname              $hostname
ns_param address               $address

#
# Modules to load
#
ns_section "ns/server/${servername}/modules"
...
ns_param   nsopenssl       ${bindir}/nsopenssl${ext}



###############################################################################
#
# nsopenssl version 2.x configuration
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

