#
# nsd.tcl --
#
#      Sample nsopenssl configuration.
#
# $Header$
#

#
# Applies to nsopenssl 3.x
#

# Items that are global to the nsopenssl module
ns_section "ns/server/module/nsopenssl"
ns_param RandomFile                /some/file
ns_param SeedBytes                 1024

# Items specific to a particular server

# All of the listening ports to be defined. These are the servers that are
# driven by the core nsd process. They are used immediately and are running
# before AOLserver finishes it's startup process.
ns_section "ns/server/${servername}/module/nsopenssl/servers"
ns_param users                 "Main SSL Port for Users"
ns_param admins                "SSL Port for Administrators only"

# All of the sockserver listening contexts to be defined. These are *not*
# driven by the core nsd process, but are driven by nsopenssl itself via C API
# and Tcl API. They must be started manually by the C or Tcl API calls after
# AOLserver his already started.
ns_section "ns/server/${servername}/module/nsopenssl/sockservers"
ns_param tasklistener          "SSL Task Listener"

# All of the sockclients to be defined. These sockclients can connect to
# sockservers or to standard nsd core process driven servers, or any other SSL
# listener. These are used via the C and/or Tcl API. 
ns_section "ns/server/${servername}/module/nsopenssl/sockclients"
ns_param taskdispatcher        "SSL Task Dispatcher"

# Define an SSL context that will be used by the core nsd process to listen and
# handle connections coming from normal users.
ns_section "ns/server/${servername}/module/nsopenssl/servers/users"
ns_param Port                  443
ns_param Hostname              $hostname
ns_param Address               $address
ns_param ModuleDir             /path/to/dir
ns_param CertFile              servercertfile.pem
ns_param KeyFile               serverkeyfile.pem
ns_param Protocols             "SSLv2, SSLv3, TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SessionCacheOn        true
ns_param SessionCacheID        1
ns_param SessionCacheSize      512
ns_param SessionCacheTimeout   300
ns_param PeerVerifyOn          false
ns_param PeerVerifyDepth       3
ns_param CADir                 ca
ns_param CAFile                ca.pem
ns_param Trace                 false

# Define an SSL context that will be used by the core nsd process to listen and
# handle connections coming from administrative users.
ns_section "ns/server/${servername}/module/nsopenssl/servers/admins"
ns_param Port                  8443
ns_param Hostname              $hostname
ns_param Address               $address
ns_param ModuleDir             /path/to/dir
ns_param CertFile              servercertfile.pem
ns_param KeyFile               serverkeyfile.pem
ns_param Protocols             "SSLv3, TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:"
ns_param SessionCacheOn        true
ns_param SessionCacheID        2
ns_param SessionCacheSize      512
ns_param SessionCacheTimeout   300
ns_param PeerVerifyOn          true
ns_param PeerVerifyDepth       3
ns_param CADir                 ca
ns_param CAFile                ca.pem
ns_param Trace                 false

# Define an SSL sockserver context that will be used to listen for connections
# and handle them directly inside of nsopenssl.
ns_section "ns/server/${servername}/module/nsopenssl/sockservers/tasklistener"
ns_param Port                  9443  /* default listen port; can be overridden */
ns_param Hostname              $hostname
ns_param Address               $address
ns_param ModuleDir             /path/to/dir
ns_param CertFile              tasklistenercertfile.pem
ns_param KeyFile               tasklistenerkeyfile.pem
ns_param Protocols             "TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH"
ns_param SessionCacheOn        true
ns_param SessionCacheID        3
ns_param SessionCacheSize      512
ns_param SessionCacheTimeout   300
ns_param PeerVerifyOn          true
ns_param PeerVerifyDepth       3
ns_param CADir                 ca
ns_param CAFile                ca.pem
ns_param Trace                 false

# Define an SSL sockclient context that will be used to send out connections to
# the given default port and host.
ns_section "ns/server/${servername}/module/nsopenssl/sockclients/taskdispatcher"
ns_param Port                  9443 /* default port to connect to; can be overridden */
ns_param Hostname              $hostname /* default host to connect to; can be overridden */
ns_param Address               $address /* default address to connect to; can be overridden */
ns_param ModuleDir             /path/to/dir
ns_param CertFile              taskdispatchercertfile.pem
ns_param KeyFile               taskdispatcherkeyfile.pem
ns_param Protocols             "TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH"
ns_param SessionCacheOn        true
ns_param SessionCacheID        4
ns_param SessionCacheSize      512
ns_param SessionCacheTimeout   300
ns_param PeerVerifyOn          true
ns_param PeerVerifyDepth       3
ns_param CADir                 ca
ns_param CAFile                ca.pem
ns_param Trace                 false


/**********************************************************************************/

#
# Applies to nsopenssl 2.x
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
ns_param ServerSessionCacheSize          512
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
ns_param SockServerSessionCacheSize      512
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
ns_param SockClientSessionCacheSize      512
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






#
# DEPRECATED: applies to nsopenssl version 1.1c and less
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
#ns_param CipherSuite              "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
#ns_param SessionCache        true
#ns_param SessionCacheSize         512
#ns_param SessionCacheTimeout      300
ns_param ClientVerify             true
ns_param CADir                    ca
ns_param CAFile                   ca.pem
ns_param Trace                    false
ns_param RandomFile               /some/file

ns_section "ns/server/${servername}/modules"
ns_param nsopenssl    ${bindir}/nsopenssl${ext}

