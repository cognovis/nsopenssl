#
# nsd.tcl --
#
#      Sample nsopenssl configuration.
#
# $Header$

#
# Applies to nsopenssl 3.x ONLY
#

# Items that are global to the nsopenssl module
ns_section "ns/server/module/nsopenssl"
ns_param RandomFile                /some/file
ns_param SeedBytes                 1024

#
# Items specific to each virtual server
#

# Define SSL drivers. Connections coming into these drivers are
# piped straight through nsd's core HTTP processing engine.

ns_section "ns/server/${servername}/module/nsopenssl/drivers"
ns_param users                 "Main SSL Port for Users"
ns_param admins                "SSL Port for Administrators only"

ns_section "ns/server/${servername}/module/nsopenssl/driver/users"
ns_param context               usercontext
ns_param port                  443
ns_param hostname              127.0.0.1
ns_param address               127.0.0.1

ns_section "ns/server/${servername}/module/nsopenssl/driver/admins"
ns_param context               admincontext
ns_param port                  8443
ns_param hostname              127.0.0.1
ns_param address               127.0.0.1

# Define SSL contexts. Each SSL context is intended to be a complete definition
# of an SSL instance. A particular SSL context may be used by multiple drivers,
# sockservers and sockclients. The "sex" of the SSL instance is determined at
# run-time (i.e. whether it is a server or client).

ns_section "ns/server/${servername}/module/nsopenssl/contexts"
ns_param  user                 "User connections"
ns_param  admin                "Admin connections"

ns_section "ns/server/${servername}/module/nsopenssl/context/user"
ns_param Role                  server
ns_param ModuleDir             /path/to/dir
ns_param CertFile              servercertfile.pem
ns_param KeyFile               serverkeyfile.pem
ns_param CADir                 ca
ns_param CAFile                ca.pem
ns_param Protocols             "SSLv2, SSLv3, TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param PeerVerifyOn          false
ns_param PeerVerifyDepth       3
ns_param SessionCacheOn        true
ns_param SessionCacheSize      512
ns_param SessionCacheTimeout   300
ns_param Trace                 false

ns_section "ns/server/${servername}/module/nsopenssl/context/admin"
ns_param Role                  server
ns_param ModuleDir             /path/to/dir
ns_param CertFile              servercertfile.pem
ns_param KeyFile               serverkeyfile.pem
ns_param CADir                 ca
ns_param CAFile                ca.pem
ns_param Protocols             "SSLv2, SSLv3, TLSv1"
ns_param CipherSuite           "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param PeerVerifyOn          false
ns_param PeerVerifyDepth       3
ns_param SessionCacheOn        true
ns_param SessionCacheSize      512
ns_param SessionCacheTimeout   300
ns_param Trace                 false

#
# IGNORING sockservers and sockclients for now
#

# Define SSL "sockservers". A sockserver is an SSL listener that is *not* piped
# through the core nsd HTTP processing engine but are managed directly by nsopenssl
# via its C and Tcl APIs. They must be started manually using C or Tcl API calls after
# AOLserver has finished its startup (note: there may be problems if you want
# to listen on a port below 1024. I may have to add prebind capability somehow).

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

