# $Header$

#
# Define ports to use for testing
#
set httpsport_server              9050
set httpsport_sockserver          9051
set httpsport_sockclient          9052

#
# Define modules to load
#
array set loadmodules [list nsopenssl nsopenssl$ext]

#
# nsopenssl (HTTPS)
#
ns_section "ns/server/${servername}/module/nsopenssl"
ns_param ServerHostname                   $hostname
ns_param ServerAddress                    $address
ns_param ServerPort                       $httpsport_server
# This should be last resort???
#ns_param ServerLocation                   "https://192.168.0.2:$https2port"

ns_param ServerTrace                      true
ns_param ServerCertFile                   server1-cert.pem
ns_param ServerKeyFile                    server1-key-unsecure.pem
ns_param ServerPeerVerify                 false
ns_param ServerPeerVerifyDepth            10
ns_param ServerCADir                      server.cadir
ns_param ServerCAFile                     ca1-cert.pem
ns_param ServerProtocols                  "SSLv2, SSLv3, TLSv1"
ns_param ServerCipherSuite                "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param ServerSessionCache               false
ns_param ServerSessionCacheId             1
ns_param ServerSessionCacheSize           128
ns_param ServerSessionCacheTimeout        300


ns_param SockServerTrace                  true
ns_param SockServerCertFile               server1-cert.pem
ns_param SockServerKeyFile                server1-key-unsecure.pem
ns_param SockServerPeerVerify             true
ns_param SockServerPeerVerifyDepth        10
ns_param SockServerCADir                  server.cadir
ns_param SockServerCAFile                 ca1-cert.pem
ns_param SockServerProtocols              "SSLv2, SSLv3, TLSv1"
ns_param SockServerCipherSuite            "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SockServerSessionCache           false
ns_param SockServerSessionCacheId         2
ns_param SockServerSessionCacheSize       128
ns_param SockServerSessionCacheTimeout    300


ns_param SockClientTrace                  true
ns_param SockClientCertFile               client1-cert.pem
ns_param SockClientKeyFile                client1-key-unsecure.pem
ns_param SockClientPeerVerify             false
ns_param SockClientPeerVerifyDepth        10
ns_param SockClientCADir                  server.cadir
ns_param SockClientCAFile                 ca1-cert.pem
ns_param SockClientProtocols              "SSLv2, SSLv3, TLSv1"
ns_param SockClientCipherSuite            "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SockClientSessionCache           false
ns_param SockClientSessionCacheId         3
ns_param SockClientSessionCacheSize       128
ns_param SockClientSessionCacheTimeout    300


#ns_param RandomFile             /dev/urandom
#ns_param SeedBytes              1024

#ns_param ServerBufferSize       16384
#ns_param ServerSockTimeout      30

#ns_param ClientBufferSize       16384
#ns_param ClientSockTimeout      30


#
# nsopenssl (HTTPS) (Loading a second copy of the module)
#
ns_section "ns/server/${servername}/module/nsopenssl2"
ns_param ServerHostname                   $hostname
ns_param ServerAddress                    $address
ns_param ServerPort                       $httpsport_sockclient
# This should be last resort???
#ns_param ServerLocation                   "https://192.168.0.2:$https2port"

ns_param ServerTrace                      true
ns_param ServerCertFile                   server1-cert.pem
ns_param ServerKeyFile                    server1-key-unsecure.pem
ns_param ServerPeerVerify                 false
ns_param ServerPeerVerifyDepth            10
ns_param ServerCADir                      server.cadir
ns_param ServerCAFile                     ca1-cert.pem
ns_param ServerProtocols                  "SSLv2, SSLv3, TLSv1"
ns_param ServerCipherSuite                "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param ServerSessionCache               false
ns_param ServerSessionCacheId             1
ns_param ServerSessionCacheSize           128
ns_param ServerSessionCacheTimeout        300


ns_param SockServerTrace                  true
ns_param SockServerCertFile               server1-cert.pem
ns_param SockServerKeyFile                server1-key-unsecure.pem
ns_param SockServerPeerVerify             true
ns_param SockServerPeerVerifyDepth        10
ns_param SockServerCADir                  server.cadir
ns_param SockServerCAFile                 ca1-cert.pem
ns_param SockServerProtocols              "SSLv2, SSLv3, TLSv1"
ns_param SockServerCipherSuite            "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SockServerSessionCache           false
ns_param SockServerSessionCacheId         2
ns_param SockServerSessionCacheSize       128
ns_param SockServerSessionCacheTimeout    300


ns_param SockClientTrace                  true
ns_param SockClientCertFile               client1-cert.pem
ns_param SockClientKeyFile                client1-key-unsecure.pem
ns_param SockClientPeerVerify             false
ns_param SockClientPeerVerifyDepth        10
ns_param SockClientCADir                  server.cadir
ns_param SockClientCAFile                 ca1-cert.pem
ns_param SockClientProtocols              "SSLv2, SSLv3, TLSv1"
ns_param SockClientCipherSuite            "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"
ns_param SockClientSessionCache           false
ns_param SockClientSessionCacheId         3
ns_param SockClientSessionCacheSize       128
ns_param SockClientSessionCacheTimeout    300


#ns_param RandomFile             /dev/urandom
#ns_param SeedBytes              1024

#ns_param ServerBufferSize       16384
#ns_param ServerSockTimeout      30

#ns_param ClientBufferSize       16384
#ns_param ClientSockTimeout      30
