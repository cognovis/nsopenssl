#
# nsd.tcl --
#
#      Sample nsopenssl configuration.
#
# $Header$
#

ns_section "ns/server/${servername}/module/nsopenssl"
ns_param port                $httpsport
ns_param hostname            $hostname
ns_param certfile            $sslcertfile
ns_param keyfile             $sslkeyfile
ns_param sessioncachesize    512
ns_param sessioncachetimeout 300
ns_param protocol            "SSLv2, SSLv3, TLSv1"
#ns_param ciphersuite         "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"

ns_section "ns/server/${servername}/modules"
ns_param nsopenssl    ${bindir}/nsopenssl${ext}

