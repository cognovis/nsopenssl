# nsopenssl socket testing setup
# Copyright (c) 2001 by Scott S. Goodwin
# See http://scottg.net for more information

ns_log notice "loading test-socklisten.tcl"

## non-SSL socklisten/sockaccept
# Listen on a non-SSL socket and read/write messages to a client
ns_register_proc GET /do_socklisten do_socklisten
proc do_socklisten {} {
    set p "do_socklisten"
    set sock [ns_socklisten [nsv_get . httpaddr] [nsv_get . listenport]]
    set fds [ns_sockaccept $sock]
    set rfd [lindex $fds 0]
    set wfd [lindex $fds 1]
    ns_log notice "$p: SERVER: RFD=$rfd; WFD=$wfd"
    set line [gets $rfd]
    ns_log notice "$p: SERVER READ A: $line"
    puts $wfd "MSG B"
    flush $wfd
    ns_log notice "$p: SERVER WROTE B"
    set line [gets $rfd]
    ns_log notice "$p: SERVER READ C: $line"
    puts $wfd "MSG D"
    flush $wfd
    ns_log notice "$p: SERVER WROTE D"
    # Really, we should let the client send the last message
    # and then close, as closing the fd's here seems to cause an
    # SSL_ERROR_SYSCALL in the NsOpenSSLSend function. Need
    # to debug this.
    ns_log notice "$p: SERVER CLOSING FDs"
    close $rfd
    close $wfd
    close $sock
    set content [do_content "<b>tested ns_socklisten/ns_sockaccept</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# do_connect
# Connect to a non-SSL listening socket and read/write messages, closing at the end
ns_register_proc GET /do_connect do_connect
proc do_connect {} {
    set p "do_connect"
    set fds [ns_sockopen -nonblock [nsv_get . httpaddr] [nsv_get . listenport]]
    set rfd [lindex $fds 0]
    set wfd [lindex $fds 1]
    ns_log notice "$p: CLIENT RFD=$rfd; WFD=$wfd"
    puts $wfd "MSG A"
    flush $wfd
    ns_log notice "$p: CLIENT WROTE A"
    set line [gets $rfd]
    ns_log notice "$p: CLIENT READ B: $line"
    puts $wfd "MSG C"
    flush $wfd
    ns_log notice "$p: CLIENT WROTE C"
    set line [gets $rfd]
    ns_log notice "$p: CLIENT READ D: $line"
    ns_log notice "$p: CLIENT CLOSING FDs"
    close $rfd
    close $wfd
    set content [do_content "<b>ran do_connect</b><br>"]
    set rc [do_write [do_header $content] $content]
}

#######################################################################################

# SSL socklisten/sockaccept
# Listen on an SSL socket and read/write messages to a client
ns_register_proc GET /do_ssl_socklisten do_ssl_socklisten
proc do_ssl_socklisten {} {
    set p "do_ssl_socklisten"
    set sock [ns_openssl_socklisten [nsv_get . httpaddr] [nsv_get . listensslport]]
    set fds [ns_openssl_sockaccept $sock]
    set rfd [lindex $fds 0]
    set wfd [lindex $fds 1]
    ns_log notice "$p: SERVER: RFD=$rfd; WFD=$wfd"
    set line [gets $rfd]
    ns_log notice "$p: SERVER READ A: $line"
    puts $wfd "MSG B"
    flush $wfd
    ns_log notice "$p: SERVER WROTE B"
    set line [gets $rfd]
    ns_log notice "$p: SERVER READ C: $line"
    puts $wfd "MSG D"
    flush $wfd
    ns_log notice "$p: SERVER WROTE D"
    ns_log notice "$p: SERVER CLOSING FDs"
    close $rfd
    close $wfd
    close $sock
    set content [do_content "<b>tested ns_openssl_socklisten/ns_openssl_sockaccept</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# do_ssl_connect
# Connect to as SSL listening socket and read/write messages, closing at the end
ns_register_proc GET /do_ssl_connect do_ssl_connect
proc do_ssl_connect {} {
    set p "do_ssl_connect"
    set fds [ns_openssl_sockopen -nonblock [nsv_get . httpaddr] [nsv_get . listensslport]]
    set rfd [lindex $fds 0]
    set wfd [lindex $fds 1]
    ns_log notice "$p: CLIENT RFD=$rfd; WFD=$wfd"
    puts $wfd "MSG A"
    flush $wfd
    ns_log notice "$p: CLIENT WROTE A"
    set line [gets $rfd]
    ns_log notice "$p: CLIENT READ B: $line"
    puts $wfd "MSG C"
    flush $wfd
    ns_log notice "$p: CLIENT WROTE C"
    set line [gets $rfd]
    ns_log notice "$p: CLIENT READ D: $line"
    ns_log notice "$p: CLIENT CLOSING FDs"
    close $rfd
    close $wfd
    set content [do_content "<b>ran do_ssl_connect</b><br>"]
    set rc [do_write [do_header $content] $content]
}

ns_log notice "done loading test-socklisten.tcl"
