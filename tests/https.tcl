# nsopenssl socket testing setup
# Copyright (c) 2001 by Scott S. Goodwin
# See http://scottg.net for more information

ns_log notice "loading test-http.tcl"

#####################################################################################

# test ns_httppost
ns_register_proc GET /do_httppost httppost
proc httppost {} {
    set qsset [ns_set new qsset]
    ns_set put $qsset user goodwin
    ns_set put $qsset pass blahblah
    set page [ns_httppost "http://[nsv_get . httpaddr]:[nsv_get . port]/test.cgi" "" $qsset]
    ns_log notice "PAGE = $page"
    set content [do_content "after: <b>ns_httppost</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httpspost
ns_register_proc GET /do_httpspost httpspost
proc httpspost {} {
    set qsset [ns_set new qsset]
    ns_set put $qsset user goodwin
    ns_set put $qsset pass blahblah
    set page [ns_httpspost "https://[nsv_get . httpaddr]:[nsv_get . sslport]/test.cgi" "" $qsset]
    ns_log notice "PAGE = $page"
    set content [do_content "after: <b>ns_httpspost</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httppost (multipart)
ns_register_proc GET /do_httppost_multi httppost_multi
proc httppost_multi {} {
    set qsset [ns_set new qsset]
    ns_set put $qsset user goodwin
    ns_set put $qsset pass blahblah
    set page [ns_httppost "http://[nsv_get . httpaddr]:[nsv_get . port]/test.cgi" "" $qsset]
    ns_log notice "PAGE =\n$page\nDONE\n"
    set content [do_content "after: <b>ns_httppost_multi</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httpspost (multipart)
ns_register_proc GET /do_httpspost_multi httpspost_multi
proc httpspost_multi {} {
    set qsset [ns_set new qsset]
    ns_set put $qsset user goodwin
    ns_set put $qsset pass blahblah
    set page [ns_httpspost "https://[nsv_get . httpaddr]:[nsv_get . sslport]/test.cgi" "" $qsset "multipart/form-data"]
    ns_log notice "PAGE =\n$page\nDONE\n"
    set content [do_content "after: <b>ns_httpspost_multi</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httppost (no data)
ns_register_proc GET /do_httppost_nodata httppost_nodata
proc httppost_nodata {} {
    set page [ns_httppost "http://[nsv_get . httpaddr]:[nsv_get . port]/test.cgi" "" ""]
    ns_log notice "PAGE = $page"
    set content [do_content "after: <b>ns_httppost (no data)</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httpspost (no data)
ns_register_proc GET /do_httpspost_nodata httpspost_nodata
proc httpspost_nodata {} {
    set page [ns_httpspost "https://[nsv_get . httpaddr]:[nsv_get . sslport]/test.cgi" "" ""]
    ns_log notice "PAGE = $page"
    set content [do_content "after: <b>ns_httpspost (no data)</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# read a POST
ns_register_proc POST /do_httppost_read httppost_read
proc httppost_read {} {
    ns_log notice "READING"
    ns_log notice "R: [ns_conn form]"
    set setId [ns_conn form]
#    ns_set merge $setId [ns_conn form]
    set size [ns_set size $setId]
    for {set i 0} {$i < $size} {incr i} {
	set key [ns_set key $setId $i]
	set value [ns_set value $setId $i]
	ns_log notice "READING: key=$key value=$value"
    }
    set content [do_content "after: <b>ns_httppost</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httpspost
#ns_register_proc GET /do_httpspost httpspost
#proc httpspost {} {
#    set page [ns_httpspost "https://[nsv_get . httpaddr]:[nsv_get . sslport]"]
#    ns_log notice "PAGE=$page"
#    set content [do_content "after: <b>ns_httpspost</b><br>"]
#    set rc [do_write [do_header $content] $content]
#}

#####################################################################################

# test ns_geturl
ns_register_proc GET /do_geturl geturl 
proc geturl { conn context } {
    #ns_return 200 text/html [ns_geturl https://www.wais.com/]
    ns_return 200 text/html [ns_geturl "http://[nsv_get . httpaddr]:[nsv_get . port]"]

}

# test ns_openssl_geturl
ns_register_proc GET /do_openssl_geturl openssl_geturl 
proc openssl_geturl { conn context } {
    #ns_return 200 text/html [ns_geturl https://www.wais.com/]
    ns_return 200 text/html [ns_openssl_geturl "https://[nsv_get . httpaddr]:[nsv_get . sslport]"]

}

#####################################################################################

# test ns_httpopen
ns_register_proc GET /do_httpopen httpopen
proc httpopen {} {
    set cookie_set [ns_set create cookie_set]
    ns_set put $cookie_set Cookie "mycookiename=mycookievalue; Path=/; Domain=.eglin.af.mil"
#    set hlist [ns_httpopen GET "http://[nsv_get . httpaddr]:[nsv_get . port]" $cookie_set]
    set hlist [ns_httpopen GET "/testurl" $cookie_set]
    set rid [lindex $hlist 0]
    set wid [lindex $hlist 1]
    set setid [lindex $hlist 2]
    ns_log notice "RID=$rid  WID=$wid  SETID=$setid"
    set page [read $rid]
    close $rid
    close $wid
    ns_log notice "PAGE=$page"
    set content [do_content "after: <b>ns_httpopen</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httpsopen
ns_register_proc GET /do_httpsopen httpsopen
proc httpsopen {} {
    set cookie_set [ns_set create cookie_set]
    ns_set put $cookie_set Cookie "mycookiename=mycookievalue; Path=/; Domain=.eglin.af.mil"
    set hlist [ns_httpsopen GET "https://[nsv_get . httpaddr]:[nsv_get . sslport]" $cookie_set]
    set rid [lindex $hlist 0]
    set wid [lindex $hlist 1]
    set setid [lindex $hlist 2]
    ns_log notice "RID=$rid  WID=$wid  SETID=$setid"
    set page [read $rid]
    close $rid
    close $wid
    ns_log notice "PAGE=$page"
    set content [do_content "after: <b>ns_httpsopen</b><br>"]
    set rc [do_write [do_header $content] $content]
}

#####################################################################################

# test ns_httpget
ns_register_proc GET /do_httpget httpget
proc httpget {} {
    set page [ns_httpget "http://[nsv_get . httpaddr]:[nsv_get . port]"]
    ns_log notice "PAGE=$page"
    set content [do_content "after: <b>ns_httpget</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httpsget
ns_register_proc GET /do_httpsget httpsget
proc httpsget {} {
    set page [ns_httpsget "https://[nsv_get . httpaddr]:[nsv_get . sslport]"]
    ns_log notice "PAGE=$page"
    set content [do_content "after: <b>ns_httpsget</b><br>"]
    set rc [do_write [do_header $content] $content]
}

#####################################################################################

# test ns_httpget with a local url
ns_register_proc GET /do_httpget_local httpget_local
proc httpget_local {} {
    set page [ns_httpget "/testurl"]
    ns_log notice "PAGE=$page"
    set content [do_content "after: <b>ns_httpget</b><br>"]
    set rc [do_write [do_header $content] $content]
}

# test ns_httpsget with a local url
ns_register_proc GET /do_httpsget_local httpsget_local
proc httpsget_local {} {
    set page [ns_httpsget "/testurl"]
    ns_log notice "PAGE=$page"
    set content [do_content "after: <b>ns_httpsget</b><br>"]
    set rc [do_write [do_header $content] $content]
}

ns_log notice "done loading test-http.tcl"
