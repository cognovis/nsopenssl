# nsopenssl socket testing setup
# Copyright (c) 2001 by Scott S. Goodwin
# See http://scottg.net for more information

ns_log notice "loading 0-socktests.tcl"

nsv_set . httpaddr       #%#ADDRESS#%#
nsv_set . sslport        #%#HTTPSPORT#%#
nsv_set . port           #%#HTTPPORT#%#
nsv_set . listenport     #%#LISTENPORT#%#
nsv_set . listensslport  #%#LISTENSSLPORT#%#

# show test page
ns_register_proc GET /testurl testurl
proc testurl {conn} {
     set content [do_content "Choose a test link from below"]
     set rc [do_write [do_header $content] $content]
}

# Returns HTML to the client requesting this url
ns_register_proc GET /hardcodedurl hardcodedurl
proc hardcodedurl {conn} {
    set content_htm \
"<html>
<head>
<title>ssltest</title>
</head>
<body>
<p>If you're reading this, then it worked.
</body>
</html>
"

    set myheader \
        "HTTP/1.0 200 Document follows
MIME-Version: 1.0
Content-Type: text/html
Content-Length: [string length $content_htm]"

    ns_write \
"$myheader   


$content_htm"
}

# show the url the browser requested
ns_register_filter preauth GET /* showurl
proc showurl {conn} {
    set url [ns_conn url]
    ns_log notice "rp: URL requested: $url"

    return filter_ok
}


proc do_write {header content} {
    ns_write \
"$header   


$content"
return 1;
}

proc do_header {content} {
    return \
        "HTTP/1.0 200 Document follows
MIME-Version: 1.0
Content-Type: text/html
Content-Length: [string length $content]"
}

proc do_content {content} {
    return \
"<html>
<head>
<title>ssl-platform tests</title>
<style>
a { text-decoration: none; }
</style>
</head>
<body>
<table width=\"100%\">
<tr><td colspan=\"2\" bgcolor=\"#f0f0f0\">$content</td></tr>

<tr>
<td><b>Normal Conn Tests</b></td>
<td><b>SSL Conn Tests</b></td>
</tr>

<!-- Connect to the testurl via normal or SSL conn -->
<tr>
<td><a href=\"http://[nsv_get . httpaddr]:[nsv_get . port]/testurl\">testurl</a></td>
<td><a href=\"https://[nsv_get . httpaddr]:[nsv_get . sslport]/testurl\">testurl</a></td>
</tr>

<!-- Connect to the home page of the test server via normal and SSL connections -->
<tr>
<td><a href=\"http://[nsv_get . httpaddr]:[nsv_get . port]\">home</a></td>
<td><a href=\"https://[nsv_get . httpaddr]:[nsv_get . sslport]\">ssl home</a></td>
</tr>
<tr>
<td><a href=\"/do_sockopen\">ns_sockopen</a></td>
<td><a href=\"/do_ssl_sockopen\">ns_openssl_sockopen</a></td>
</tr>

<!-- Test socklisten commands -->
<tr>
<td><a href=\"/do_socklisten\">ns_socklisten (1)</a> | <a href=\"/do_connect\">connect</a></td>
<td><a href=\"/do_ssl_socklisten\">ns_openssl_socklisten (1)</a> | <a href=\"/do_ssl_connect\">connect</a></td>
</tr>
<tr>
<td><a href=\"/do_socklisten2\">ns_socklisten (2)</a> | <a href=\"http://[nsv_get . httpaddr]:[nsv_get . listenport]\">connect</a></td>
<td><a href=\"/do_ssl_socklisten2\">ns_openssl_socklisten (2)</a> | <a href=\"https://[nsv_get . httpaddr]:[nsv_get . listensslport]\">connect</a></td></tr>
</tr>

<!-- Test sockcallback and socklistencallback -->
<tr>
<td><a href=\"/do_sockcallback\">ns_sockcallback</a> | <a href=\"http://[nsv_get . httpaddr]:[nsv_get . listenport]\">connect</a></td>
<td><a href=\"/do_ssl_sockcallback\">ns_openssl_sockcallback</a> | <a href=\"https://[nsv_get . httpaddr]:[nsv_get . listensslport]\">connect</a></td>
</tr>
<tr>
<td><a href=\"/do_socklistencallback\">ns_socklistencallback</a> | <a href=\"http://[nsv_get . httpaddr]:[nsv_get . listenport]\">connect</a></td>
<td><a href=\"/do_ssl_socklistencallback\">ns_openssl_socklistencallback</a> | <a href=\"https://[nsv_get . httpaddr]:[nsv_get . listensslport]\">connect</a></td>
</tr>

<!-- Test http.tcl and https.tcl -->
<tr>
<td><a href=\"/do_httpopen\">ns_httpopen</a></td>
<td><a href=\"/do_httpsopen\">ns_httpsopen</a></td>
</tr>
<tr>
<td><a href=\"/do_httpget\">ns_httpget</a></td>
<td><a href=\"/do_httpsget\">ns_httpsget</a></td>
</tr>
<tr>
<td><a href=\"/do_httpget_local\">ns_httpget local url</a></td>
<td><a href=\"/do_httpsget_local\">ns_httpsget local url</a></td>
</tr>
<tr>
<td><a href=\"/do_httppost\">ns_httppost</a> | <a href=\"/do_httppost_nodata\">ns_httppost (no data)</a> | <a href=\"/do_httppost_multi\">ns_httppost (multipart)</a></td>
<td><a href=\"/do_httpspost\">ns_httpspost</a> | <a href=\"/do_httpspost_nodata\">ns_httpspost (no data)</a> | <a href=\"/do_httpspost_multi\">ns_httpspost (multipart)</a></td>
</tr>
<!-- Do test.htm tests -->
<tr>
<td><a href=\"http://[nsv_get . httpaddr]:[nsv_get . port]/test.htm\">Have Browser Form call test.cgi</a></td>
<td><a href=\"https://[nsv_get . httpaddr]:[nsv_get . sslport]/test.htm\">Have Browser Form call test.cgi</a></td>
</tr>


<!-- Test Ns_OpenSSLFetchURL -->
<tr>
<td><a href=\"/do_geturl\">ns_geturl</a></td>
<td><a href=\"/do_openssl_geturl\">ns_openssl_geturl</a></td>
</tr>

<!-- Do a file upload to test aborted connections -->
<tr>
<td><a href=\"http://[nsv_get . httpaddr]:[nsv_get . port]/test-upload.htm\">file upload</a></td>
<td><a href=\"https://[nsv_get . httpaddr]:[nsv_get . sslport]/test-upload.htm\">file upload</a></td>
</tr>

<!-- Do large file download test -->
<tr>
<td><a href=\"http://[nsv_get . httpaddr]:[nsv_get . port]/bigfile.dat\">bigfile.dat</a></td>
<td><a href=\"https://[nsv_get . httpaddr]:[nsv_get . sslport]/bigfile.dat\">bigfile.dat</a></td>
</tr>

<!-- kickoff automated tests -->
<tr>
<td><a href=\"http://[nsv_get . httpaddr]:[nsv_get . port]/http_auto_tests\">Start Automated Tests</a></td>
<td><a href=\"https://[nsv_get . httpaddr]:[nsv_get . sslport]/https_auto_tests\">Start Automated Tests</a></td>
</tr>

<!--
<tr><td><b> -- NOT YET IMPLEMENTED -- </b></td></tr>
<tr><td><a href=\"/do_sockaccept\">ns_sockaccept</a></td><td><a href=\"/do_ssl_sockaccept\">ns_openssl_sockaccept</a></td></tr>
<tr><td><a href=\"/do_socksetblocking\">ns_socksetblocking</a></td><td><a href=\"/do_ssl_socksetblocking\">ns_openssl_socksetblocking</a></td></tr>
<tr><td><a href=\"/do_socksetnonblocking\">ns_socksetnonblocking</a></td><td><a href=\"/do_ssl_socksetnonblocking\">ns_openssl_socksetnonblocking</a></td></tr>
<tr><td><a href=\"/do_sockpair\">ns_sockpair</a></td><td><a href=\"/do_ssl_sockpair\">ns_openssl_sockpair</a></td></tr>
<tr><td><a href=\"/do_socknread\">ns_socknread</a></td><td><a href=\"/do_ssl_socknread\">ns_openssl_socknread</a></td></tr>
-->


</table>
</body>
</html>
"
}

ns_log notice "done loading 0-socktests.tcl"
