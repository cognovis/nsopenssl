<html>
<head>
  <title>SSL Test Page for the nsopenssl module</title>
</head>
<body>

<font face="Verdana, Arial">

<h2>SSL Test Page for the nsopenssl module</h2>


<p>(Copy this ADP page to your pageroot and run.)


<table border=1 cellspacing=0>

<tr><td><font color=red>Does Cert Exist?</font></td><td>
<%
  if {[ns_openssl clientcert exists]} {
        ns_puts "Client cert exists"
  } else {
        ns_puts "Client cert does NOT exist"
  }
%>
</td></tr>

<tr><td><font color=red>SSL INFO</font></td><td>
<%=[ns_openssl info]%>
</td></tr>

<tr><td><font color=red>CLIENT CERT VERSION</font></td><td>
<%=[ns_openssl clientcert version]%>
</td></tr>

<tr><td><font color=red>SERIAL NUMBER</font></td><td>
<%=[ns_openssl clientcert serial]%>
</td></tr>

<tr><td><font color=red>SUBJECT</font></td><td>
<%
  set var [ns_openssl clientcert subject]
  ns_puts "$var"
%>
</td></tr>

<tr><td><font color=red>ISSUER</font></td><td>
<%
  set var [ns_openssl clientcert issuer]
  ns_puts "$var"
%>
</td></tr>

<tr><td><font color=red>NOT BEFORE</font></td><td>
<%=[ns_openssl clientcert notbefore]%>
</td></tr>

<tr><td><font color=red>NOT AFTER</font></td><td>
<%=[ns_openssl clientcert notafter]%>
</td></tr>

<tr><td><font color=red>SIGNATURE ALGORITHM</font></td><td>
<%=[ns_openssl clientcert signature_algorithm]%>
</td></tr>

<tr><td><font color=red>KEY ALGORITHM</font></td><td>
<%=[ns_openssl clientcert key_algorithm]%>
</td></tr>

<tr><td><font color=red>PEM Certificate</font></td><td>
<%=[ns_openssl clientcert pem]%>
</td></tr>

</table>

<p>This page and client certificate support in nsopenssl brought to
you by Scott S. Goodwin, <a
href="http://scottg.net">http://scottg.net</a>.

<p>Copyright &copy; 2000 by Scott S. Goodwin
<p>Send feedback, bugs and comments to <a href="mailto:scott@scottg.net">me</a>. Enjoy!!!

</font>

</body>
</html>















