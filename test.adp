<html>
<head>
  <title>SSL Test Page for the nsopenssl module</title>
</head>
<body>

<font face="Verdana, Arial">

<h2>SSL Test Page for the nsopenssl module</h2>


<p>(Copy this ADP page to your pageroot and run.)


<table border=1 cellspacing=0>


<tr><td><font color=red>SSL INFO</font></td><td>
<%=[ssl info]%>
</td></tr>

<tr><td><font color=red>CLIENT CERT VERSION</font></td><td>
<%=[ssl clientcert version]%>
</td></tr>

<tr><td><font color=red>SERIAL NUMBER</font></td><td>
<%=[ssl clientcert serial]%>
</td></tr>

<tr><td><font color=red>SUBJECT</font></td><td>
<%
  set var [ssl clientcert subject]
  ns_puts "$var"
%>
</td></tr>

<tr><td><font color=red>ISSUER</font></td><td>
<%
  set var [ssl clientcert issuer]
  ns_puts "$var"
%>
</td></tr>

<tr><td><font color=red>NOT BEFORE</font></td><td>
<%=[ssl clientcert notbefore]%>
</td></tr>

<tr><td><font color=red>NOT AFTER</font></td><td>
<%=[ssl clientcert notafter]%>
</td></tr>

<tr><td><font color=red>SIGNATURE ALGORITHM</font></td><td>
<%=[ssl clientcert signature_algorithm]%>
</td></tr>

<tr><td><font color=red>KEY ALGORITHM</font></td><td>
<%=[ssl clientcert key_algorithm]%>
</td></tr>

<tr><td><font color=red>PEM Certificate</font></td><td>
<%=[ssl clientcert pem]%>
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















