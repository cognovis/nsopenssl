# Create certificate authorities and certificates

# $Header$

# In progress -- figure out if openssl will create the subdirs specified in the ca1.conf file,
# or if I have to manually do that here.

CA1_ROOT     = ca1

MKDIR      = /bin/mkdir -p

ca1: ca1-dirs

ca1-dirs:
	@if [ ! -d $(CA1DIR) ]; then \
		$(MKDIR) $(CA1_ROOT); \
		$(MKDIR) $(CA1_CERTS); \
		$(MKDIR) $(CA1_CRL); \
		$(MKDIR) $(CA1DIR); \
	fi


# Create a Triple-DES, PEM-encode CA RSA private key
# WARNING!!! Note the insecure way we are creating the password!!!
#openssl genrsa -des3 -passout pass:noway -out ca1/ca1.key 1024

# Create a self-signed CA Certificate with the RSA key of the CA:
#openssl req -new -x509 -days 365 -config ca1.conf -passin pass:noway -key ca1/ca1.key -out ca1/ca1.crt


### END

# Take a look at the key in readable format
#openssl rsa -noout -text -in ca.key


# Take a look at the certificate in readable format
#openssl x509 -noout -text -in ca.crt
