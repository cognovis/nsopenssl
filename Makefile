#
# $Header$
#
# nsopenssl --
#
#      SSL v3 module using OpenSSL.
#

ifdef INST
NSHOME ?= $(INST)
else
NSHOME ?= ../aolserver
endif

MOD      =  nsopenssl.so
OBJS     =  nsopenssl.o config.o init.o ssl.o thread.o tclcmds.o
#tclsock.o sslsock.o
# sslcli.o
HDRS     =  nsopenssl.h tclcmds.h config.h thread.h

# This will not work for OpenSSL 0.9.6 or above
ifdef BSAFE
    MODLIBS  =  -L$(OPENSSL)/lib -L$(BSAFE)/lib -lssl -lcrypto \
	-lBSAFEglue -lcrypto -lbsafe -lBSAFEglue
else
    MODLIBS  =  -L$(OPENSSL)/lib -lssl -lcrypto 
# NOTE!!! Solaris users *might* need the following, but you'll need to modify it to point to where your libgcc.a sits:
#    MODLIBS  =  -L$(OPENSSL)/lib -lssl -lcrypto -L/usr/local/products/gcc-2.95/lib/gcc-lib/sparc-sun-solaris2.5.1/2.95 -lgcc

endif

CFLAGS   +=  -I$(OPENSSL)/include

#
# If you compiled OpenSSL without rc2, rc4, rc5 and idea, then use this instead
#
#CFLAGS   +=  -I$(OPENSSL)/include -DNO_RC2 -DNO_RC4 -DNO_RC5 -DNO_IDEA 

include  $(NSHOME)/include/Makefile.module
# Override AOLserver's gcc options - use this to turn off -Wno-unused to ident unused funcs, vars etc.
#GCCOPT       =   $(GCCOPTIMIZE) -fPIC -Wall

# Extra stuff to make sure that OPENSSL is set.

nsopenssl.h: check-env

.PHONY: check-env
check-env:
	@if [ "$(OPENSSL)" = "" ]; then \
	    echo "** "; \
	    echo "** OPENSSL variable not set."; \
	    echo "** nsopenssl.so will not be built."; \
	    echo "** "; \
	    exit 1; \
	fi

