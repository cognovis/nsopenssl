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
HDRS     =  nsopenssl.h tclcmds.h config.h thread.h

# Client certificate verification (experimental)
ifdef VERIFY_CLIENT
    CFLAGS += -DVERIFY_CLIENT -DTCL
endif

ifdef BSAFE
    MODLIBS  =  -L$(OPENSSL)/lib -L$(BSAFE)/lib -lssl -lcrypto \
	-lBSAFEglue -lcrypto -lbsafe -lBSAFEglue
else
    MODLIBS  =  -L$(OPENSSL)/lib -lssl -lcrypto 
endif

CFLAGS   +=  -I$(OPENSSL)/include

#
# If you compiled OpenSSL without rc2, rc4, rc5 and idea, then use this instead
#
#CFLAGS   +=  -I$(OPENSSL)/include -DNO_RC2 -DNO_RC4 -DNO_RC5 -DNO_IDEA 

include  $(NSHOME)/include/Makefile.module

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

