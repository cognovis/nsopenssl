#
# $Header$
#
# nsopenssl --
#
#      SSLv2, SSLv3, TLSv1 module using OpenSSL.
#

ifdef INST
NSHOME ?= $(INST)
else
NSHOME ?= ../aolserver
endif

#
# Version number used in release tags. Valid VERs are "1.1c", "2.1", 
# "2.2beta7". VER "1.1c" will be translated into "v1_1c" by this Makefile.
#
VER_ = $(subst .,_,$(VER))

#
# Module name
#
MOD      =  nsopenssl.so

#
# Objects to build
#
OBJS     =  nsopenssl.o config.o init.o ssl.o thread.o tclcmds.o

#
# Header files in THIS directory (included with your module)
#
HDRS     =  nsopenssl.h tclcmds.h config.h thread.h

#
# Extra libraries required by your module (-L and -l go here)
#
ifdef BSAFE
    MODLIBS  =  -L$(OPENSSL)/lib -L$(BSAFE)/lib -lssl -lcrypto \
                -lBSAFEglue -lcrypto -lbsafe -lBSAFEglue
else
    MODLIBS  =  -L$(OPENSSL)/lib -lssl -lcrypto 
endif

#
# Compiler flags required by your module (-I for external headers goes here)
#
CFLAGS   +=  -I$(OPENSSL)/include

#
# Tcl modules to install
#
TCLMOD   =  https.tcl

#
# The common Makefile defined by AOLserver for making modules
#
include  $(NSHOME)/include/Makefile.module

#
# Create a tagged release. This moves the 'stable' tag to coincide with the v$(VER_) tag.
#
tag-release:
	@if [ "$$VER" = "" ]; then echo 1>&2 "VER must be set to version number!"; exit 1; fi
	cvs rtag -r stable v$(VER_) nsopenssl

#
# Create a tagged release (force it)
#
tag-release-force:
	@if [ "$$VER" = "" ]; then echo 1>&2 "VER must be set to version number!"; exit 1; fi
	cvs rtag -F -r stable v$(VER_) nsopenssl

#
# Create a distribution file release
#
file-release:
	@if [ "$$VER" = "" ]; then echo 1>&2 "VER must be set to version number!"; exit 1; fi
	rm -rf work
	mkdir work
	cd work && cvs -d :pserver:anonymous@cvs.aolserver.sourceforge.net:/cvsroot/aolserver co -r v$(VER_) nsopenssl
	mv work/nsopenssl work/nsopenssl-$(VER)
	( cd work && tar cvf - nsopenssl-$(VER) ) | gzip -9 > nsopenssl-$(VER).tar.gz
	rm -rf work

# XXX alter this to work with sed or tcl instead of perl
# perl -pi -e 's/\@VER\@/$(VER)/g' work/nscache/index.html work/nscache/tclcache.c

#
# Check to see that the OPENSSL variable has been set
#
.PHONY: check-env
nsopenssl.h: check-env
check-env:
	@if [ "$(OPENSSL)" = "" ]; then \
	    echo "** "; \
	    echo "** OPENSSL variable not set."; \
	    echo "** nsopenssl.so will not be built."; \
	    echo "** Usage: make OPENSSL=/path/to/openssl"; \
	    echo "** Usage: make install OPENSSL=/path/to/openssl INST=/path/to/aolserver"; \
	    echo "** "; \
	    exit 1; \
	fi

#
# This overrides the install directive in $(NSHOME)/include/Makefile.module because we
# have a Tcl module (https.tcl) to install as well.
#
install: all
	$(RM) $(INSTBIN)/$(MOD)
	$(CP) $(MOD) $(INSTBIN)
	$(MKDIR) $(INSTTCL)
	$(CP) $(TCLMOD) $(INSTTCL)

## TEST FRAMEWORK (under development)  ####################################################

#
# Install test code
#
TESTNSD = \
	nsd.tcl

TESTMOD =

#TESTMOD = \
#	server1-cert.pem \
#	server1-key.pem \
#	server1-key-unsecure.pem \
#	client1-cert.pem \
#	client1-key.pem \
#	client1-key-unsecure.pem \
#	server-cafile.pem

TESTTCLMOD = \
	ns_openssl_sockcallback.tcl \
	ns_openssl_socklistencallback.tcl \
	ns_openssl_socklisten.tcl \
	ns_openssl_socknread.tcl \
	ns_openssl_sockopen.tcl

TESTPAG = \
	index.adp

install-tests: install ca
	@if [ ! -d "$(INST)/servers/test" ]; then \
		echo "** $(CP) -r $(INST)/servers/server1 $(INST)/servers/test;  $(MKDIR)"; \
		$(CP) -r $(INST)/servers/server1 $(INST)/servers/test; \
	fi

	@if [ -n "$(TESTNSD)" ]; then \
		$(MKDIR) $(INST)/tests; \
		for i in $(TESTNSD); do \
			$(CP) tests/$$i $(INST)/tests/nsopenssl.tcl; \
		done \
	fi

	@if [ -n "$(TESTMOD)" ]; then \
		$(MKDIR) $(INST)/servers/test/modules/nsopenssl; \
		for i in $(TESTMOD); do \
			$(CP) tests/$$i $(INST)/servers/test/modules/nsopenssl; \
		done \
	fi

	@if [ -n "$(TESTTCLMOD)" ]; then \
		$(MKDIR) $(INST)/servers/test/modules/tcl/nsopenssl; \
		for i in $(TESTTCLMOD); do \
			$(CP) tests/$$i $(INST)/servers/test/modules/tcl/nsopenssl; \
		done \
	fi

	@if [ -n "$(TESTPAG)" ]; then \
		$(MKDIR) $(INST)/servers/test/pages/nsopenssl; \
		for i in $(TESTPAG); do \
			$(CP) tests/$$i $(INST)/servers/test/pages/nsopenssl; \
		done \
	fi

	@if [ ! -d "ca/ca1" ]; then \
		cd ca; \
		$(MAKE) ca1; \
	fi

## NOTES #################################################################################


# Solaris users *might* need the following, 
# but you'll need to modify it to point to where 
# your libgcc.a lives. Replace the MODLIBS above with
# this:
#
#   MODLIBS  =  -L$(OPENSSL)/lib -lssl -lcrypto \
#   -L/usr/local/products/gcc-2.95/lib/gcc-lib/sparc-sun-solaris2.5.1/2.95 -lgcc


# For development purposes, put the GCCOPT above somewhere
# to turn off 'no-unused' so gcc will report unused funcs
# and variables.
#
#   GCCOPT       =   $(GCCOPTIMIZE) -fPIC -Wall

