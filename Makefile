#
# $Header$
#
# nsopenssl --
#
#      SSLv2, SSLv3, TLSv1 module using OpenSSL.
#

# XXX AOLserver 3.x defines this, but AOLserver 4.x uses the install binary
# instead. We'll need to update all the modules to use install
CP = /bin/cp -fp

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

# Add static compilation ability, per grax3272
#MODLIBS  =  -L$(OPENSSL)/lib ../openssl-0.9.6g/libssl.a ../openssl-0.9.6g/libcrypto.a#-lssl -lcrypto

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

