#
# The contents of this file are subject to the AOLserver Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://aolserver.com.
#
# Software distributed under the License is distributed on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
# the License for the specific language governing rights and limitations
# under the License.
#
# Alternatively, the contents of this file may be used under the terms
# of the GNU General Public License (the "GPL"), in which case the
# provisions of GPL are applicable instead of those above.  If you wish
# to allow use of your version of this file only under the terms of the
# GPL and not to allow others to use your version of this file under the
# License, indicate your decision by deleting the provisions above and
# replace them with the notice and other provisions required by the GPL.
# If you do not delete the provisions above, a recipient may use your
# version of this file under either the License or the GPL.
#
# Copyright (C) 2001-2003 Scott S. Goodwin
#
# Portions created by AOL are Copyright (C) 1999 America Online, Inc.  All
# Rights Reserved.
#
#
# $Header$
#

AOLSERVER ?= ../aolserver

ifndef OPENSSL

all:
	@echo "** "
	@echo "** OPENSSL variable not set."
	@echo "** nsopenssl will not be built."
	@echo "** "

install: all

clean:

else

#
# Version number used in release tags. Valid VERs are "1.1c", "2.1", 
# "2.2beta7". VER "1.1c" will be translated into "v1_1c" by this Makefile.
#
VER_ = $(subst .,_,$(VER))

MODNAME  = nsopenssl

LIB      = nsopenssl
LIBOBJS  = sslcontext.o ssl.o tclcmds.o x509.o
LIBLIBS  = -L$(OPENSSL)/lib -lssl -lcrypto 

MOD      = nsopenssl.so
MODOBJS  = nsopenssl.o
HDRS     = nsopenssl.h
MODLIBS  = -L$(OPENSSL)/lib -lssl -lcrypto

TCLMOD   = https.tcl

# Add static compilation ability, per grax3272
ifeq ($(STATIC),1)
	MODLIBS	= $(OPENSSL)/lib/libssl.a $(OPENSSL)/lib/libcrypto.a
endif

#
# Kerberos headers are included in case your OpenSSL library was built with
# Kerberos support. This is generally true on RedHat 9 and possibly Fedora
# Core. If OPENSSL_NO_KRB5 is define in <openssl/opensslconf.h> then OpenSSL
# *was not* compiled with Kerberos support.
#

CFLAGS   += -I$(OPENSSL)/include -I/usr/kerberos/include

INSTALL	= install-https.tcl

include  $(AOLSERVER)/include/Makefile.module

##
## Extra install targets.
##

install-https.tcl:
	$(INSTALL_SH) $(TCLMOD) $(INSTTCL)

.PHONY: install-https.tcl

#
# Help the poor developer
#
help:
	@echo "**" 
	@echo "** DEVELOPER HELP FOR THIS $(MODNAME)"
	@echo "**"
	@echo "** make tag VER=X.Y"
	@echo "**     Tags the module CVS code with the given tag."
	@echo "**     You can tag the CVS copy at any time, but follow the rules."
	@echo "**     VER must be of the form:"
	@echo "**         X.Y"
	@echo "**         X.YbetaN"
	@echo "**     You should browse CVS at SF to find the latest tag."
	@echo "**"
	@echo "** make file-release VER=X.Y"
	@echo "**     Checks out the code for the given tag from CVS."
	@echo "**     The result will be a releaseable tar.gz file of"
	@echo "**     the form: module-X.Y.tar.gz."
	@echo "**"

#
# Tag the code in CVS right now
#
tag:
	@if [ "$(VER)" = "" ]; then echo 1>&2 "VER must be set to version number!"; exit 1; fi
	cvs rtag v$(VER_) $(MODNAME)

#
# Create a distribution file release
#
file-release:
	@if [ "$(VER)" = "" ]; then echo 1>&2 "VER must be set to version number!"; exit 1; fi
	@echo "(Just hit the return key when prompted for CVS password)"
	cvs -d :pserver:anonymous@cvs.sf.net:/cvsroot/aolserver login
	cd /tmp && cvs -d :pserver:anonymous@cvs.sf.net:/cvsroot/aolserver co -rv$(VER_) -d$(MODNAME)-$(VER) $(MODNAME) && tar cf - $(MODNAME)-$(VER) | gzip -c > $(MODNAME)-$(VER).tar.gz
	echo "--- FILE RELEASE is: /tmp/$(MODNAME)-$(VER).tar.gz"

endif
