#
# $Header$
#
# nsopenssl --
#
#      SSL v3 module using OpenSSL.
#

#
# AOLserver's location
#
#  Since your module probably doesn't live inside the "aolserver"
#  directory, you can tell make where to find aolserver.
#
#NSHOME   =  /home/user/cvs/aolserver
#NSHOME   =  ../aolserver
NSHOME   = /src/aolserver/aolserver3_1

#
# Override default rules if library not available
#
ifndef OPENSSL
all:
	@echo "** "
	@echo "** OPENSSL variable not set."
	@echo "** nsopenssl.so will not be built."
	@echo "** "
install:   all
clean:
	$(RM) *.so *.o *.a *~ TAGS core so_locations
clobber:   clean
distclean: clean

else

#
# Module name
#
MOD      =  nsopenssl.so

#
# Objects to build
#
OBJS     =  cache.o sock.o nsopenssl.o tclcmds.o

#
# Header files in THIS directory (included with your module)
#
HDRS     =  nsopenssl.h tclcmds.h

# Client certificate verification (experimental)
ifdef VERIFY_CLIENT
EXTRA = -DVERIFY_CLIENT -DTCL
endif

#
# Extra libraries required by your module (-L and -l go here)
#
ifndef BSAFE
MODLIBS  =  -L$(OPENSSL)/lib -lssl -lcrypto 
else
MODLIBS  =  -L$(OPENSSL)/lib -L$(BSAFE)/lib -lssl -lcrypto -lBSAFEglue -lcrypto -lbsafe -lBSAFEglue
endif

#
# Compiler flags required by your module (-I for external headers goes here)
#
CFLAGS   =  -I$(OPENSSL)/include $(EXTRA)

#
# If you compiled OpenSSL without rc2, rc4, rc5 and idea, then use this instead
#
#CFLAGS   =  -I$(OPENSSL)/include -DNO_RC2 -DNO_RC4 -DNO_RC5 -DNO_IDEA 


include  $(NSHOME)/include/Makefile.module

endif

