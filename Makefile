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
NSHOME   =  ../aolserver

#
# Override default rules if library not available
#
ifndef OPENSSL
all:
	@echo "** "
	@echo "** OPNESSL variable not set."
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
OBJS     =  nsopenssl.o

#
# Header files in THIS directory (included with your module)
#
HDRS     =  

#
# Extra libraries required by your module (-L and -l go here)
#
MODLIBS  =  -L$(OPENSSL)/lib -lssl -lcrypto

#
# Compiler flags required by your module (-I for external headers goes here)
#
CFLAGS   =  -I$(OPENSSL)/include


include  $(NSHOME)/include/Makefile.module

endif

