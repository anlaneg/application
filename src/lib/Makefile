all:libnl-build libevent-build liburcu-build
clean:libnl-clean libevent-clean liburcu-clean


libnl-build:
	(cd libnl ; if [ ! -f Makefile ] ; then ./autogen.sh; ./configure --enable-shared=no --enable-static=yes; fi; make)
libnl-clean:
	(cd libnl ; if [   -f Makefile ] ; then make distclean; fi; )

libevent-build:
	(cd libevent ; if [ ! -f Makefile ] ; then ./autogen.sh ; ./configure --enable-shared=no --enable-static-yes; fi; make)
libevent-clean:
	(cd libevent ; if [ -f Makefile ] ; then make distclean ; fi; )

liburcu-build:
	(cd liburcu ; if [ ! -f Makefile ] ; then ./bootstrap ; CFLAGS="-m64 -g -O2" ./configure --enable-static --enable-shared=no ; make; fi; )
liburcu-clean:
	(cd liburcu ; if [ -f Makefile ] ; then make distclean ; fi ; )
