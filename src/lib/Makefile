all:libnl-build libevent-build
clean:libnl-clean libevent-clean


libnl-build:
	(cd libnl ; if [ ! -f Makefile ] ; then ./autogen.sh; ./configure --enable-shared=no --enable-static=yes; fi; make)
libnl-clean:
	(cd libnl ; if [   -f Makefile ] ; then make distclean; fi; )

libevent-build:
	(cd libevent ; if [ ! -f Makefile ] ; then ./autogen.sh ; ./configure --enable-shared=no --enable-static-yes; fi; make)
libevent-clean:
	(cd libevent ; if [ -f Makefile ] ; then make distclean ; fi; )
	
