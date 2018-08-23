all:
	(cd libnl ;./autogen.sh;./configure --enable-shared=no --enable-static=yes;make)
clean:
	(cd libnl ; if [ -f Makefile ] ; then make distclean;fi;)
