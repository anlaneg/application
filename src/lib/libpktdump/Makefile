all:
	(cd tcpdump;./do.sh)
clean:
	(cd tcpdump;if [ -f Makefile ] ; then make distclean; fi ;\
      cd ../libpcap;if [ -f Makefile ] ; then make distclean; fi ;)
