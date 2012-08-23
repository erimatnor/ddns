lib_LTLIBRARIES = libddns.la
libddns_la_SOURCES = \
	ddns.c \
	dyndns2.c

libddns_la_includedir = $(includedir)/ddns
libddns_la_include_HEADERS = \
	$(top_srcdir)/include/ddns/ddns.h
libddns_la_CPPFLAGS = -I$(top_srcdir)/include $(CSOCKET_INCLUDES)
libddns_la_LDFLAGS = $(CSOCKET_LDFLAGS) $(CSOCKET_LIBS)
libddns_la_LIBADD = -lcsocket

clean-local:
	rm -f *~
