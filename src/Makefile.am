lib_LTLIBRARIES = libddns.la
libddns_la_SOURCES = \
	ddns.c \
	http.c \
	base64.c \
	dyndns2.c

noinst_HEADERS = \
	base64.h \
	debug.h \
	http.h


AM_CPPFLAGS = @EXTRA_DEFINES@
libddns_la_includedir = $(includedir)/ddns
libddns_la_include_HEADERS = \
	$(top_srcdir)/include/ddns/ddns.h

libddns_la_CPPFLAGS = -I$(top_srcdir)/include $(CSOCKET_INCLUDES)
libddns_la_LDFLAGS = $(CSOCKET_LDFLAGS) $(CSOCKET_LIBS)
libddns_la_LIBADD = -lcsocket

if HAVE_OPENSSL
libddns_la_SOURCES += \
	freedns.c
libddns_la_CPPFLAGS += $(OPENSSL_INCLUDES)
libddns_la_LDFLAGS += $(OPENSSL_LDFLAGS)
libddns_la_LIBADD += $(OPENSSL_LIBS)
if OS_MACOSX
libddns_la_CFLAGS = -Wno-deprecated-declarations
endif
endif


bin_PROGRAMS = ddnsclient http_test

ddnsclient_SOURCES = ddnsclient.c
ddnsclient_CPPFLAGS = -I$(top_srcdir)/include $(EXTRA_DEFINES)
ddnsclient_LDFLAGS = -L$(top_srcdir)/src -lddns


http_test_SOURCES = http.c
http_test_CFLAGS = -DENABLE_TEST
http_test_CPPFLAGS = -I$(top_srcdir)/include $(EXTRA_DEFINES)
http_test_LDFLAGS = -L$(top_srcdir)/src -lddns


clean-local:
	rm -f *~
