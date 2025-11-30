## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tinc

CLEANFILES = version_git.h

.PHONY: version-stamp
version-stamp:

version_git.h: version-stamp
	$(AM_V_GEN)echo >$@
	@-(cd $(srcdir) && git describe 2>/dev/null >/dev/null) && echo '#define GIT_DESCRIPTION "'`(cd $(srcdir) && git describe) | sed 's/release-//'`'"' >$@ ||:
${srcdir}/version.c: version_git.h

## Now a hack to appease some versions of BSD make that don't understand that "./foo" is the same as "foo".
if BSD
version.c: ${srcdir}/version.c
endif

# Stub implementations for legacy crypto (SPTPS/ECDSA/RSA no longer used)
stub_SOURCES = \
	stub/sptps_stub.c \
	stub/ecdsa_stub.c \
	stub/ecdh_stub.c \
	stub/rsa_stub.c \
	stub/ecdsagen_stub.c \
	stub/rsagen_stub.c

vless_SOURCES = \
	vless/vless.c vless/vless.h \
	vless/reality.c vless/reality.h \
	vless/dpi_evasion.c vless/dpi_evasion.h \
	vless/domain_fronting.c vless/domain_fronting.h \
	vless/multihop.c vless/multihop.h

# QUIC support disabled for VLESS-only build
# quic_SOURCES = \
#	quic/quic.c quic/quic.h \
#	quic/quic_transport.c quic/quic_transport.h \
#	quic/quic_connection.c \
#	quic/quic_packet.c \
#	quic/quic_meta.c \
#	quic/quic_migration.c \
#	quic/quic_maintenance.c \
#	quic/quic_internal.h \
#	quic/quic_reality.c quic/quic_reality.h \
#	quic/quic_fingerprint.c quic/quic_fingerprint.h

tincd_SOURCES = \
	address_cache.c address_cache.h \
	autoconnect.c autoconnect.h \
	buffer.c buffer.h \
	cipher.h \
	conf.c conf.h \
	connection.c connection.h \
	control.c control.h \
	control_common.h \
	crypto.h \
	device.h \
	digest.h \
	dropin.c dropin.h \
	dummy_device.c \
	ecdh.h \
	ecdsa.h \
	ecdsagen.h \
	edge.c edge.h \
	ethernet.h \
	event.c event.h \
	fd_device.c \
	graph.c graph.h \
	hash.c hash.h \
	hosts_json.c hosts_json.h \
	ifconfig_auto.c ifconfig_auto.h \
	invitation_server.c invitation_server.h \
	have.h \
	ipv4.h \
	ipv6.h \
	list.c list.h \
	logger.c logger.h \
	meta.c meta.h \
	multicast_device.c \
	names.c names.h \
	net.c net.h \
	net_packet.c \
	net_setup.c \
	net_socket.c \
	netutl.c netutl.h \
	node.c node.h \
	prf.h \
	process.c process.h \
	protocol.c protocol.h \
	protocol_auth.c \
	protocol_edge.c \
	protocol_key.c \
	protocol_misc.c \
	protocol_subnet.c \
	raw_socket_device.c \
	route.c route.h \
	rsa.h \
	rsagen.h \
	script.c script.h \
	splay_tree.c splay_tree.h \
	sptps.h \
	subnet.c subnet.h \
	subnet_parse.c \
	system.h \
	tincd.c \
	utils.c utils.h \
	xalloc.h \
	version.c version.h \
	$(stub_SOURCES) \
	$(vless_SOURCES)

tinc_SOURCES = \
	dropin.c dropin.h \
	fsck.c fsck.h \
	hash.c hash.h \
	hosts_json.c hosts_json.h \
	ifconfig.c ifconfig.h \
	info.c info.h \
	invitation.c invitation.h \
	invitation_client.c invitation_client.h \
	list.c list.h \
	names.c names.h \
	netutl.c netutl.h \
	script.c script.h \
	splay_tree.c splay_tree.h \
	sptps.h \
	subnet_parse.c subnet.h \
	tincctl.c tincctl.h \
	top.c top.h \
	utils.c utils.h \
	version.c version.h \
	$(stub_SOURCES)

## Conditionally compile device drivers

if !GETOPT
tincd_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
tinc_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
endif

if LINUX
tincd_SOURCES += linux/device.c
endif

if BSD
tincd_SOURCES += bsd/device.c
if TUNEMU
tincd_SOURCES += bsd/tunemu.c bsd/tunemu.h
endif
endif

if SOLARIS
tincd_SOURCES += solaris/device.c
endif

if MINGW
tincd_SOURCES += mingw/device.c mingw/common.h
endif

if UML
tincd_SOURCES += uml_device.c
endif

if VDE
tincd_SOURCES += vde_device.c
endif

if OPENSSL
tincd_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/prf.c
tinc_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/prf.c
else
if GCRYPT
tincd_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/prf.c
tinc_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/prf.c
else
tincd_SOURCES += \
	nolegacy/crypto.c \
	nolegacy/prf.c
tinc_SOURCES += \
	nolegacy/crypto.c \
	nolegacy/prf.c
endif
endif

if MINIUPNPC
tincd_SOURCES += upnp.h upnp.c
tincd_LDADD = $(MINIUPNPC_LIBS)
tincd_LDFLAGS = -pthread
endif

tinc_LDADD = $(READLINE_LIBS) $(CURSES_LIBS)

LIBS = @LIBS@ -lm $(CODE_COVERAGE_LIBS)

if TUNEMU
LIBS += -lpcap
endif

# QUIC support disabled for VLESS-only build
# LIBS += -L$(top_srcdir)/deps/quiche/target/release -lquiche

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DRUNSTATEDIR=\"$(runstatedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\" -iquote. $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)
