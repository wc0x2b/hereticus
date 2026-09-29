/* What expat's own configure step writes, for the builds that
 * fixtures/backports.sh makes. The options are the ones OpenWrt builds
 * expat with. */
#ifndef EXPAT_CONFIG_H
#define EXPAT_CONFIG_H

/* One build script serves both byte orders, so the compiler says which. */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define BYTEORDER 4321
#else
#  define BYTEORDER 1234
#endif

#define XML_CONTEXT_BYTES 1024
#define XML_DTD 1
#define XML_NS 1
/* The entropy source, for the hash salt. */
#define XML_DEV_URANDOM 1

#endif
