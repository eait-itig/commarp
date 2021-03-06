# $OpenBSD$

.include <bsd.own.mk>

PROG=	commarp
SRCS=	commarp.c parse.y
SRCS+=	log.c
YFLAGS=
MAN=

LDADD=  -levent -lcrypto
DPADD=  ${LIBEVENT} ${LIBCRYPTO}

WARNINGS=Yes
DEBUG=-g

CFLAGS+=-I${.CURDIR}

BINDIR=/opt/local/sbin
MANDIR=/opt/local/share/man/man

.include <bsd.prog.mk>
