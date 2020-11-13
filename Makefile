# $OpenBSD$

.include <bsd.own.mk>

PROG=	commarp
SRCS=	commarp.c
SRCS+=	log.c

MAN=

LDADD=  -levent
DPADD=  ${LIBEVENT}

WARNINGS=Yes
DEBUG=-g

BINDIR=/opt/local/sbin
MANDIR=/opt/local/share/man/man

.include <bsd.prog.mk>
