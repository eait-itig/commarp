/*	*/

/*
 * Copyright (c) 2020 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This code was developed by Alex Wilson <alex@uq.edu.au> and David
 * Gwynne <dlg@uq.edu.au> as part of the Information Technology
 * Infrastructure Group for the Faculty of Engineering, Architecture
 * and Information Technology.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <net/bpf.h>

#include <arpa/inet.h> /* inet_ntoa */
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <err.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <paths.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <assert.h>
#include <stddef.h>

#include "commarp.h"
#include "log.h"

#define COMMARP_USER	"_commarp"
#define COMMARP_CONF	"/etc/commarp.conf"

struct ether_arp_pkt {
	struct ether_header		eap_ether;
	struct ether_arp		eap_arp;
} __packed;

/* i'm not a fan of struct icmp cos it's too big */
struct ping_hdr {
	uint8_t		ping_type;
	uint8_t		ping_code;
	uint16_t	ping_cksum;
	uint16_t	ping_id;
	uint16_t	ping_seq;
};

#define ETHER_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define ETHER_ARGS(_e)	(_e)[0], (_e)[1], (_e)[2], (_e)[3], (_e)[4], (_e)[5]
#define ETHER_ADDR_ARGS(_e) \
			ETHER_ARGS((_e)->ether_addr_octet)

#define streq(_a, _b)	(strcmp(_a, _b) == 0)

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ISSET
#define ISSET(_v, _m)	((_v) & (_m))
#endif

struct commarp;

struct commarp_iface {
	struct commarp		*if_ca;
	unsigned int		 if_index;
	char			 if_name[IF_NAMESIZE];
	struct ether_addr	 if_etheraddr;
	struct sockaddr_in	 if_addr;

	struct commarp_address_filter *
				 if_filters;

	struct event		 if_bpf_ev;
	uint8_t			*if_bpf_buf;
	unsigned int		 if_bpf_len;
	unsigned int		 if_bpf_cur;

	struct event		 if_ping_ev;
	uint16_t		 if_ping_seq;

	TAILQ_ENTRY(commarp_iface)
				 if_entry;

	uint64_t		 if_bpf_reads;
	uint64_t		 if_packets;
	uint64_t		 if_bpf_short;
	uint64_t		 if_ether_short;
	uint64_t		 if_arp_short;

	uint64_t		 if_bpf_fail;
	uint64_t		 if_arp_inval;
	uint64_t		 if_arp_filtered;
};

struct commarp {
	struct commarp_ifaces	 ca_ifaces;
	struct event		 ca_siginfo;

	uint16_t		 ca_ping_ident;
};

__dead void	 usage(void);
int		 rdaemon(int);

static void	 ifaces_get(struct commarp *, char *);
static void	 iface_bpf_open(struct commarp_iface *);
static void	 iface_bpf_read(int, short, void *);
static void	 iface_ping_open(struct commarp_iface *, int);
static void	 iface_ping_recv(int, short, void *);

static void	 commarp_siginfo(int, short, void *);

static uint32_t	 cksum_add(uint32_t, const void *, size_t);
static uint16_t	 cksum_fini(uint32_t);

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dv] [-f file] [-u user]\n",
	    __progname);

	exit(1);
}

int verbose = 0;

int
main(int argc, char *argv[])
{
	struct commarp commarp = {
		.ca_ifaces = TAILQ_HEAD_INITIALIZER(commarp.ca_ifaces),
	};
	struct commarp *ca = &commarp;
	struct commarp_iface *iface;

	const char *user = COMMARP_USER;
	char *filename = COMMARP_CONF;

	int debug = 0;
	int ch;

	struct passwd *pw;
	int devnull = -1;

	while ((ch = getopt(argc, argv, "df:u:v")) != -1) {
		switch (ch) {
		case 'd':
			debug = verbose = 1;
			break;
		case 'f':
			filename = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (geteuid() != 0)
		errx(1, "need root privileges");

	pw = getpwnam(user);
	if (pw == NULL)
		errx(1, "no %s user", user);

	ifaces_get(ca, filename);

	TAILQ_FOREACH(iface, &ca->ca_ifaces, if_entry) {
		iface->if_ca = ca;

		iface_bpf_open(iface);
		iface_ping_open(iface, -1);

		iface->if_bpf_buf = malloc(iface->if_bpf_len * 2);
		if (iface->if_bpf_buf == NULL)
			err(1, "BPF buffer");

		if (debug) {
			printf("%s address: " ETHER_FMT "\n",
			    iface->if_name,
			    ETHER_ADDR_ARGS(&iface->if_etheraddr));
		}
	}

	if (!debug) {
		extern char *__progname;

		devnull = open(_PATH_DEVNULL, O_RDWR, 0);
		if (devnull == -1)
			err(1, "%s", _PATH_DEVNULL);

		logger_syslog(__progname);
	}

	if (chroot(pw->pw_dir) == -1)
		err(1, "chroot %s", pw->pw_dir);
	if (chdir("/") == -1)
		err(1, "chdir %s", pw->pw_dir);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "can't drop privileges");

	if (!debug && rdaemon(devnull) == -1)
		err(1, "unable to daemonize");

	ca->ca_ping_ident = htons(arc4random());

	event_init();

	TAILQ_FOREACH(iface, &ca->ca_ifaces, if_entry) {
		event_set(&iface->if_bpf_ev, iface->if_bpf_ev.ev_fd,
		    EV_READ | EV_PERSIST, iface_bpf_read, iface);
		event_add(&iface->if_bpf_ev, NULL);

		event_set(&iface->if_ping_ev, iface->if_ping_ev.ev_fd,
		    EV_READ | EV_PERSIST, iface_ping_recv, iface);
		event_add(&iface->if_ping_ev, NULL);
	}

	signal_set(&ca->ca_siginfo, SIGINFO, commarp_siginfo, ca);
	signal_add(&ca->ca_siginfo, NULL);

	event_dispatch();

	return (0);
}

void
commarp_siginfo(int sig, short events, void *arg)
{
	struct commarp *ca = arg;
	struct commarp_iface *iface = arg;

	TAILQ_FOREACH(iface, &ca->ca_ifaces, if_entry) {
		linfo("iface:%s bpf_reads:%llu packets:%llu bpf_short:%llu "
		    "ether_short:%llu arp_short:%llu",
		    iface->if_name, iface->if_bpf_reads, iface->if_packets,
		    iface->if_bpf_short, iface->if_ether_short,
		    iface->if_arp_short);
	}
}

#if 0
static void
hexdump(const void *d, size_t datalen)
{
	const uint8_t *data = d;
	size_t i, j = 0;

	for (i = 0; i < datalen; i += j) {
		printf("%4zu: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
			printf("%02x ", data[i + j]);
		while (j++ < 16)
			printf("   ");
		printf("|");
		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(isprint(data[i + j]) ? data[i + j] : '.');
		printf("|\n");
	}
}
#endif

void
commarp_iface_get(struct commarp_ifaces *ifaces, struct ifaddrs *ifas,
    const char *ifname, struct commarp_address_filter *filters)
{
	struct ifaddrs *ifa;
	struct sockaddr_in *sin;
	struct sockaddr_dl *sdl;
	struct if_data *ifi;

	struct commarp_iface *iface;

	iface = malloc(sizeof(*iface));
	if (iface == NULL)
		err(1, "iface alloc");

	memset(iface, 0, sizeof(*iface));

	for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
		if (ISSET(ifa->ifa_flags, IFF_LOOPBACK) ||
		    ISSET(ifa->ifa_flags, IFF_POINTOPOINT))
			continue;

		if (!streq(ifa->ifa_name, ifname))
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			ifi = (struct if_data *)ifa->ifa_data;
			if (ifi->ifi_type != IFT_ETHER &&
			    ifi->ifi_type != IFT_CARP) {
				errx(1, "interface %s: unsupported type",
				    ifname);
			}

			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl->sdl_alen != sizeof(iface->if_etheraddr)) {
				errx(1, "interface %s: "
				    "unexpected hardware address", ifname);
			}

			iface->if_index = sdl->sdl_index;
			memcpy(&iface->if_etheraddr, LLADDR(sdl),
			    sdl->sdl_alen);

			break;

		case AF_INET:
			if (iface->if_addr.sin_family == AF_INET)
				break;

			sin = (struct sockaddr_in *)ifa->ifa_addr;
			iface->if_addr = *sin;
			break;
		}
	}

	if (iface->if_index == 0)
		errx(1, "interface %s: not found", ifname);
	if (iface->if_addr.sin_family != AF_INET)
		errx(1, "interface %s: no IP address", ifname);

	if (strlcpy(iface->if_name, ifname, sizeof(iface->if_name)) >=
	    sizeof(iface->if_name))
		errx(1, "ifname too long");

	iface->if_filters = filters;

	TAILQ_INSERT_TAIL(ifaces, iface, if_entry);
}

void
ifaces_get(struct commarp *ca, char *filename)
{
	struct ifaddrs *ifas;

	if (getifaddrs(&ifas) == -1)
		err(1, "getifaddrs");

	if (parse_config(&ca->ca_ifaces, ifas, filename) == -1)
		exit(1);

	freeifaddrs(ifas);
}

/*
 * Packet filter program: 'ip and udp and dst port SERVER_PORT'
 */
/* const */ struct bpf_insn dhcp_bpf_rfilter[] = {
	/* Make sure this is an ARP packet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	    offsetof(struct ether_arp_pkt, eap_ether.ether_type)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 7),

	/* Make sure this is an ARP request */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	    offsetof(struct ether_arp_pkt, eap_arp.arp_op)),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, ARPOP_REQUEST, 0, 5),

	/* Make sure it's for Ethernet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	    offsetof(struct ether_arp_pkt, eap_arp.arp_hrd)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 0, 3),

	/* Make sure it wants an IP address... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	    offsetof(struct ether_arp_pkt, eap_arp.arp_pro)),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, ETHERTYPE_IP, 0, 1),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

	/* Otherwise, drop it. */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

static void
iface_bpf_open(struct commarp_iface *iface)
{
	struct ifreq ifr;
	struct bpf_version v;
	struct bpf_program p;
	unsigned int dirfilt = BPF_DIRECTION_OUT;
	int opt;
	int fd;

	fd = open("/dev/bpf", O_RDWR|O_NONBLOCK);
	if (fd == -1)
		err(1, "/dev/bpf");

	if (ioctl(fd, BIOCVERSION, &v) == -1)
		err(1, "get BPF version");

	if (v.bv_major != BPF_MAJOR_VERSION || v.bv_minor < BPF_MINOR_VERSION)
		errx(1, "kerel BPF version is too high, recompile!");

	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, iface->if_name, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		errx(1, "interface name is too long");

	if (ioctl(fd, BIOCSETIF, &ifr) == -1)
		err(1, "unable to set BPF interface to %s", iface->if_name);

	opt = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &opt) == -1)
		err(1, "unable to set BPF immediate mode");

	if (ioctl(fd, BIOCSDIRFILT, &dirfilt) == -1)
		err(1, "unable to set BPF direction filter");

	if (ioctl(fd, BIOCGBLEN, &opt) == -1)
		err(1, "unable to get BPF buffer length");

	if ((size_t)opt < sizeof(struct ether_arp_pkt)) {
		errx(1, "BPF buffer length is too short: %d < %zu",
		    opt, sizeof(struct ether_arp_pkt));
	}

	p.bf_len = nitems(dhcp_bpf_rfilter);
	p.bf_insns = dhcp_bpf_rfilter;

	if (ioctl(fd, BIOCSETF, &p) == -1)
		err(1, "unable to set BPF read filter");

	if (ioctl(fd, BIOCLOCK) == -1)
		err(1, "unable to lock BPF descriptor");

	iface->if_bpf_ev.ev_fd = fd;
	iface->if_bpf_len = opt;
	iface->if_bpf_cur = 0;
}

static int
commarp_filter(const struct commarp_address_filter *filters,
    struct commarp_address caddr)
{
	const struct commarp_address_filter *f;

	for (f = filters; f != NULL; f = f->next) {
		if (caddr.addr >= f->addresses.min.addr &&
		    caddr.addr <= f->addresses.max.addr)
			return (f->filter);
	}

	return (1);
}

static void
arp_pkt_input(struct commarp_iface *iface, void *pkt, size_t len)
{
	struct ether_arp_pkt *eap;
	struct ether_arp *arp;
	struct ping_hdr ping;
	uint32_t cksum;

	struct commarp_address_filter *filter;

	struct sockaddr_in sin;
	struct msghdr msg;
	struct iovec iov[2];

	iface->if_packets++;

	if (len < sizeof(eap->eap_ether)) {
		iface->if_ether_short++;
		return;
	}
	if (len < sizeof(*eap)) {
		iface->if_arp_short++;
		return;
	}

	eap = pkt;
	arp = &eap->eap_arp;

	/* to be sure to be sure */
	if (eap->eap_ether.ether_type != htons(ETHERTYPE_ARP)) {
		iface->if_bpf_fail++;
		return;
	}
	if (arp->arp_hrd != htons(ARPHRD_ETHER)) {
		iface->if_bpf_fail++;
		return;
	}
	if (arp->arp_pro != htons(ETHERTYPE_IP)) {
		iface->if_bpf_fail++;
		return;
	}
	if (arp->arp_hln != sizeof(arp->arp_sha)) {
		iface->if_arp_inval++;
		return;
	}
	if (arp->arp_pln != sizeof(arp->arp_spa)) {
		iface->if_arp_inval++;
		return;
	}
	if (arp->arp_op != htons(ARPOP_REQUEST)) {
		iface->if_bpf_fail++;
		return;
	}
	if (ETHER_IS_BROADCAST(arp->arp_sha)) {
		iface->if_arp_inval++;
		return;
	}

	filter = iface->if_filters;
	if (filter) {
		struct commarp_address spa;
		struct commarp_address tpa;

		commarp_bytes_to_address(&spa, arp->arp_spa);
		commarp_bytes_to_address(&tpa, arp->arp_tpa);
		if (commarp_filter(filter, spa) ||
		    commarp_filter(filter, tpa)) {
			iface->if_arp_filtered++;
			return;
		}
	}

	memset(&ping, 0, sizeof(ping));
	ping.ping_type = ICMP_ECHO;
	ping.ping_seq = htons(iface->if_ping_seq++);
	ping.ping_id = iface->if_ca->ca_ping_ident;

	cksum = cksum_add(0, &ping, sizeof(ping));
	cksum = cksum_add(cksum, arp, sizeof(*arp));
	ping.ping_cksum = cksum_fini(cksum);

	iov[0].iov_base = &ping;
	iov[0].iov_len = sizeof(ping);
	iov[1].iov_base = arp;
	iov[1].iov_len = sizeof(*arp);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	memcpy(&sin.sin_addr, arp->arp_tpa, sizeof(sin.sin_addr));

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sin;
	msg.msg_namelen = sizeof(sin);
	msg.msg_iov = iov;
	msg.msg_iovlen = nitems(iov);

	if (sendmsg(EVENT_FD(&iface->if_ping_ev), &msg, 0) == -1)
		lwarn("%s ping", iface->if_name);
}

static void
iface_bpf_read(int fd, short events, void *arg)
{
	struct commarp_iface *iface = arg;
	struct bpf_hdr hdr;
	size_t len, bpflen;
	ssize_t rv;
	uint8_t *buf = iface->if_bpf_buf;

	rv = read(fd, buf + iface->if_bpf_cur, iface->if_bpf_len);
	switch (rv) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			break;
		default:
			lerr(1, "%s bpf read", iface->if_name);
			/* NOTREACHED */
		}
		return;
	case 0:
		lerrx(0, "%s BPF has closed", iface->if_name);
		/* NOTREACHED */
	default:
		break;
	}

	iface->if_bpf_reads++;

	len = iface->if_bpf_cur + rv;

	while (len >= sizeof(hdr)) {
		/* Copy out a bpf header... */
		memcpy(&hdr, buf, sizeof(hdr));
		bpflen = hdr.bh_hdrlen + hdr.bh_caplen;

		/*
		 * If the bpf header plus data doesn't fit in what's
		 * left of the buffer, stick head in sand yet again...
		 */
		if (bpflen > len)
			break;

		/*
		 * If the captured data wasn't the whole packet, or if
		 * the packet won't fit in the input buffer, all we can
		 * do is skip it.
		 */
		if (hdr.bh_caplen < hdr.bh_datalen)
			iface->if_bpf_short++;
		else {
			arp_pkt_input(iface,
			    buf + hdr.bh_hdrlen, hdr.bh_datalen);
		}

		bpflen = BPF_WORDALIGN(bpflen);
		if (len <= bpflen) {
			/* Short circuit if everything is consumed */
			iface->if_bpf_cur = 0;
			return;
		}

		/* Move the loop to the next packet */
		buf += bpflen;
		len -= bpflen;
	}

	if (len > iface->if_bpf_len) {
		lerrx(1, "len %zu > bpf len %u (iface=%p)", len,
		    iface->if_bpf_len, iface);
	}

	iface->if_bpf_cur = len;
	if (len && iface->if_bpf_buf != buf)
		memmove(iface->if_bpf_buf, buf, len);
}

static void
iface_ping_open(struct commarp_iface *iface, int ttl)
{
	int s;

	s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (s == -1)
		err(1, "socket");

	if (bind(s, (struct sockaddr *)&iface->if_addr,
	    sizeof(iface->if_addr)) == -1)
		err(1, "interface %s bind", iface->if_name);

	if (ttl != -1) {
		if (setsockopt(s, IPPROTO_IP, IP_TTL,
		    &ttl, sizeof(ttl)) == -1)
			err(1, "interface %s set ttl %d", iface->if_name, ttl);
	}

	iface->if_ping_ev.ev_fd = s;
}

static void
iface_arp_reply(struct commarp_iface *iface, const struct ether_arp *req)
{
	struct ether_arp_pkt eap;
	struct ether_header *eh = &eap.eap_ether;
	struct ether_arp *arp = &eap.eap_arp;

	memset(&eap, 0, sizeof(eap));

	memcpy(eh->ether_shost, &iface->if_etheraddr,
	    sizeof(eh->ether_shost));
	memcpy(eh->ether_dhost, &req->arp_sha,
	    sizeof(eh->ether_dhost));
	eh->ether_type = htons(ETHERTYPE_ARP);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = sizeof(req->arp_sha);
	arp->arp_pln = sizeof(req->arp_spa);
	arp->arp_op = htons(ARPOP_REPLY);

	memcpy(arp->arp_sha, &iface->if_etheraddr, sizeof(arp->arp_sha));
	memcpy(arp->arp_spa, req->arp_tpa, sizeof(arp->arp_spa));

	memcpy(arp->arp_tha, req->arp_sha, sizeof(arp->arp_tha));
	memcpy(arp->arp_tpa, req->arp_spa, sizeof(arp->arp_tpa));

	if (write(EVENT_FD(&iface->if_bpf_ev), &eap, sizeof(eap)) == -1)
		lwarn("%s reply", iface->if_name);
}

static void
iface_ping_recv(int fd, short events, void *arg)
{
	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	struct commarp_iface *iface = arg;
	struct ip *ip;
	struct ping_hdr *ping;
	struct ether_arp *arp;
	uint8_t bytes[(0xf << 2) + sizeof(*ping) + sizeof(*arp)];
	unsigned int iphlen;
	ssize_t rv, hlen;

	rv = recvfrom(fd, bytes, sizeof(bytes), 0,
	    (struct sockaddr *)&sin, &sinlen);
	if (rv == -1)
		lwarn("%s ping recv", iface->if_name);

	iphlen = sizeof(*ip);
	if (rv < iphlen) {
		/* iface->if_ping_ip_short++ */
		return;
	}

	ip = (struct ip *)bytes;
	iphlen = ip->ip_hl << 2;
	if (rv < iphlen) {
		/* iface->if_ping_ip_short++ */
		return;
	}

	hlen = iphlen + sizeof(*ping);
	if (rv < hlen) {
		/* iface->if_ping_short++ */
		return;
	}

	ping = (struct ping_hdr *)(bytes + iphlen);
	if (ping->ping_type != ICMP_ECHOREPLY)
		return;
	if (ping->ping_id != iface->if_ca->ca_ping_ident)
		return;
	if (cksum_fini(cksum_add(0, ping, rv - iphlen)) != htons(0)) {
		/* iface->if_ping_cksum++ */
		return;
	}

	arp = (struct ether_arp *)(bytes + hlen);
	hlen += sizeof(*arp);
	if (rv < hlen) {
		/* iface->if_ping_arp_short++ */
		return;
	}

	iface_arp_reply(iface, arp);
}

void
commarp_inaddr_to_address(struct commarp_address *caddr,
    const struct in_addr *iaddr)
{
	caddr->addr = ntohl(iaddr->s_addr);
}

void
commarp_bytes_to_address(struct commarp_address *caddr, const void *bytes)
{
	const uint8_t *baddr = bytes;

	caddr->addr = (uint32_t)baddr[0] << 24 | (uint32_t)baddr[1] << 16 |
	    (uint32_t)baddr[2] << 8 | (uint32_t)baddr[3] << 0;
}

static uint32_t
cksum_add(uint32_t sum, const void *buf, size_t len)
{
	const uint16_t *words = buf;

	while (len > 1) {
		sum += *words++;
		len -= sizeof(*words);
	}

	if (len == 1) {
		const uint8_t *bytes = (const uint8_t *)words;
		sum += (uint16_t)*bytes << 8;
	}

	return (sum);
}

static uint16_t
cksum_fini(uint32_t sum)
{
	uint16_t cksum;

	cksum = sum;
	cksum += sum >> 16;

	return (~cksum);
}

/* daemon(3) clone, intended to be used in a "r"estricted environment */
int
rdaemon(int devnull)
{
	if (devnull == -1) {
		errno = EBADF;
		return (-1);
	}
	if (fcntl(devnull, F_GETFL) == -1)
		return (-1);

	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() == -1)
		return (-1);

	(void)dup2(devnull, STDIN_FILENO);
	(void)dup2(devnull, STDOUT_FILENO);
	(void)dup2(devnull, STDERR_FILENO);
	if (devnull > 2)
		(void)close(devnull);

	return (0);
}
