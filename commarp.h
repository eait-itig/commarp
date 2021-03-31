/*	*/

/*
 * Copyright (c) 2021 The University of Queensland
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

#ifndef _COMMARP_H_
#define _COMMARP_H_

/*
 * this is an ipv4 address, but in host byte order so we can do
 * range checks.
 */
struct commarp_address {
	uint32_t			 addr;
};

struct commarp_address_range {
	struct commarp_address		 min;
	struct commarp_address		 max;
};

struct commarp_address_filter {
	struct commarp_address_filter	*next;
	unsigned int		 	 filter;
	struct commarp_address_range	 addresses;
};

void	commarp_inaddr_to_address(struct commarp_address *,
	    const struct in_addr *);
void	commarp_bytes_to_address(struct commarp_address *, const void *);

struct commarp_iface;
TAILQ_HEAD(commarp_ifaces, commarp_iface);

void	commarp_iface_get(struct commarp_ifaces *, struct ifaddrs *,
	    const char *, struct commarp_address_filter *);

int	parse_config(struct commarp_ifaces *, struct ifaddrs *, char *);
int	cmdline_symset(char *);

#endif /* _COMMARP_H_ */
