# commarp(8)

An ARP responder for routers/firewalls on community ports in a
private VLAN (PVLAN) or WiFi environment configured to provide
client isolation.

The goal is to allow hosts on a subnet that are isolated from each
other to communicate via the router or firewall on the subnet. This
is acheived by having the router reply to ARP requests by these
clients with it's own l2 address, which in turn directs all IPv4
communication to the router for... routing.

This has been written to run on OpenBSD.

## Todo

- Allow for the specification of which IPs to respond on behalf of
- Strengthen the ICMP payload
