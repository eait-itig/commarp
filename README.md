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

## How it works

Host A wishes to communicated with host B on a network with client isolation enabled. Router R running `commarp` as follows:

1. Host A broadcasts an ARP request for host B to the network
2. `commarp` on router A receives the ARP requests
3. `commarp` encapsulates the ARP request in an ICMP ping packet
   and sends it to host B
4. Host B echos the ping packet back to router R
5. Router R decapsulates the ARP request from inside the ping reply
   from Host B
6. Router R generates an ARP reply using it's own Ethernet address
   as the ARP hardware address to use
7. Router R sends the generated ARP reply to Host A

Subsequent IPv4 communication from host A to host B is sent via router R.
