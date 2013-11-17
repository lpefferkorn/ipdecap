ipdecap
=======

Decapsulate traffic encapsulated within GRE, IPIP, 6in4 and ESP (ipsec) protocols, from a pcap file.
Can also remove IEEE 802.1Q (virtual lan - vlan) header.

Documentation available at http://www.loicp.eu/ipdecap

Installation
============

Requirements:
  * OpenSSL
  * pcap

Run ./autogen.sh && ./configure && make install
