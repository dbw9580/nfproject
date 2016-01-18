nfproject
=======

Network packet handling and obfuscation tool based on Netfilter.

Introduction:
------------
**This project is a proof-of-concept. It is not designed and built for real world uses(at least for now). Use it at you own risks.**

Instead of modifying the system routing table as most VPN softwares would do, 
I try ro utilize the Netfilter framework that has been built into the Linux kernel.

Assuming both ends of communication are using Linux so they both have Netfilter ready,
this tool receives network packets from the framework, and encode/decode them with a
previously defined protocol. Since the Netfilter is part of the kernel,
it is possible to do modifications to packets after they have been routed, and just before they are sent to the NIC send buffer.

The code only does a bitwise-reverse to every packets, because both ends can share the same code whether it is encoding/decoding. 
It is not strong enough to avoid detection/decryption/cencorship, etc.


Requirements: 
--------
*   the Netfilter framework(already built into the Linux kernel)
*   the [netfilter queue library](http://www.netfilter.org/projects/libnetfilter_queue/)
    (debian package: libnetfilter-queue-dev)

Build:
------
Please build the executables yourself.

    gcc -lnetfilter_queue -o nf -Wall nf.c
	
or use

    gcc -D__DEBUG -lnetfilter_queue -o nf -Wall nf.c 
	
to enable debug output. (This will print every packet received)

Usage:
-----
1.  set up rules in iptables to enable packet capture:

	on the end to use obfuscation by encoding output packets:
	
		iptables -t filter -A OUTPUT -p tcp --dport *dport* -j NFQUEUE --queue-num *queue-num1*
		
	where *dport* is the destination port the other end uses, *queue-num1* is the queue number to be used as the value of `-n` parameter.
	
	on the end to decode the obfuscation:
	
		iptables -t filter -A INPUT -p tcp --dport *dport* -j NFQUEUE --queue-num *queue-num2*
		
	where *dport* has to be the same as the encoding end, but *queue-num2* is free to choose, usually 0 will do.
2.  run the executables on both ends. make sure you specify the `-n` parameter as previously set with the iptables rule. 
    on Debian and Ubuntu you may need to be root to run the executables.
3.  use netcat to check if things are working out well.

License:
---------
This project is licensed under the GNU General Public License v3.


