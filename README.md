mitm
===

This is application written in C for Unix, debugged on Linux and FreeBSD system, that implements Man in the middle attack.

DESCRIPTION
---

The application consists of two programs. Program **arpspoof** is for poisoning two victims with arp packets, so they would send all IPv4 packets to the attacker. Second program **sniffer** is for redirection of the victims packets to the other victim, so that communication between the victims would work. Second program can also injects the packets and log them. Both programs need root permissions.

### arpspoof ###
The program will send each second one ARP reply packet to each of the victims saying, that the MAC address of the other victim is now the attackers one. When the program is interrupted with `^C`, it sends 5 unpoisoning ARP reply packets to each of the victim to establish the communication between them again. Then the program ends.

### sniffer ###
Program looks at the every packet and if the packet source and destination IP addresses are victim's and it is IPv4 packet, process following steps (in this order):
- if log file parameter (see the *USAGE* section) is provided, logs packet in human readable form to the file
- if replacement file parameter is provided, injects packet by replacing some substrings with anothers (see the *USAGE* section for more info)
- if the packet was injected in the previous step and it is TCP packet, eval new checksum
- forward packet to the right victim

When a packet is injected, program write a message about it to the standard output. Program is silent otherwise. For the verbose mode, you can use */dev/stdout* as the last parameter.

COMPILATION
---

To compilate the application, simply run the *make* command in its root directory. Only Unix standard libraries are needed.

USAGE
---

Both programs needs the root permissions.

### arpspoof ###

Run program *arpspoof* with these parameters:

	sudo ./arpspoof <interface> <target1-ip> <target1-mac> <target2-ip> <target2-mac>

- `<interface>`
	Network interface of the attacker that is connected to the same network as the victims.
- `<target1-ip>`
	IPv4 address of the 1. victim
- `<target1-mac>`
	Hardware (MAC) address of the 1. victim
- `<target2-ip>`
	IPv4 address of the 2. victim
- `<target2-mac>`
	Hardware (MAC) address of the 2. victim

### sniffer ###

So that the sniffer works properly, be sure that your computer is not forwarding IPv4
packets automatically by typing `echo 0 > /proc/sys/net/ipv4/ip_forward`.

Run program *sniffer* with these parameters:

	sudo ./sniffer <interface> <target1-ip> <target1-mac> <target2-ip> <target2-mac> [<replacement-file> [<log-file>]]

The first 5 arguments should have set the same value as the the 5 arguments of the *arpspoof* program.

- `<interface>`
	Network interface of the attacker that is connected to the same network as the victims.
- `<target1-ip>`
	IPv4 address of the 1. victim
- `<target1-mac>`
	Hardware (MAC) address of the 1. victim
- `<target2-ip>`
	IPv4 address of the 2. victim
- `<target2-mac>`
	Hardware (MAC) address of the 2. victim
- `<replacement-file>`
	Replacement file path.
	If this parameter is provided, packets will be injected using a replacement file with *find and replace* method. Replacement file is a text file with the following format:
	
		<number of lines following>
		<find 1>
		<replace 1>
		<find 2>
		<replace 2>
		...

	- `<number of lines following>` is number of `find` and `replace` lines in the file. The number should be even.
	- Pair `<find>` and `<replace>`: If there is a string *<find>* in the packet, it is replaced with *<replace>* string. These both strings should have the same length.
	Most of the http servers compress the packet data so they are unreadable for the sniffer then. To stop the compressing, it is very useful to add these *find and replace* lines to your replacement file (note that the second line ends with spaces so that both lines has the same length):
	```
	Accept-Encoding: gzip, deflate, sdch
		Accept-Encoding: identity           
	```
	If you do not need to inject the packets but still need to provide the following argument, use *-* instead of the replacement file path.

	There is an example replacement file in root directory *replace.txt*.

- `<log-file>`
	Log file path. All IPv4 packets will be logged in readable form to this file. If the packets are injected, uninjected form will be logged.

EXAMPLES
---

Stop the communication betwen two victims connected to the same wireless network as the attacker, who is connected through wlan0 interface. First victim has an IP address 192.168.43.1 and MAC address b4:3a:28:63:e6:ab, the second one has an ip address 192.168.43.107 and MAC address 54:e6:fc:8e:b9:99.

	sudo ./arpspoof wlan0 192.168.43.1 b4:3a:28:63:e6:ab 192.168.43.107 54:e6:fc:8e:b9:99

Redirects the victim traffic to the attacker with first command. Then bridge log the traffic to the standard output and forward them so the victims do not know that someting is happening.

	sudo ./arpspoof wlan0 192.168.43.1 b4:3a:28:63:e6:ab 192.168.43.107 54:e6:fc:8e:b9:99 &
	sudo ./sniffer wlan0 192.168.43.1 b4:3a:28:63:e6:ab 192.168.43.108 54:e6:fc:8e:b9:99 - /dev/stdout 

Redirects the victims traffic to the attacker with first command. Then injects all IPv4 packets by replacing string apple with linux, log the packets to the *log.txt* file and forward them so the victims do not know that someting is happening.

	sudo ./arpspoof wlan0 192.168.43.1 b4:3a:28:63:e6:ab 192.168.43.107 54:e6:fc:8e:b9:99 &
	sudo ./sniffer wlan0 192.168.43.1 b4:3a:28:63:e6:ab 192.168.43.108 54:e6:fc:8e:b9:99 replace.txt log.txt 

ARCHITECTURE
---

Program consists of these source files:
- `arp.c`
	For creating ARP packet.
- `arpspoof.c`
	Entry point to arpspoof program.
- `mutils.c`
	Intended only for use in files with main() method (*arpspoof.c*, *sniffer.c*).
 	Contains method for parsing first 5 program arguments.
- `packet.c`
	Contains methods for working with interfaces, for printing ip packets and buffers and for injecting packets.
- `packet_tcp.c`
	Contains methods for TCP packets eg. modifying TCP checksum.
- `sniffer.c`
	Entry point to sniffer program.
- `utils.c`
	Parsing addresses, converting addresses to string,
- `rawsock.c`
	System independent interface for using raw sockets (so they could work
	with ethernet header as well).
	Since there are different methods to use raw sockets on each system,
	it works absolutely different way for each system.
	For Linux, it uses RAW sockets with AF_PACKET address family, on BSD, there is no
	AF_PACKET address family, so it uses **BPF** (so no sockets actually).
- `lib\`
	A few header files from Linux system, so they could be used for BSD as well.

For more info, see the comments in the source files.

TESTS
---

To test the program, you need two victims (for instance wifi router and smartphone connected to the router). To see if the program *arpspoof* is working, you can for instance ping the router from the smartphone. If it is working and the *sniffer* program is not running, you should get no ping ICMP replies from the router on your smartphone. There is an example command for testing *arpspoof* in **test-arpspoof.sh**.

To test the *sniffer*, use **test-sniffer.sh** program which contains example *sniffer* commands. Then you can for instance try to reach website http://www.idnes.cz/ (that is for news) from the smartphone and inject some news by creating right *replace file*. You can use file *replace.txt* as an example of that file.

RESTRICTIONS
---

Because of that ARP protocol works for IPv4 packets only, program can not work with IPv6 packets.

The arpspoof is working on both systems properly but the sniffer program is not debugged on BSD yet.
