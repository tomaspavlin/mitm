#ahoj
baf

mitm
===
This is application written in C for Unix (debugged on Linux), that implements Man in the middle attack. It consists of two programs. Program **arpspoof** is for poisoning two victims with arp packets, so they would send all IPv4 packets to attacker. Second program **sniffer** is for redirection of the victims packets to the other victim, so that communication between the victims would work. Second program can also injects the packets and log them.

COMPILATION
---
To compilate the application, simply run the *make* command in its root directory. Only Unix standard libraries are needed.

##COMMAND LINE USAGE
###arpspoof
Run arpspoof with these parameters:
```
./arpspoof <interface> <target1-ip> <target1-mac> <target2-ip> <target2-mac>
```


	./arpspoof <interface> <target1-ip> <target1-mac> <target2-ip> <target2-mac>

- `ahoj`
	cau


##ARCHITECTURE
##TESTS
##RESTRICTIONS
