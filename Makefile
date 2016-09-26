

OBJ = utils.o arp.o packet.o mutils.o packet_tcp.o
DEPS = *.h

CFLAGS = -Wall

all: arpspoof sniffer

arpspoof: arpspoof.o $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ ${@}.o $(OBJ)

sniffer: sniffer.o $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ ${@}.o $(OBJ)

temp: temp.o
	$(CC) $(CFLAGS) -o $@ ${@}.o $(OBJ)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f ./*.o