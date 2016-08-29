OBJ = utils.o arp.o packet.o mutils.o
DEPS = *.h

all: arpspoof sniffer

arpspoof: arpspoof.o $(OBJ)
	$(CC) $(CFLAGS)-o $@ ${@}.o $(OBJ)

sniffer: sniffer.o $(OBJ)
	$(CC) $(CFLAGS)-o $@ ${@}.o $(OBJ)

temp: temp.o
	$(CC) $(CFLAGS)-o $@ ${@}.o $(OBJ)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f ./*.o