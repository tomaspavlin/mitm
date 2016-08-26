OBJ = arpspoof.o utils.o arp.o packet.o
DEPS = *.h

arpspoof: $(OBJ)
	$(CC) $(CFLAGS)-o $@ $(OBJ)


%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f ./*.o