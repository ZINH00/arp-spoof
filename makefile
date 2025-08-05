LDLIBS=-lpcap -pthread

all: arp-spoof


main.o: main.cpp mac.h ip.h ethhdr.h arphdr.h

arphdr.o: arphdr.cpp mac.h ip.h arphdr.h

ethhdr.o: ethhdr.cpp mac.h ethhdr.h

ip.o: ip.cpp ip.h

mac.o: mac.cpp mac.h

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o

	g++ -std=c++11 $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:

	rm -f arp-spoof *.o


