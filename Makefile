LDLIBS += -lpcap

all: airodump

airodump: airodump.c

clean:
	rm -f airodump *.o
