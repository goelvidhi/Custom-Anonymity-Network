#
# Define general macros
#
IDIR 			= include
ODIR			= obj
SDIR			= src
CC 			= gcc
CFLAGS 			= -g -Wall -I$(IDIR) 
LD 			= -c
LIBS			= -lpcap -lrt -lcrypto -pthread -fopenmp

include Config.mk
CFLAGS			+= -DFUNCTION=${FUNCTION} -DPERFORMANCE=${PERFORMANCE} -DDYNAMIC=${DYNAMIC}
CFLAGS			+= -DRTR1=${RTR1} -DRTR2=${RTR2} -DRTR3=${RTR3}
CFLAGS			+= -DNODE1=${NODE1} -DNODE2=${NODE2} -DNODE3=${NODE3} -DNODE4=${NODE4} -DNODE5=${NODE5} -DNODE6=${NODE6}

#
# Define include macros
#
_DEPS 			= *.h
DEPS 			= $(patsubst %,$(IDIR)/%,$(_DEPS))

#
# Define object set
#
_PKTOBJS		= printp.o packet_util.o
PKTOBJS 		= $(patsubst %,$(ODIR)/%,$(_PKTOBJS))

_DHOBJS			= des.o
DHOBJS 			= $(patsubst %,$(ODIR)/%,$(_DHOBJS))

_RTOBJS			= routing.o router_util.o
RTOBJS 			= $(patsubst %,$(ODIR)/%,$(_RTOBJS))

_KEYOBJS		= libkeystore.o
KEYOBJS 		= $(patsubst %,$(ODIR)/%,$(_KEYOBJS))


PSENDER 		= $(patsubst %,$(ODIR)/%,pcap_sender_new.o)
PRECV 			= $(patsubst %,$(ODIR)/%,raw_recv.o)
FSENDER			= $(patsubst %,$(ODIR)/%,fsender.o)
FRECEIVER		= $(patsubst %,$(ODIR)/%,freceiver.o)
DH1 			= $(patsubst %,$(ODIR)/%,dh_1.o)
DH2 			= $(patsubst %,$(ODIR)/%,dh_2.o)
ROUTER 			= $(patsubst %,$(ODIR)/%,router.o)


#
# Define general compilation rules
#
.PHONY: clean all
$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) $(LD) -O2 -o $@ $< $(CFLAGS) $(LIBS)


#
# Define executables
#
all: pcap_sender pcap_receiver dh_1 dh_2 router fsender 

pcap_sender:$(PKTOBJS)  $(PSENDER) $(DHOBJS) $(KEYOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -lm
pcap_receiver: $(PRECV) $(PKTOBJS) $(DHOBJS) $(KEYOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -lm
fsender: $(FSENDER) $(PKTOBJS) $(DHOBJS) $(KEYOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
freceiver: $(FRECEIVER) $(PKTOBJS) $(DHOBJS) $(KEYOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
dh_1: $(DH1) $(PKTOBJS) $(DHOBJS) $(KEYOBJS) $(RTOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
dh_2: $(DH2) $(PKTOBJS) $(DHOBJS) $(KEYOBJS) $(RTOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	
router: $(ROUTER) $(PKTOBJS) $(RTOBJS) $(KEYOBJS) $(DHOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ pcap_sender pcap_receiver router dh_1 dh_2 fsender freceiver
