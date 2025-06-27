# Makefile for pnfdscan

CPPFLAGS=-I/usr/local/include
CFLAGS=-g -O $(CPPFLAGS)
LDFLAGS=-L/usr/local/lib -licuuc

BIN=pnfdscan
OBJS=pnfdscan.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(LDFLAGS)

clean distclean:
	-rm -f $(BIN) *.o *~ \#* core

push:	distclean
	git add -A && git commit -a && git push
