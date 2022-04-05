CC     = gcc
CFLAGS = -Wall -Werror
LDL    = -ldl

PROGS = logger.so testlogger

.PHONY: all test clean

all: $(PROGS)

%.so: %.c
	$(CC) -o $@ $(CFLAGS) -shared -fPIC $< $(LDL)

%: %.c
	$(CC) -o $@ $<

test: all
	LD_PRELOAD=./logger.so ./testlogger

clean:
	rm $(PROGS)
