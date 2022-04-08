CC     = gcc
CXX    = g++
CFLAGS = -Wall -Werror -g
LDL    = -ldl

PROGS = logger.so logger

.PHONY: all clean

all: $(PROGS)

%.so: %.c
	$(CC) -o $@ $(CFLAGS) -shared -fPIC $< $(LDL)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $< $(LDL)

clean:
	rm -f $(PROGS)
