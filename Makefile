CC     = gcc
CFLAGS = -Wall -Werror -g
LDL    = -ldl

INJECTSO = logger
LOGGERRUNTIME = logger

.PHONY: all clean

all: $(INJECTSO).so $(LOGGERRUNTIME)

$(INJECTSO).so: hw2.c
	$(CC) -o $@ $(CFLAGS) -shared -fPIC $< $(LDL)

$(LOGGERRUNTIME): $(LOGGERRUNTIME).c
	$(CC) -o $@ $(CFLAGS) $<

clean:
	rm -f $(INJECTSO).so $(LOGGERRUNTIME) *.txt
