CC     = gcc
CFLAGS = -Wall -Werror -g
LDL    = -ldl
INJECTSO = logger
LOGGERRUNTIME = logger
PACKNAME= 310552029_hw2

.PHONY: all clean pack

all: $(INJECTSO).so $(LOGGERRUNTIME)

$(INJECTSO).so: hw2.c
	$(CC) -o $@ $(CFLAGS) -shared -fPIC $< $(LDL)

$(LOGGERRUNTIME): $(LOGGERRUNTIME).c
	$(CC) -o $@ $(CFLAGS) $<

clean:
	rm -rf $(INJECTSO).so $(LOGGERRUNTIME) $(PACKNAME).zip *.txt

pack: clean
	mkdir -p $(PACKNAME)
	cp *.c Makefile $(PACKNAME)
	zip -r $(PACKNAME).zip $(PACKNAME)
	rm -rf $(PACKNAME)
