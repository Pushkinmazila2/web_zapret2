CC ?= gcc
CFLAGS ?= -O2 -Wall

all: wz-udprelay

wz-udprelay: wz-udprelay.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread

clean:
	rm -f wz-udprelay

.PHONY: all clean