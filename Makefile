CPPFLAGS ?= -Wall -Werror -I../libusbg/include -static
LDFLAGS ?= -L../libusbg/src/.libs -lusbg
CC=gcc

all: clean usb-manager.o
	$(CC) -static ../libusbg/src/usbg.o usb-manager.o -o usb-manager

dynamic: clean usb-manager.o
	$(CC) `pkg-config --libs libusbg` usb-manager.o $(CFLAGS) $(LDFLAGS) -Wall -Werror -o usb-manager

clean:
	rm -f usb-manager *.o
