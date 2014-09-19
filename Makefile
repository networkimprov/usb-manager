CPPFLAGS=-Wall -Werror -I../libusbg/include -static
LDFLAGS=-L../libusbg/src/.libs -lusbg

all: clean usb-manager.o
	gcc -static ../libusbg/src/usbg.o usb-manager.o -o usb-manager

clean:
	rm -f usb-manager *.o
