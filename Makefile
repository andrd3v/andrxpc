CC = clang
CFLAGS = -Wall -O2 -arch arm64e
LDFLAGS = -lSystem -framework Foundation -framework CoreFoundation
OBJCFLAGS = $(CFLAGS) -fobjc-arc

all: build/injector build/xpchook.dylib build/andrxpc

build:
	mkdir -p build

build/injector: injector/main.c injector/injector.m injector/injector.h | build
	$(CC) $(CFLAGS) -Wno-deprecated-declarations -o $@ injector/main.c injector/injector.m $(LDFLAGS)

build/xpchook.dylib: dylib/xpchook.m | build
	$(CC) $(CFLAGS) -fno-objc-arc -shared -o $@ dylib/xpchook.m -framework CoreFoundation -lobjc
	codesign -f -s - $@

build/andrxpc: tui/main.c | build
	$(CC) $(CFLAGS) -o $@ tui/main.c -lncurses

clean:
	rm -rf build

.PHONY: all clean
