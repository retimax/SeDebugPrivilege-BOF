CC     = x86_64-w64-mingw32-gcc
CFLAGS = -c -Os -DBOF

SRC = src/SeDebugPrivilege.c
OUT = bin/SeDebugPrivilege.o

all:
	mkdir -p bin
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)

clean:
	rm -f $(OUT)