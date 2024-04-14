all: dexec

dexec: src/main.c
	$(CC) $^ -o $@ -O2 -Wall
