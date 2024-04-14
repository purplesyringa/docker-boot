all: docker-boot

docker-boot: src/main.c
	$(CC) $^ -o $@ -O2 -Wall
