TARGET=youtube-unthrottle

all:
	$(CC) -Wall -o $(TARGET) main.c

.PHONY:	clean
clean:
	rm -f -- *.o $(TARGET)
