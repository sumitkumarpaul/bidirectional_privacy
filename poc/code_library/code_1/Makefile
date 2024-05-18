CC = gcc
CFLAGS = -fPIC -Wall -Wextra -I/usr/include/libxml2/

TARGET = $(shell basename $(CURDIR)).so
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -shared -o $(TARGET) $(OBJECTS)
	

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
