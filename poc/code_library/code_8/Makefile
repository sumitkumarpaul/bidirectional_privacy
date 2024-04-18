CC = gcc
CFLAGS = -fPIC -Wall -Wextra

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
