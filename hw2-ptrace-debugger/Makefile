CC       := gcc
CFLAGS   := -Wall -Wextra -O2 -g -std=c17
LDFLAGS  := -lcapstone
TARGET   := sdb
SRC      := sdb.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)
