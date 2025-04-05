CC = x86_64-linux-gnu-gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared

LIBGOTOKU_SO = libgotoku.so
SOLVER_SO = libsolver.so
GOTOKU_BIN = gotoku.local

.PHONY: all clean solver

all: $(LIBGOTOKU_SO) $(SOLVER_SO) $(GOTOKU_BIN) 

$(LIBGOTOKU_SO): libgotoku_dummy.c libgotoku.h
	$(CC) $(CFLAGS) -o $@ libgotoku_dummy.c $(LDFLAGS)

$(SOLVER_SO): libsolver.c
	$(CC) $(CFLAGS) -rdynamic -o $@ libsolver.c $(LDFLAGS)

$(GOTOKU_BIN): gotoku.c libgotoku.h
	$(CC) $(CFLAGS) -o $@ gotoku.c -L. -lgotoku

solver: $(SOLVER_SO)

clean:
	rm -f $(LIBGOTOKU_SO) $(GOTOKU_BIN) $(SOLVER_SO)
