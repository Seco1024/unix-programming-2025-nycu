#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>
#include <time.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <dlfcn.h>

#include "libsolver.h"
#include "gops_addr.h"

#define GAMEPFX	"GOTOKU: "
#define MAX_GOPS 1200

typedef void (*func_ptr) (void);
func_ptr operations[MAX_GOPS];
int op_idx = 0;

static int _initialized = 0;
static void * __stored_ptr = NULL;
static gotoku_t *_board;
static int _solution[9][9];
static int _x_idx = 0;
static int _y_idx = 0;

__attribute__((constructor))
static void
__libinit() {
	fprintf(stderr, GAMEPFX "library loaded (%d, %d).\n", getuid(), getgid());
	return;
}

static int isValid(int x, int y, int value) {
    for (int i = 0; i < 9; ++i) {
        if (_solution[i][x] == value) return 0;
        if (_solution[y][i] == value) return 0;
    }

    int x_grid_idx = (x / 3) * 3;
    int y_grid_idx = (y / 3) * 3;

    for (int i = x_grid_idx; i < x_grid_idx + 3; ++i) {
        for (int j = y_grid_idx; j < y_grid_idx + 3; ++j) {
            if (_solution[j][i] == value) return 0;
        }
    }

    return 1;
}

static int solver(int x, int y) {
    if (y == 9) return 1;
    int x_next = (x + 1) % 9;
    int y_next = (x == 8) ? y + 1 : y;

    if (_solution[y][x] != 0) return solver(x_next, y_next);

    for (int i = 1; i <= 9; ++i) {
        if (!isValid(x, y, i)) continue;
        _solution[y][x] = i;
        if (solver(x_next, y_next)) return 1;
        _solution[y][x] = 0;
    }

    return 0;
}

void
game_set_ptr(void *ptr) {
	_initialized = 1;
	__stored_ptr = ptr;
}

void *
game_get_ptr() {
	return __stored_ptr;
}

static void hijack_GOT (void *main_ptr) {
    const uintptr_t main_offset = MAIN_OFFSET;
    uintptr_t base = (uintptr_t)main_ptr - main_offset;

    for (int i = 0; i < op_idx; ++i) {
        uintptr_t got_entry = base + got_offsets[i];
        uintptr_t page = got_entry & ~0xfff;
        mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE);
        *(void **)got_entry = (void *)operations[i];
    }
}

__attribute__((visibility("default")))
int game_init() {
    printf("============================\n");
    printf("UP113_GOT_PUZZLE_CHALLENGE\n");
    printf("============================\n");

	fprintf(stderr, GAMEPFX "library init - stored pointer = %p.\n", __stored_ptr);
    void *main_addr = game_get_ptr(); 
    printf("SOLVER: _main = %p\n", main_addr);

    // Load task
    gotoku_t *board = NULL;
    if((board = game_load("/gotoku.txt")) == NULL)
		return -1;

    for (int i = 0; i < 9; ++i) {
        for (int j = 0; j < 9; ++j) {
            _solution[i][j] = board->board[i][j];
        }
    }

    // Solve task
    if (!solver(0, 0)) {
        fprintf(stderr, GAMEPFX "[SOLVER] failed to solve sudoku\n");
        return -1;
    }

    // Define operations
    void *lib_handler = dlopen("libgotoku.so", RTLD_LAZY);
    if (!lib_handler) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return -1;
    }
    
    dlerror(); 

    func_ptr gop_up = dlsym(lib_handler, "gop_up");
    func_ptr gop_down = dlsym(lib_handler, "gop_down");
    func_ptr gop_left = dlsym(lib_handler, "gop_left");
    func_ptr gop_right = dlsym(lib_handler, "gop_right");

    func_ptr gop_fill[10];
    for (int i = 0; i <= 9; ++i) {
        char func_name[12];
        snprintf(func_name, sizeof(func_name), "gop_fill_%d", i);
        gop_fill[i] = dlsym(lib_handler, func_name);
    }

    // Save operations
    gotoku_t *gt = _board;
    for (int row = 0; row < 9; ++row) {
        for (int col = 0; col < 9; ++col) {
            if (gt->board[row][col] == 0) {
                int val = _solution[row][col];

                while (_x_idx < col) {
                    operations[op_idx++] = gop_right;
                    _x_idx++;
                }

                while (_x_idx > col) {
                    operations[op_idx++] = gop_left;
                    _x_idx--;
                }

                while (_y_idx < row) {
                    operations[op_idx++] = gop_down;
                    _y_idx++;
                }

                while (_y_idx > row) {
                    operations[op_idx++] = gop_up;
                    _y_idx--;
                }

                operations[op_idx++] = gop_fill[val];
            }
        }
    }

    hijack_GOT(main_addr);
	return 0;
}

static gotoku_t *
game_load(const char *fn) {
	gotoku_t *gt = NULL;
	FILE *fp = NULL;
	int i, j, k;
	if((fp = fopen(fn, "rt")) == NULL) {
		fprintf(stderr, GAMEPFX "fopen failed - %s.\n", strerror(errno));
		return NULL;
	}
	if((gt = _board = (gotoku_t*) malloc(sizeof(gotoku_t))) == NULL) {
		fprintf(stderr, GAMEPFX "alloc failed - %s.\n", strerror(errno));
		goto err_quit;
	}
	gt->x = gt->y = 0;
	for(i = 0; i < 9; i++) {
		for(j = 0; j < 9; j++) {
			if(fscanf(fp, "%d", &k) != 1) {
				fprintf(stderr, GAMEPFX "load number (%d, %d) failed - %s.\n", j, i, strerror(errno));
				goto err_quit;
			}
			gt->board[i][j] = k;
		}
	}
	fclose(fp);
	fprintf(stderr, GAMEPFX "game loaded\n");
	return gt;
err_quit:
	if(gt) free(gt);
	if(fp) fclose(fp);
	_board = NULL;
	return NULL;
}