#ifndef __SOLVER_H__
#define __SOLVER_H__

typedef struct gotoku_s {
	int x, y;		           
	int board[9][9];              
}	gotoku_t;

void game_set_ptr(void *ptr);
void * game_get_ptr();
int game_init();                        
static gotoku_t * game_load(const char *path); 

#endif	