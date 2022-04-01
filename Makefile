all: pg_fsm.c

pg_fsm.c: pg_fsm.rl Makefile
	ragel -G2 $< -o $@
