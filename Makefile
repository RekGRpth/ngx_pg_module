all: pg_parser.c

pg_parser.c: pg_parser.rl Makefile
	ragel $< -o $@
