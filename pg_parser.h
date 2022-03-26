#include <stddef.h>
#include <stdint.h>

typedef int (*pg_parser_cb) (void *data);
typedef int (*pg_parser_ptr_cb) (void *data, const void *ptr);
typedef int (*pg_parser_len_str_cb) (void *data, size_t len, const char *str);

typedef struct {
    pg_parser_cb auth;
    pg_parser_cb bind;
    pg_parser_cb close;
    pg_parser_cb colbeg;
    pg_parser_cb idle;
    pg_parser_cb inerror;
    pg_parser_cb intrans;
    pg_parser_cb parse;
    pg_parser_cb ready;
    pg_parser_cb secret;
    pg_parser_len_str_cb all;
    pg_parser_len_str_cb cmdval;
    pg_parser_len_str_cb errkey;
    pg_parser_len_str_cb errval;
    pg_parser_len_str_cb name;
    pg_parser_len_str_cb optkey;
    pg_parser_len_str_cb optval;
    pg_parser_len_str_cb rowval;
    pg_parser_ptr_cb cmd;
    pg_parser_ptr_cb col;
    pg_parser_ptr_cb column;
    pg_parser_ptr_cb error;
    pg_parser_ptr_cb format;
    pg_parser_ptr_cb key;
    pg_parser_ptr_cb method;
    pg_parser_ptr_cb mod;
    pg_parser_ptr_cb nbytes;
    pg_parser_ptr_cb ncols;
    pg_parser_ptr_cb nrows;
    pg_parser_ptr_cb oid;
    pg_parser_ptr_cb oidlen;
    pg_parser_ptr_cb opt;
    pg_parser_ptr_cb pid;
    pg_parser_ptr_cb row;
    pg_parser_ptr_cb table;
} pg_parser_settings_t;

typedef struct pg_parser_t pg_parser_t;

size_t pg_parser_execute(pg_parser_t *parser, const char *p, const char *pe);
size_t pg_parser_size(void);
void pg_parser_init(pg_parser_t *parser, const pg_parser_settings_t *settings, const void *data);
