#include <stddef.h>
#include <stdint.h>

typedef int (*pg_parser_cb) (void *data);
typedef int (*pg_parser_int2_cb) (void *data, int16_t int2);
typedef int (*pg_parser_int4_cb) (void *data, int32_t int4);
typedef int (*pg_parser_len_str_cb) (void *data, size_t len, const char *str);

typedef struct {
    pg_parser_cb auth;
    pg_parser_cb bind;
    pg_parser_cb close;
    pg_parser_cb colbeg;
    pg_parser_cb parse;
    pg_parser_cb ready;
    pg_parser_cb ready_idle;
    pg_parser_cb ready_inerror;
    pg_parser_cb ready_intrans;
    pg_parser_cb secret;
    pg_parser_int2_cb field_column;
    pg_parser_int2_cb format;
    pg_parser_int2_cb ncols;
    pg_parser_int2_cb nrows;
    pg_parser_int2_cb field_len;
    pg_parser_int4_cb col;
    pg_parser_int4_cb complete;
    pg_parser_int4_cb error;
    pg_parser_int4_cb key;
    pg_parser_int4_cb method;
    pg_parser_int4_cb mod;
    pg_parser_int4_cb nbytes;
    pg_parser_int4_cb field_oid;
    pg_parser_int4_cb option;
    pg_parser_int4_cb pid;
    pg_parser_int4_cb row;
    pg_parser_int4_cb field_table;
    pg_parser_len_str_cb all;
    pg_parser_len_str_cb complete_val;
    pg_parser_len_str_cb error_key;
    pg_parser_len_str_cb error_val;
    pg_parser_len_str_cb field_name;
    pg_parser_len_str_cb option_key;
    pg_parser_len_str_cb option_val;
    pg_parser_len_str_cb rowval;
} pg_parser_settings_t;

typedef struct pg_parser_t pg_parser_t;

size_t pg_parser_execute(pg_parser_t *parser, const char *p, const char *pe);
size_t pg_parser_size(void);
void pg_parser_init(pg_parser_t *parser, const pg_parser_settings_t *settings, const void *data);
