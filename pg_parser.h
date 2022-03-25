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
    pg_parser_cb rowbeg;
    pg_parser_cb secret;
    pg_parser_len_str_cb byte;
    pg_parser_len_str_cb column;
    pg_parser_len_str_cb command;
    pg_parser_len_str_cb constraint;
    pg_parser_len_str_cb context;
    pg_parser_len_str_cb datatype;
    pg_parser_len_str_cb detail;
    pg_parser_len_str_cb file;
    pg_parser_len_str_cb function;
    pg_parser_len_str_cb hint;
    pg_parser_len_str_cb internal;
    pg_parser_len_str_cb line;
    pg_parser_len_str_cb name;
    pg_parser_len_str_cb nonlocalized;
    pg_parser_len_str_cb option;
    pg_parser_len_str_cb primary;
    pg_parser_len_str_cb query;
    pg_parser_len_str_cb schema;
    pg_parser_len_str_cb severity;
    pg_parser_len_str_cb sqlstate;
    pg_parser_len_str_cb statement;
    pg_parser_len_str_cb table;
    pg_parser_len_str_cb value;
    pg_parser_ptr_cb all;
    pg_parser_ptr_cb col;
    pg_parser_ptr_cb columnid;
    pg_parser_ptr_cb complete;
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
    pg_parser_ptr_cb pid;
    pg_parser_ptr_cb row;
    pg_parser_ptr_cb status;
    pg_parser_ptr_cb tableid;
} pg_parser_settings_t;

typedef struct pg_parser_t pg_parser_t;

size_t pg_parser_execute(pg_parser_t *parser, const char *p, const char *pe);
size_t pg_parser_size(void);
void pg_parser_init(pg_parser_t *parser, const pg_parser_settings_t *settings, const void *data);
