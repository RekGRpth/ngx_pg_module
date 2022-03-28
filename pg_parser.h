#include <stddef.h>
#include <stdint.h>

typedef enum {
    pg_ready_state_unknown = 0,
    pg_ready_state_idle,
    pg_ready_state_inerror,
    pg_ready_state_intrans,
} pg_ready_state_t;

typedef int (*pg_parser_cb) (void *data);
typedef int (*pg_parser_int2_cb) (void *data, uint16_t n);
typedef int (*pg_parser_int4_cb) (void *data, uint32_t n);
typedef int (*pg_parser_str_cb) (void *data, size_t len, const unsigned char *str);

typedef struct {
    pg_parser_cb field_beg;
    pg_parser_int2_cb field_column;
    pg_parser_int2_cb field_count;
    pg_parser_int2_cb field_format;
    pg_parser_int2_cb field_len;
    pg_parser_int2_cb ready_state;
    pg_parser_int2_cb value_count;
    pg_parser_int4_cb auth;
    pg_parser_int4_cb bind;
    pg_parser_int4_cb close;
    pg_parser_int4_cb complete;
    pg_parser_int4_cb error;
    pg_parser_int4_cb field;
    pg_parser_int4_cb field_mod;
    pg_parser_int4_cb field_oid;
    pg_parser_int4_cb field_table;
    pg_parser_int4_cb key;
    pg_parser_int4_cb method;
    pg_parser_int4_cb option;
    pg_parser_int4_cb parse;
    pg_parser_int4_cb pid;
    pg_parser_int4_cb ready;
    pg_parser_int4_cb secret;
    pg_parser_int4_cb value;
    pg_parser_int4_cb value_len;
    pg_parser_str_cb all;
    pg_parser_str_cb complete_val;
    pg_parser_str_cb error_key;
    pg_parser_str_cb error_val;
    pg_parser_str_cb field_val;
    pg_parser_str_cb option_key;
    pg_parser_str_cb option_val;
    pg_parser_str_cb value_val;
} pg_parser_settings_t;

typedef struct pg_parser_t pg_parser_t;

size_t pg_parser_execute(pg_parser_t *parser, const unsigned char *p, const unsigned char *pe);
size_t pg_parser_size(void);
void pg_parser_init(pg_parser_t *parser, const pg_parser_settings_t *settings, const void *data);
