#include <stddef.h>
#include <stdint.h>

typedef enum {
    pg_ready_state_unknown = 0,
    pg_ready_state_idle,
    pg_ready_state_inerror,
    pg_ready_state_intrans,
} pg_ready_state_t;

typedef int (*pg_fsm_cb) (void *user);
typedef int (*pg_fsm_int2_cb) (void *user, uint16_t n);
typedef int (*pg_fsm_int4_cb) (void *user, uint32_t n);
typedef int (*pg_fsm_str_cb) (void *user, size_t len, const unsigned char *data);

typedef struct {
    pg_fsm_cb field_beg;
    pg_fsm_int2_cb field_column;
    pg_fsm_int2_cb field_format;
    pg_fsm_int2_cb field_length;
    pg_fsm_int2_cb fields_count;
    pg_fsm_int2_cb ready_state;
    pg_fsm_int2_cb results_count;
    pg_fsm_int4_cb auth;
    pg_fsm_int4_cb bind;
    pg_fsm_int4_cb close;
    pg_fsm_int4_cb complete;
    pg_fsm_int4_cb empty;
    pg_fsm_int4_cb errors;
    pg_fsm_int4_cb field_mod;
    pg_fsm_int4_cb field_oid;
    pg_fsm_int4_cb fields;
    pg_fsm_int4_cb field_table;
    pg_fsm_int4_cb function;
    pg_fsm_int4_cb key;
    pg_fsm_int4_cb method;
    pg_fsm_int4_cb option;
    pg_fsm_int4_cb parse;
    pg_fsm_int4_cb pid;
    pg_fsm_int4_cb ready;
    pg_fsm_int4_cb result_len;
    pg_fsm_int4_cb results;
    pg_fsm_int4_cb secret;
    pg_fsm_str_cb all;
    pg_fsm_str_cb complete_val;
    pg_fsm_str_cb error_key;
    pg_fsm_str_cb error_val;
    pg_fsm_str_cb field_name;
    pg_fsm_str_cb option_key;
    pg_fsm_str_cb option_val;
    pg_fsm_str_cb result_val;
} pg_fsm_cb_t;

typedef struct pg_fsm_t pg_fsm_t;

size_t pg_fsm_execute(pg_fsm_t *fsm, const unsigned char *p, const unsigned char *eof);
size_t pg_fsm_size(void);
void pg_fsm_init(pg_fsm_t *fsm, const pg_fsm_cb_t *cb, const void *data);
