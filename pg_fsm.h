#include <stddef.h>
#include <stdint.h>

typedef enum {
    pg_ready_for_query_state_unknown = 0,
    pg_ready_for_query_state_idle,
    pg_ready_for_query_state_inerror,
    pg_ready_for_query_state_intrans,
} pg_ready_for_query_state_t;

typedef int (*pg_fsm_cb) (void *user);
typedef int (*pg_fsm_int2_cb) (void *user, uint16_t n);
typedef int (*pg_fsm_int4_cb) (void *user, uint32_t n);
typedef int (*pg_fsm_str_cb) (void *user, size_t len, const uint8_t *data);

typedef struct {
    pg_fsm_cb authentication_ok;
    pg_fsm_cb backend_key_data;
    pg_fsm_cb bind_complete;
    pg_fsm_cb close_complete;
    pg_fsm_cb copy_done;
    pg_fsm_cb empty_query_response;
    pg_fsm_cb error;
    pg_fsm_cb no_data;
    pg_fsm_cb parse_complete;
    pg_fsm_cb ready_for_query;
    pg_fsm_cb row_description_beg;
    pg_fsm_int2_cb data_row_count;
    pg_fsm_int2_cb ready_for_query_state;
    pg_fsm_int2_cb row_description_column;
    pg_fsm_int2_cb row_description_count;
    pg_fsm_int2_cb row_description_format;
    pg_fsm_int2_cb row_description_length;
    pg_fsm_int4_cb backend_key_data_key;
    pg_fsm_int4_cb backend_key_data_pid;
    pg_fsm_int4_cb command_complete;
    pg_fsm_int4_cb copy_data;
    pg_fsm_int4_cb copy_out_response;
    pg_fsm_int4_cb data_row;
    pg_fsm_int4_cb error_response;
    pg_fsm_int4_cb function_call_response;
    pg_fsm_int4_cb notice_response;
    pg_fsm_int4_cb notification_response;
    pg_fsm_int4_cb notification_response_pid;
    pg_fsm_int4_cb parameter_status;
    pg_fsm_int4_cb result_len;
    pg_fsm_int4_cb row_description;
    pg_fsm_int4_cb row_description_mod;
    pg_fsm_int4_cb row_description_oid;
    pg_fsm_int4_cb row_description_table;
    pg_fsm_str_cb all;
    pg_fsm_str_cb command_complete_val;
    pg_fsm_str_cb error_response_key;
    pg_fsm_str_cb error_response_val;
    pg_fsm_str_cb notification_response_extra;
    pg_fsm_str_cb notification_response_relname;
    pg_fsm_str_cb parameter_status_key;
    pg_fsm_str_cb parameter_status_val;
    pg_fsm_str_cb result_val;
    pg_fsm_str_cb row_description_name;
} pg_fsm_cb_t;

typedef struct pg_fsm_t pg_fsm_t;

size_t pg_fsm_execute(pg_fsm_t *fsm, const pg_fsm_cb_t *cb, const void *user, const unsigned char *p, const unsigned char *pe, const unsigned char *eof);
size_t pg_fsm_size(void);
size_t pg_fsm_stack(void);
void pg_fsm_init(pg_fsm_t *fsm);
