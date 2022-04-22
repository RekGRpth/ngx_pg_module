#include <stddef.h>
#include <stdint.h>

typedef enum {
    pg_ready_for_query_state_unknown = 0,
    pg_ready_for_query_state_idle,
    pg_ready_for_query_state_inerror,
    pg_ready_for_query_state_intrans,
} pg_ready_for_query_state_t;

typedef enum {
    pg_command_state_unknown = 0,
    pg_command_state_authentication_cleartext_password,
    pg_command_state_authentication_md5_password,
    pg_command_state_authentication_ok,
    pg_command_state_authentication_sasl,
    pg_command_state_backend_key_data,
    pg_command_state_bind_complete,
    pg_command_state_close_complete,
    pg_command_state_command_complete,
    pg_command_state_copy_data,
    pg_command_state_copy_done,
    pg_command_state_copy_out_response,
    pg_command_state_data_row,
    pg_command_state_empty_query_response,
    pg_command_state_error_response,
    pg_command_state_function_call_response,
    pg_command_state_no_data,
    pg_command_state_notice_response,
    pg_command_state_notification_response,
    pg_command_state_parameter_status,
    pg_command_state_parse_complete,
    pg_command_state_ready_for_query,
    pg_command_state_row_description,
} pg_command_state_t;

typedef int (*pg_fsm_cb) (void *u);
typedef int (*pg_fsm_int2_cb) (void *u, uint16_t n);
typedef int (*pg_fsm_int4_cb) (void *u, uint32_t n);
typedef int (*pg_fsm_str_cb) (void *u, size_t len, const uint8_t *data);

typedef struct {
    pg_fsm_cb authentication_cleartext_password;
    pg_fsm_cb authentication_ok;
    pg_fsm_cb backend_key_data;
    pg_fsm_cb bind_complete;
    pg_fsm_cb close_complete;
    pg_fsm_cb copy_done;
    pg_fsm_cb empty_query_response;
    pg_fsm_cb no_data;
    pg_fsm_cb notification_response_done;
    pg_fsm_cb parse_complete;
    pg_fsm_cb ready_for_query;
    pg_fsm_cb result_done;
    pg_fsm_cb row_description_beg;
    pg_fsm_int2_cb data_row_count;
    pg_fsm_int2_cb ready_for_query_state;
    pg_fsm_int2_cb row_description_column;
    pg_fsm_int2_cb row_description_count;
    pg_fsm_int2_cb row_description_format;
    pg_fsm_int2_cb row_description_length;
    pg_fsm_int4_cb authentication_md5_password;
    pg_fsm_int4_cb authentication_sasl;
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
    pg_fsm_str_cb authentication_sasl_name;
    pg_fsm_str_cb command_complete_val;
    pg_fsm_str_cb error;
    pg_fsm_str_cb error_response_column;
    pg_fsm_str_cb error_response_constraint;
    pg_fsm_str_cb error_response_context;
    pg_fsm_str_cb error_response_datatype;
    pg_fsm_str_cb error_response_detail;
    pg_fsm_str_cb error_response_file;
    pg_fsm_str_cb error_response_function;
    pg_fsm_str_cb error_response_hint;
    pg_fsm_str_cb error_response_internal;
    pg_fsm_str_cb error_response_line;
    pg_fsm_str_cb error_response_nonlocalized;
    pg_fsm_str_cb error_response_primary;
    pg_fsm_str_cb error_response_query;
    pg_fsm_str_cb error_response_schema;
    pg_fsm_str_cb error_response_severity;
    pg_fsm_str_cb error_response_sqlstate;
    pg_fsm_str_cb error_response_statement;
    pg_fsm_str_cb error_response_table;
    pg_fsm_str_cb notification_response_extra;
    pg_fsm_str_cb notification_response_relname;
    pg_fsm_str_cb parameter_status_application_name;
    pg_fsm_str_cb parameter_status_client_encoding;
    pg_fsm_str_cb parameter_status_datestyle;
    pg_fsm_str_cb parameter_status_default_transaction_read_only;
    pg_fsm_str_cb parameter_status_in_hot_standby;
    pg_fsm_str_cb parameter_status_integer_datetimes;
    pg_fsm_str_cb parameter_status_intervalstyle;
    pg_fsm_str_cb parameter_status_is_superuser;
    pg_fsm_str_cb parameter_status_server_encoding;
    pg_fsm_str_cb parameter_status_server_version;
    pg_fsm_str_cb parameter_status_session_authorization;
    pg_fsm_str_cb parameter_status_standard_conforming_strings;
    pg_fsm_str_cb parameter_status_timezone;
    pg_fsm_str_cb result_val;
    pg_fsm_str_cb row_description_name;
} pg_fsm_cb_t;

typedef struct pg_fsm_t pg_fsm_t;

size_t pg_fsm_execute(pg_fsm_t *m, const pg_fsm_cb_t *f, const void *u, const uint8_t *p, const uint8_t *pe);
size_t pg_fsm_size(void);
size_t pg_fsm_stack(void);
void pg_fsm_init(pg_fsm_t *m);
