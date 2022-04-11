#include "pg_fsm.h"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_fsm_t {
    const unsigned char *string;
    uint16_t cs;
    uint16_t data_row_count;
    uint16_t int2;
    uint16_t row_description_count;
    uint32_t int4;
    uint32_t result_len;
    uint8_t i;
} pg_fsm_t;

%%{
    machine pg_fsm;
    access fsm->;
    alphtype unsigned char;

    action all { if (cb->all(user, 0, p)) fbreak; }
    action authentication_ok { if (cb->authentication_ok(user)) fbreak; }
    action backend_key_data { if (cb->backend_key_data(user)) fbreak; }
    action backend_key_data_key { if (cb->backend_key_data_key(user, fsm->int4)) fbreak; }
    action backend_key_data_pid { if (cb->backend_key_data_pid(user, fsm->int4)) fbreak; }
    action bind_complete { if (cb->bind_complete(user)) fbreak; }
    action close_complete { if (cb->close_complete(user)) fbreak; }
    action command_complete { if (cb->command_complete(user, fsm->int4 - 4)) fbreak; }
    action command_complete_val { if (fsm->string && cb->command_complete_val(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action copy_data { fsm->result_len = fsm->int4 - 4; if (cb->copy_data(user, fsm->result_len)) fbreak; }
    action copy_done { if (cb->copy_done(user)) fbreak; }
    action copy_out_response { if (cb->copy_out_response(user, fsm->int4 - 4)) fbreak; }
    action data_row_count { fsm->data_row_count = fsm->int2; if (cb->data_row_count(user, fsm->data_row_count)) fbreak; if (!fsm->data_row_count) fnext main; }
    action data_row { if (cb->data_row(user, fsm->int4 - 4)) fbreak; }
    action data_row_len_next { if (!fsm->result_len || fsm->result_len == (uint32_t)-1) if (--fsm->data_row_count) fnext data_row; }
    action data_row_val_next { if (!fsm->string && --fsm->data_row_count) fnext data_row; }
    action empty_query_response { if (cb->empty_query_response(user)) fbreak; }
    action error_response_column { if (cb->error_response_key(user, sizeof("column") - 1, (const unsigned char *)"column")) fbreak; }
    action error_response_constraint { if (cb->error_response_key(user, sizeof("constraint") - 1, (const unsigned char *)"constraint")) fbreak; }
    action error_response_context { if (cb->error_response_key(user, sizeof("context") - 1, (const unsigned char *)"context")) fbreak; }
    action error_response_datatype { if (cb->error_response_key(user, sizeof("datatype") - 1, (const unsigned char *)"datatype")) fbreak; }
    action error_response_detail { if (cb->error_response_key(user, sizeof("detail") - 1, (const unsigned char *)"detail")) fbreak; }
    action error_response_file { if (cb->error_response_key(user, sizeof("file") - 1, (const unsigned char *)"file")) fbreak; }
    action error_response_function { if (cb->error_response_key(user, sizeof("function") - 1, (const unsigned char *)"function")) fbreak; }
    action error_response_hint { if (cb->error_response_key(user, sizeof("hint") - 1, (const unsigned char *)"hint")) fbreak; }
    action error_response { if (cb->error_response(user, fsm->int4 - 4)) fbreak; }
    action error_response_internal { if (cb->error_response_key(user, sizeof("internal") - 1, (const unsigned char *)"internal")) fbreak; }
    action error_response_line { if (cb->error_response_key(user, sizeof("line") - 1, (const unsigned char *)"line")) fbreak; }
    action error_response_nonlocalized { if (cb->error_response_key(user, sizeof("nonlocalized") - 1, (const unsigned char *)"nonlocalized")) fbreak; }
    action error_response_primary { if (cb->error_response_key(user, sizeof("primary") - 1, (const unsigned char *)"primary")) fbreak; }
    action error_response_query { if (cb->error_response_key(user, sizeof("query") - 1, (const unsigned char *)"query")) fbreak; }
    action error_response_schema { if (cb->error_response_key(user, sizeof("schema") - 1, (const unsigned char *)"schema")) fbreak; }
    action error_response_severity { if (cb->error_response_key(user, sizeof("severity") - 1, (const unsigned char *)"severity")) fbreak; }
    action error_response_sqlstate { if (cb->error_response_key(user, sizeof("sqlstate") - 1, (const unsigned char *)"sqlstate")) fbreak; }
    action error_response_statement { if (cb->error_response_key(user, sizeof("statement") - 1, (const unsigned char *)"statement")) fbreak; }
    action error_response_table { if (cb->error_response_key(user, sizeof("table") - 1, (const unsigned char *)"table")) fbreak; }
    action error_response_val { if (fsm->string && cb->error_response_val(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action function_call_response { if (cb->function_call_response(user, fsm->int4 - 4)) fbreak; }
    action int2 { if (!fsm->i) { fsm->i = sizeof(fsm->int2); fsm->int2 = 0; } fsm->int2 |= *p << ((2 << 2) * --fsm->i); }
    action int4 { if (!fsm->i) { fsm->i = sizeof(fsm->int4); fsm->int4 = 0; } fsm->int4 |= *p << ((2 << 2) * --fsm->i); }
    action no_data { if (cb->no_data(user)) fbreak; }
    action notice_response { if (cb->notice_response(user, fsm->int4 - 4)) fbreak; }
    action notification_response_extra { if (fsm->string && cb->notification_response_extra(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action notification_response { if (cb->notification_response(user, fsm->int4 - 4)) fbreak; }
    action notification_response_pid { if (cb->notification_response_pid(user, fsm->int4)) fbreak; }
    action notification_response_relname { if (fsm->string && cb->notification_response_relname(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status { if (cb->parameter_status(user, fsm->int4 - 4)) fbreak; }
    action parameter_status_key { if (fsm->string && cb->parameter_status_key(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_val { if (fsm->string && cb->parameter_status_val(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parse_complete { if (cb->parse_complete(user)) fbreak; }
    action ready_for_query_idle { if (cb->ready_for_query_state(user, pg_ready_for_query_state_idle)) fbreak; }
    action ready_for_query { if (cb->ready_for_query(user)) fbreak; }
    action ready_for_query_inerror { if (cb->ready_for_query_state(user, pg_ready_for_query_state_inerror)) fbreak; }
    action ready_for_query_intrans { if (cb->ready_for_query_state(user, pg_ready_for_query_state_intrans)) fbreak; }
    action result_len { fsm->result_len = fsm->int4; if (cb->result_len(user, fsm->result_len)) fbreak; if (!fsm->result_len || fsm->result_len == (uint32_t)-1) fnext main; }
    action result_val { if (p == eof || !fsm->result_len--) { if (fsm->string && cb->result_val(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; if (p != eof) { if (cb->result_done(user)) fbreak; fhold; fnext main; } } }
    action row_description_beg { if (cb->row_description_beg(user)) fbreak; }
    action row_description_column { if (cb->row_description_column(user, fsm->int2)) fbreak; }
    action row_description_count { fsm->row_description_count = fsm->int2; if (cb->row_description_count(user, fsm->row_description_count)) fbreak; if (!fsm->row_description_count) fnext main;}
    action row_description_format { if (cb->row_description_format(user, 0)) fbreak; if (!--fsm->row_description_count) fnext main; }
    action row_description { if (cb->row_description(user, fsm->int4 - 4)) fbreak; }
    action row_description_length { if (cb->row_description_length(user, fsm->int2)) fbreak; }
    action row_description_mod { if (cb->row_description_mod(user, fsm->int4)) fbreak; }
    action row_description_name { if (fsm->string && cb->row_description_name(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action row_description_oid { if (cb->row_description_oid(user, fsm->int4)) fbreak; }
    action row_description_table { if (cb->row_description_table(user, fsm->int4)) fbreak; }
    action string { if (!fsm->string) fsm->string = p; }

    char = any - 0;
    int2 = any{2} $int2;
    int4 = any{4} $int4;
    str0 = char ** $string 0;

    error_response_key =
    ( "c" @error_response_column
    | "C" @error_response_sqlstate
    | "d" @error_response_datatype
    | "D" @error_response_detail
    | "F" @error_response_file
    | "H" @error_response_hint
    | "L" @error_response_line
    | "M" @error_response_primary
    | "n" @error_response_constraint
    | "p" @error_response_internal
    | "P" @error_response_statement
    | "q" @error_response_query
    | "R" @error_response_function
    | "s" @error_response_schema
    | "S" @error_response_severity
    | "t" @error_response_table
    | "V" @error_response_nonlocalized
    | "W" @error_response_context
    );

    ready_for_query_idle = "I" @ready_for_query_idle;
    ready_for_query_inerror = "E" @ready_for_query_inerror;
    ready_for_query_intrans = "T" @ready_for_query_intrans;
    result = any ** $string $result_val $/result_val;

    data_row = int4 @result_len @data_row_len_next result @data_row_val_next;
    error_response = error_response_key str0 @error_response_val @/error_response_val;
    ready_for_query = ready_for_query_inerror | ready_for_query_idle | ready_for_query_intrans;
    row_description = str0 >row_description_beg @row_description_name @/row_description_name int4 @row_description_table int2 @row_description_column int4 @row_description_oid int2 @row_description_length int4 @row_description_mod 0 0 @row_description_format;

    main :=
    ( "1" 0 0 0 4 @parse_complete
    | "2" 0 0 0 4 @bind_complete
    | "3" 0 0 0 4 @close_complete
    | "A" int4 @notification_response int4 @notification_response_pid str0 @notification_response_relname @/notification_response_relname str0 @notification_response_extra @/notification_response_extra
    | "c" 0 0 0 4 @copy_done
    | "C" int4 @command_complete str0 @command_complete_val @/command_complete_val
    | "d" int4 @copy_data result
    | "D" int4 @data_row int2 @data_row_count data_row **
    | "E" int4 @error_response error_response ** 0
    | "H" int4 @copy_out_response 0 any{2} ( 0 0 ) **
    | "I" 0 0 0 4 @empty_query_response
    | "K" 0 0 0 12 @backend_key_data int4 @backend_key_data_pid int4 @backend_key_data_key
    | "n" 0 0 0 4 @no_data
    | "N" int4 @notice_response error_response ** 0
    | "R" 0 0 0 8 @authentication_ok 0 0 0 0
    | "S" int4 @parameter_status str0 @parameter_status_key @/parameter_status_key str0 @parameter_status_val @/parameter_status_val
    | "T" int4 @row_description int2 @row_description_count row_description **
    | "V" int4 @function_call_response int4 @result_len result
    | "Z" 0 0 0 5 @ready_for_query ready_for_query
    ) **;

    write data;
}%%

size_t pg_fsm_execute(pg_fsm_t *fsm, const pg_fsm_cb_t *cb, const void *user, const unsigned char *p, const unsigned char *pe, const unsigned char *eof) {
    const unsigned char *b = p;
    %% write exec;
    if (fsm->cs == pg_fsm_error) (void)cb->error(user);
    return p - b;
}

size_t pg_fsm_size(void) {
    return sizeof(pg_fsm_t);
}

void pg_fsm_init(pg_fsm_t *fsm) {
    %% write init;
}
