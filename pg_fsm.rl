#define PG_FSM_STACK_SIZE 1
#include "pg_fsm.h"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_fsm_t {
    const pg_fsm_cb_t *cb;
    const unsigned char *string;
    const void *user;
    uint16_t cs;
    uint16_t row_description_count;
    uint16_t int2;
    uint16_t data_row_count;
    uint16_t stack[PG_FSM_STACK_SIZE];
    uint16_t top;
    uint32_t int4;
    uint32_t result_len;
    uint8_t i;
} pg_fsm_t;

%%{
    machine pg_fsm;
    access fsm->;
    alphtype unsigned char;

    action all { if (cb->all(fsm->user, 0, p)) fbreak; }
    action authentication_ok { if (cb->authentication_ok(fsm->user)) fbreak; }
    action backend_key_data { if (cb->backend_key_data(fsm->user)) fbreak; }
    action bind_complete { if (cb->bind_complete(fsm->user)) fbreak; }
    action close_complete { if (cb->close_complete(fsm->user)) fbreak; }
    action command_complete { if (cb->command_complete(fsm->user, fsm->int4)) fbreak; }
    action command_complete_val { if (fsm->string && cb->command_complete_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action data_row_count { fsm->data_row_count = fsm->int2; if (cb->data_row_count(fsm->user, fsm->data_row_count)) fbreak; if (!fsm->data_row_count) fnext main; }
    action data_row { if (cb->data_row(fsm->user, fsm->int4)) fbreak; }
    action data_row_len_next { if (!fsm->result_len || fsm->result_len == (uint32_t)-1) if (--fsm->data_row_count) fnext data_row; }
    action data_row_next { if (!fsm->string && --fsm->data_row_count) fnext data_row; }
    action empty_query_response { if (cb->empty_query_response(fsm->user)) fbreak; }
    action error_response_column { if (cb->error_response_key(fsm->user, sizeof("column") - 1, (const unsigned char *)"column")) fbreak; }
    action error_response_constraint { if (cb->error_response_key(fsm->user, sizeof("constraint") - 1, (const unsigned char *)"constraint")) fbreak; }
    action error_response_context { if (cb->error_response_key(fsm->user, sizeof("context") - 1, (const unsigned char *)"context")) fbreak; }
    action error_response_datatype { if (cb->error_response_key(fsm->user, sizeof("datatype") - 1, (const unsigned char *)"datatype")) fbreak; }
    action error_response_detail { if (cb->error_response_key(fsm->user, sizeof("detail") - 1, (const unsigned char *)"detail")) fbreak; }
    action error_response_file { if (cb->error_response_key(fsm->user, sizeof("file") - 1, (const unsigned char *)"file")) fbreak; }
    action error_response_function { if (cb->error_response_key(fsm->user, sizeof("function") - 1, (const unsigned char *)"function")) fbreak; }
    action error_response_hint { if (cb->error_response_key(fsm->user, sizeof("hint") - 1, (const unsigned char *)"hint")) fbreak; }
    action error_response { if (cb->error_response(fsm->user, fsm->int4)) fbreak; }
    action error_response_internal { if (cb->error_response_key(fsm->user, sizeof("internal") - 1, (const unsigned char *)"internal")) fbreak; }
    action error_response_line { if (cb->error_response_key(fsm->user, sizeof("line") - 1, (const unsigned char *)"line")) fbreak; }
    action error_response_nonlocalized { if (cb->error_response_key(fsm->user, sizeof("nonlocalized") - 1, (const unsigned char *)"nonlocalized")) fbreak; }
    action error_response_primary { if (cb->error_response_key(fsm->user, sizeof("primary") - 1, (const unsigned char *)"primary")) fbreak; }
    action error_response_query { if (cb->error_response_key(fsm->user, sizeof("query") - 1, (const unsigned char *)"query")) fbreak; }
    action error_response_schema { if (cb->error_response_key(fsm->user, sizeof("schema") - 1, (const unsigned char *)"schema")) fbreak; }
    action error_response_severity { if (cb->error_response_key(fsm->user, sizeof("severity") - 1, (const unsigned char *)"severity")) fbreak; }
    action error_response_sqlstate { if (cb->error_response_key(fsm->user, sizeof("sqlstate") - 1, (const unsigned char *)"sqlstate")) fbreak; }
    action error_response_statement { if (cb->error_response_key(fsm->user, sizeof("statement") - 1, (const unsigned char *)"statement")) fbreak; }
    action error_response_table { if (cb->error_response_key(fsm->user, sizeof("table") - 1, (const unsigned char *)"table")) fbreak; }
    action error_response_val { if (fsm->string && cb->error_response_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action function_call_response { if (cb->function_call_response(fsm->user, fsm->int4)) fbreak; }
    action int2 { if (!fsm->i) { fsm->i = sizeof(fsm->int2); fsm->int2 = 0; } fsm->int2 |= *p << ((2 << 2) * --fsm->i); }
    action int4 { if (!fsm->i) { fsm->i = sizeof(fsm->int4); fsm->int4 = 0; } fsm->int4 |= *p << ((2 << 2) * --fsm->i); }
    action key { if (cb->key(fsm->user, fsm->int4)) fbreak; }
    action no_data { if (cb->no_data(fsm->user)) fbreak; }
    action notice_response_column { if (cb->notice_response_key(fsm->user, sizeof("column") - 1, (const unsigned char *)"column")) fbreak; }
    action notice_response_constraint { if (cb->notice_response_key(fsm->user, sizeof("constraint") - 1, (const unsigned char *)"constraint")) fbreak; }
    action notice_response_context { if (cb->notice_response_key(fsm->user, sizeof("context") - 1, (const unsigned char *)"context")) fbreak; }
    action notice_response_datatype { if (cb->notice_response_key(fsm->user, sizeof("datatype") - 1, (const unsigned char *)"datatype")) fbreak; }
    action notice_response_detail { if (cb->notice_response_key(fsm->user, sizeof("detail") - 1, (const unsigned char *)"detail")) fbreak; }
    action notice_response_file { if (cb->notice_response_key(fsm->user, sizeof("file") - 1, (const unsigned char *)"file")) fbreak; }
    action notice_response_function { if (cb->notice_response_key(fsm->user, sizeof("function") - 1, (const unsigned char *)"function")) fbreak; }
    action notice_response_hint { if (cb->notice_response_key(fsm->user, sizeof("hint") - 1, (const unsigned char *)"hint")) fbreak; }
    action notice_response { if (cb->notice_response(fsm->user, fsm->int4)) fbreak; }
    action notice_response_internal { if (cb->notice_response_key(fsm->user, sizeof("internal") - 1, (const unsigned char *)"internal")) fbreak; }
    action notice_response_line { if (cb->notice_response_key(fsm->user, sizeof("line") - 1, (const unsigned char *)"line")) fbreak; }
    action notice_response_nonlocalized { if (cb->notice_response_key(fsm->user, sizeof("nonlocalized") - 1, (const unsigned char *)"nonlocalized")) fbreak; }
    action notice_response_primary { if (cb->notice_response_key(fsm->user, sizeof("primary") - 1, (const unsigned char *)"primary")) fbreak; }
    action notice_response_query { if (cb->notice_response_key(fsm->user, sizeof("query") - 1, (const unsigned char *)"query")) fbreak; }
    action notice_response_schema { if (cb->notice_response_key(fsm->user, sizeof("schema") - 1, (const unsigned char *)"schema")) fbreak; }
    action notice_response_severity { if (cb->notice_response_key(fsm->user, sizeof("severity") - 1, (const unsigned char *)"severity")) fbreak; }
    action notice_response_sqlstate { if (cb->notice_response_key(fsm->user, sizeof("sqlstate") - 1, (const unsigned char *)"sqlstate")) fbreak; }
    action notice_response_statement { if (cb->notice_response_key(fsm->user, sizeof("statement") - 1, (const unsigned char *)"statement")) fbreak; }
    action notice_response_table { if (cb->notice_response_key(fsm->user, sizeof("table") - 1, (const unsigned char *)"table")) fbreak; }
    action notice_response_val { if (fsm->string && cb->notice_response_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status { if (cb->parameter_status(fsm->user, fsm->int4)) fbreak; }
    action parameter_status_key { if (fsm->string && cb->parameter_status_key(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_val { if (fsm->string && cb->parameter_status_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parse_complete { if (cb->parse_complete(fsm->user)) fbreak; }
    action pid { if (cb->pid(fsm->user, fsm->int4)) fbreak; }
    action ready_for_query_idle { if (cb->ready_for_query_state(fsm->user, pg_ready_state_idle)) fbreak; }
    action ready_for_query { if (cb->ready_for_query(fsm->user)) fbreak; }
    action ready_for_query_inerror { if (cb->ready_for_query_state(fsm->user, pg_ready_state_inerror)) fbreak; }
    action ready_for_query_intrans { if (cb->ready_for_query_state(fsm->user, pg_ready_state_intrans)) fbreak; }
    action result_len { fsm->result_len = fsm->int4; if (cb->result_len(fsm->user, fsm->result_len)) fbreak; if (!fsm->result_len || fsm->result_len == (uint32_t)-1) fnext main; }
    action result_val { if (p == eof || !fsm->result_len--) { if (fsm->string && cb->result_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; if (p != eof) { fhold; fnext main; } } }
    action row_description_beg { if (cb->row_description_beg(fsm->user)) fbreak; }
    action row_description_column { if (cb->row_description_column(fsm->user, fsm->int2)) fbreak; }
    action row_description_count { fsm->row_description_count = fsm->int2; if (cb->row_description_count(fsm->user, fsm->row_description_count)) fbreak; }
    action row_description_format { if (cb->row_description_format(fsm->user, fsm->int2)) fbreak; }
    action row_description { if (cb->row_description(fsm->user, fsm->int4)) fbreak; }
    action row_description_length { if (cb->row_description_length(fsm->user, fsm->int2)) fbreak; }
    action row_description_mod { if (cb->row_description_mod(fsm->user, fsm->int4)) fbreak; }
    action row_description_name { if (fsm->string && cb->row_description_name(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action row_description_oid { if (cb->row_description_oid(fsm->user, fsm->int4)) fbreak; }
    action row_description_out { --fsm->row_description_count }
    action row_description_table { if (cb->row_description_table(fsm->user, fsm->int4)) fbreak; }
    action string { if (!fsm->string) fsm->string = p; }

    postpop { if (cb->postpop(fsm->user, fsm->top)) fbreak; }
    prepush { if (cb->prepush(fsm->user, fsm->top)) fbreak; }

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

    notice_response_key =
    ( "c" @notice_response_column
    | "C" @notice_response_sqlstate
    | "d" @notice_response_datatype
    | "D" @notice_response_detail
    | "F" @notice_response_file
    | "H" @notice_response_hint
    | "L" @notice_response_line
    | "M" @notice_response_primary
    | "n" @notice_response_constraint
    | "p" @notice_response_internal
    | "P" @notice_response_statement
    | "q" @notice_response_query
    | "R" @notice_response_function
    | "s" @notice_response_schema
    | "S" @notice_response_severity
    | "t" @notice_response_table
    | "V" @notice_response_nonlocalized
    | "W" @notice_response_context
    );

    result = any @string @result_val @/result_val;

    data_row = int4 @result_len @data_row_len_next result ** @data_row_next;
    error_response = error_response_key str0 @error_response_val @/error_response_val;
    notice_response = notice_response_key str0 @notice_response_val @/notice_response_val;
    row_description = str0 >row_description_beg @row_description_name @/row_description_name int4 @row_description_table int2 @row_description_column int4 @row_description_oid int2 @row_description_length int4 @row_description_mod int2 @row_description_format;

    main :=
    ( "1" 0 0 0 4 @parse_complete
    | "2" 0 0 0 4 @bind_complete
    | "3" 0 0 0 4 @close_complete
    | "C" int4 @command_complete str0 @command_complete_val @/command_complete_val
    | "D" int4 @data_row int2 @data_row_count data_row **
    | "E" int4 @error_response error_response ** 0
    | "I" 0 0 0 4 @empty_query_response
    | "K" 0 0 0 12 @backend_key_data int4 @pid int4 @key
    | "n" 0 0 0 4 @no_data
    | "N" int4 @notice_response notice_response ** 0
    | "R" 0 0 0 8 @authentication_ok 0 0 0 0
    | "S" int4 @parameter_status str0 @parameter_status_key @/parameter_status_key str0 @parameter_status_val @/parameter_status_val
    | "T" int4 @row_description int2 @row_description_count ( row_description outwhen row_description_out ) **
    | "V" int4 @function_call_response int4 @result_len result **
    | "Z" 0 0 0 5 @ready_for_query "E" @ready_for_query_inerror | "I" @ready_for_query_idle | "T" @ready_for_query_intrans
    ) $all;

    write data;
}%%

size_t pg_fsm_execute(pg_fsm_t *fsm, const unsigned char *p, const unsigned char *eof) {
    const pg_fsm_cb_t *cb = fsm->cb;
    const unsigned char *b = p;
    const unsigned char *pe = eof;
    %% write exec;
    return p - b;
}

size_t pg_fsm_size(void) {
    return sizeof(pg_fsm_t);
}

size_t pg_fsm_stack(void) {
    return PG_FSM_STACK_SIZE;
}

void pg_fsm_init(pg_fsm_t *fsm, const pg_fsm_cb_t *cb, const void *user) {
    %% write init;
    fsm->cb = cb;
    fsm->user = user;
}
