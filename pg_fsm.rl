#define PG_FSM_STACK_SIZE 1
#include "pg_fsm.h"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_fsm_t {
    const pg_fsm_cb_t *cb;
    const unsigned char *string;
    const void *user;
    uint16_t cs;
    uint16_t row_descriptions_count;
    uint16_t int2;
    uint16_t data_rows_count;
    uint16_t stack[PG_FSM_STACK_SIZE];
    uint16_t top;
    uint32_t int4;
    uint32_t data_row_len;
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
    action data_row_len { fsm->data_row_len = fsm->int4; if (cb->data_row_len(fsm->user, fsm->data_row_len)) fbreak; if (!fsm->data_row_len || fsm->data_row_len == (uint32_t)-1) fnext main; }
    action data_rows_count { fsm->data_rows_count = fsm->int2; if (cb->data_rows_count(fsm->user, fsm->data_rows_count)) fbreak; if (!fsm->data_rows_count) fnext main; }
    action data_rows { if (cb->data_rows(fsm->user, fsm->int4)) fbreak; }
    action data_rows_len_next { if (!fsm->data_row_len || fsm->data_row_len == (uint32_t)-1) if (--fsm->data_rows_count) fnext data_rows_val; }
    action data_rows_val_next { if (!fsm->string && --fsm->data_rows_count) fnext data_rows_val; }
    action data_row_val { if (p == eof || !fsm->data_row_len--) { if (fsm->string && cb->data_row_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; if (p != eof) { fhold; fnext main; } } }
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
    action row_description_beg { if (cb->row_description_beg(fsm->user)) fbreak; }
    action row_description_column { if (cb->row_description_column(fsm->user, fsm->int2)) fbreak; }
    action row_description_format { if (cb->row_description_format(fsm->user, fsm->int2)) fbreak; }
    action row_description_length { if (cb->row_description_length(fsm->user, fsm->int2)) fbreak; }
    action row_description_mod { if (cb->row_description_mod(fsm->user, fsm->int4)) fbreak; }
    action row_description_name { if (fsm->string && cb->row_description_name(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action row_description_oid { if (cb->row_description_oid(fsm->user, fsm->int4)) fbreak; }
    action row_descriptions_count { fsm->row_descriptions_count = fsm->int2; if (cb->row_descriptions_count(fsm->user, fsm->row_descriptions_count)) fbreak; }
    action row_descriptions { if (cb->row_descriptions(fsm->user, fsm->int4)) fbreak; }
    action row_descriptions_out { --fsm->row_descriptions_count }
    action row_description_table { if (cb->row_description_table(fsm->user, fsm->int4)) fbreak; }
    action string { if (!fsm->string) fsm->string = p; }

    postpop { if (cb->postpop(fsm->user, fsm->top)) fbreak; }
    prepush { if (cb->prepush(fsm->user, fsm->top)) fbreak; }

    char = any - 0;
    int2 = any{2} $int2;
    int4 = any{4} $int4;
    str0 = char ** $string 0;

    error_response_key =
    (  67 @error_response_sqlstate
    |  68 @error_response_detail
    |  70 @error_response_file
    |  72 @error_response_hint
    |  76 @error_response_line
    |  77 @error_response_primary
    |  80 @error_response_statement
    |  82 @error_response_function
    |  83 @error_response_severity
    |  86 @error_response_nonlocalized
    |  87 @error_response_context
    |  99 @error_response_column
    | 100 @error_response_datatype
    | 110 @error_response_constraint
    | 112 @error_response_internal
    | 113 @error_response_query
    | 115 @error_response_schema
    | 116 @error_response_table
    );

    notice_response_key =
    (  67 @notice_response_sqlstate
    |  68 @notice_response_detail
    |  70 @notice_response_file
    |  72 @notice_response_hint
    |  76 @notice_response_line
    |  77 @notice_response_primary
    |  80 @notice_response_statement
    |  82 @notice_response_function
    |  83 @notice_response_severity
    |  86 @notice_response_nonlocalized
    |  87 @notice_response_context
    |  99 @notice_response_column
    | 100 @notice_response_datatype
    | 110 @notice_response_constraint
    | 112 @notice_response_internal
    | 113 @notice_response_query
    | 115 @notice_response_schema
    | 116 @notice_response_table
    );

    data_row = any @string @data_row_val @/data_row_val;
    data_rows_val = int4 @data_row_len @data_rows_len_next data_row ** @data_rows_val_next;
    error_response = error_response_key str0 @error_response_val @/error_response_val;
    row_description = str0 >row_description_beg @row_description_name @/row_description_name int4 @row_description_table int2 @row_description_column int4 @row_description_oid int2 @row_description_length int4 @row_description_mod int2 @row_description_format;
    notice_response = notice_response_key str0 @notice_response_val @/notice_response_val;

    data_rows = int2 @data_rows_count data_rows_val **;

    main :=
    ( "1" 0 0 0 4 @parse_complete
    | "2" 0 0 0 4 @bind_complete
    | "3" 0 0 0 4 @close_complete
    | "C" int4 @command_complete str0 @command_complete_val @/command_complete_val
    | "D" int4 @data_rows data_rows
    | "E" int4 @error_response error_response ** 0
    | "I" 0 0 0 4 @empty_query_response
    | "K" 0 0 0 12 @backend_key_data int4 @pid int4 @key
    | "n" 0 0 0 4 @no_data
    | "N" int4 @notice_response notice_response ** 0
    | "R" 0 0 0 8 @authentication_ok 0 0 0 0
    | "S" int4 @parameter_status str0 @parameter_status_key @/parameter_status_key str0 @parameter_status_val @/parameter_status_val
    | "T" int4 @row_descriptions int2 @row_descriptions_count ( row_description outwhen row_descriptions_out ) **
    | "V" int4 @function_call_response int4 @data_row_len data_row **
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
