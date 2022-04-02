#define PG_FSM_STACK_SIZE 1
#include "pg_fsm.h"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_fsm_t {
    const pg_fsm_cb_t *cb;
    const unsigned char *string;
    const void *user;
    uint16_t cs;
    uint16_t fields_count;
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
    action empty { if (cb->empty(fsm->user, fsm->int4)) fbreak; }
    action empty_query_response { if (cb->empty_query_response(fsm->user)) fbreak; }
    action error_response_column { if (cb->error_response_key(fsm->user, sizeof("column") - 1, (const unsigned char *)"column")) fbreak; }
    action error_response_constraint { if (cb->error_response_key(fsm->user, sizeof("constraint") - 1, (const unsigned char *)"constraint")) fbreak; }
    action error_response_context { if (cb->error_response_key(fsm->user, sizeof("context") - 1, (const unsigned char *)"context")) fbreak; }
    action error_response_datatype { if (cb->error_response_key(fsm->user, sizeof("datatype") - 1, (const unsigned char *)"datatype")) fbreak; }
    action error_response_detail { if (cb->error_response_key(fsm->user, sizeof("detail") - 1, (const unsigned char *)"detail")) fbreak; }
    action error_response_file { if (cb->error_response_key(fsm->user, sizeof("file") - 1, (const unsigned char *)"file")) fbreak; }
    action error_response_function { if (cb->error_response_key(fsm->user, sizeof("function") - 1, (const unsigned char *)"function")) fbreak; }
    action error_response_hint { if (cb->error_response_key(fsm->user, sizeof("hint") - 1, (const unsigned char *)"hint")) fbreak; }
    action error_response_internal { if (cb->error_response_key(fsm->user, sizeof("internal") - 1, (const unsigned char *)"internal")) fbreak; }
    action error_response_line { if (cb->error_response_key(fsm->user, sizeof("line") - 1, (const unsigned char *)"line")) fbreak; }
    action error_response_nonlocalized { if (cb->error_response_key(fsm->user, sizeof("nonlocalized") - 1, (const unsigned char *)"nonlocalized")) fbreak; }
    action error_response_primary { if (cb->error_response_key(fsm->user, sizeof("primary") - 1, (const unsigned char *)"primary")) fbreak; }
    action error_response_query { if (cb->error_response_key(fsm->user, sizeof("query") - 1, (const unsigned char *)"query")) fbreak; }
    action error_response_schema { if (cb->error_response_key(fsm->user, sizeof("schema") - 1, (const unsigned char *)"schema")) fbreak; }
    action error_response_severity { if (cb->error_response_key(fsm->user, sizeof("severity") - 1, (const unsigned char *)"severity")) fbreak; }
    action error_response { if (cb->error_response(fsm->user, fsm->int4)) fbreak; }
    action error_response_sqlstate { if (cb->error_response_key(fsm->user, sizeof("sqlstate") - 1, (const unsigned char *)"sqlstate")) fbreak; }
    action error_response_statement { if (cb->error_response_key(fsm->user, sizeof("statement") - 1, (const unsigned char *)"statement")) fbreak; }
    action error_response_table { if (cb->error_response_key(fsm->user, sizeof("table") - 1, (const unsigned char *)"table")) fbreak; }
    action error_response_val { if (fsm->string && cb->error_response_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action field_beg { if (cb->field_beg(fsm->user)) fbreak; }
    action field_column { if (cb->field_column(fsm->user, fsm->int2)) fbreak; }
    action field_format { if (cb->field_format(fsm->user, fsm->int2)) fbreak; }
    action field_length { if (cb->field_length(fsm->user, fsm->int2)) fbreak; }
    action field_mod { if (cb->field_mod(fsm->user, fsm->int4)) fbreak; }
    action field_name { if (fsm->string && cb->field_name(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action field_oid { if (cb->field_oid(fsm->user, fsm->int4)) fbreak; }
    action fields_count { fsm->fields_count = fsm->int2; if (cb->fields_count(fsm->user, fsm->fields_count)) fbreak; }
    action fields { if (cb->fields(fsm->user, fsm->int4)) fbreak; }
    action fields_out { --fsm->fields_count }
    action field_table { if (cb->field_table(fsm->user, fsm->int4)) fbreak; }
    action function { if (cb->function(fsm->user, fsm->int4)) fbreak; }
    action int2 { if (!fsm->i) { fsm->i = sizeof(fsm->int2); fsm->int2 = 0; } fsm->int2 |= *p << ((2 << 2) * --fsm->i); }
    action int4 { if (!fsm->i) { fsm->i = sizeof(fsm->int4); fsm->int4 = 0; } fsm->int4 |= *p << ((2 << 2) * --fsm->i); }
    action key { if (cb->key(fsm->user, fsm->int4)) fbreak; }
    action option { if (cb->option(fsm->user, fsm->int4)) fbreak; }
    action option_key { if (fsm->string && cb->option_key(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action option_val { if (fsm->string && cb->option_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parse { if (cb->parse(fsm->user, fsm->int4)) fbreak; }
    action pid { if (cb->pid(fsm->user, fsm->int4)) fbreak; }
    action ready_idle { if (cb->ready_state(fsm->user, pg_ready_state_idle)) fbreak; }
    action ready { if (cb->ready(fsm->user, fsm->int4)) fbreak; }
    action ready_inerror { if (cb->ready_state(fsm->user, pg_ready_state_inerror)) fbreak; }
    action ready_intrans { if (cb->ready_state(fsm->user, pg_ready_state_intrans)) fbreak; }
    action data_row_len { fsm->data_row_len = fsm->int4; if (cb->data_row_len(fsm->user, fsm->data_row_len)) fbreak; if (!fsm->data_row_len || fsm->data_row_len == (uint32_t)-1) fnext main; }
    action data_rows_count { fsm->data_rows_count = fsm->int2; if (cb->data_rows_count(fsm->user, fsm->data_rows_count)) fbreak; if (!fsm->data_rows_count) fnext main; }
    action data_rows { if (cb->data_rows(fsm->user, fsm->int4)) fbreak; }
    action data_rows_len_next { if (!fsm->data_row_len || fsm->data_row_len == (uint32_t)-1) if (--fsm->data_rows_count) fnext data_rows_val; }
    action data_rows_val_next { if (!fsm->string && --fsm->data_rows_count) fnext data_rows_val; }
    action data_row_val { if (p == eof || !fsm->data_row_len--) { if (fsm->string && cb->data_row_val(fsm->user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; if (p != eof) { fhold; fnext main; } } }
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

    error_response = error_response_key str0 @error_response_val @/error_response_val;
    field = str0 >field_beg @field_name @/field_name int4 @field_table int2 @field_column int4 @field_oid int2 @field_length int4 @field_mod int2 @field_format;
    data_row = any @string @data_row_val @/data_row_val;
    data_rows_val = int4 @data_row_len @data_rows_len_next data_row ** @data_rows_val_next;

    fields = int2 @fields_count ( field outwhen fields_out ) **;
    function = int4 @data_row_len data_row **;
    option = str0 @option_key @/option_key str0 @option_val @/option_val;
    ready = 69 @ready_inerror | 73 @ready_idle | 84 @ready_intrans;
    data_rows = int2 @data_rows_count data_rows_val **;

    main :=
    (  49 int4 @parse
    | "2" 0 0 0 4 @bind_complete
    | "3" 0 0 0 4 @close_complete
    | "C" int4 @command_complete str0 @command_complete_val @/command_complete_val
    | "D" int4 @data_rows data_rows
    | "E" int4 @error_response error_response ** 0
    | "K" 0 0 0 12 @backend_key_data int4 @pid int4 @key
    | "R" 0 0 0 8 @authentication_ok 0 0 0 0
    |  83 int4 @option option
    |  84 int4 @fields fields
    |  86 int4 @function function
    |  90 int4 @ready ready
    | 110 int4 @empty
    | "I" 0 0 0 4 @empty_query_response
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
