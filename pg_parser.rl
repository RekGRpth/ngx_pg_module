#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_fsm_t {
    const pg_fsm_cb_t *cb;
    const unsigned char *string;
    const void *data;
    int cs;
    uint16_t field_count;
    uint16_t int2;
    uint16_t result_count;
    uint32_t int4;
    uint32_t result_len;
    uint8_t i;
} pg_fsm_t;

%%{
    machine pg_fsm;
    access fsm->;
    alphtype unsigned char;

    action all { if (cb->all(fsm->data, 0, p)) fbreak; }
    action auth { if (cb->auth(fsm->data, fsm->int4)) fbreak; }
    action bind { if (cb->bind(fsm->data, fsm->int4)) fbreak; }
    action close { if (cb->close(fsm->data, fsm->int4)) fbreak; }
    action complete { if (cb->complete(fsm->data, fsm->int4)) fbreak; }
    action complete_val { if (fsm->string && cb->complete_val(fsm->data, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action empty { if (cb->empty(fsm->data, fsm->int4)) fbreak; }
    action error_column { if (cb->error_key(fsm->data, sizeof("column") - 1, (const unsigned char *)"column")) fbreak; }
    action error_constraint { if (cb->error_key(fsm->data, sizeof("constraint") - 1, (const unsigned char *)"constraint")) fbreak; }
    action error_context { if (cb->error_key(fsm->data, sizeof("context") - 1, (const unsigned char *)"context")) fbreak; }
    action error_datatype { if (cb->error_key(fsm->data, sizeof("datatype") - 1, (const unsigned char *)"datatype")) fbreak; }
    action error_detail { if (cb->error_key(fsm->data, sizeof("detail") - 1, (const unsigned char *)"detail")) fbreak; }
    action error_file { if (cb->error_key(fsm->data, sizeof("file") - 1, (const unsigned char *)"file")) fbreak; }
    action error_function { if (cb->error_key(fsm->data, sizeof("function") - 1, (const unsigned char *)"function")) fbreak; }
    action error_hint { if (cb->error_key(fsm->data, sizeof("hint") - 1, (const unsigned char *)"hint")) fbreak; }
    action error { if (cb->error(fsm->data, fsm->int4)) fbreak; }
    action error_internal { if (cb->error_key(fsm->data, sizeof("internal") - 1, (const unsigned char *)"internal")) fbreak; }
    action error_line { if (cb->error_key(fsm->data, sizeof("line") - 1, (const unsigned char *)"line")) fbreak; }
    action error_nonlocalized { if (cb->error_key(fsm->data, sizeof("nonlocalized") - 1, (const unsigned char *)"nonlocalized")) fbreak; }
    action error_primary { if (cb->error_key(fsm->data, sizeof("primary") - 1, (const unsigned char *)"primary")) fbreak; }
    action error_query { if (cb->error_key(fsm->data, sizeof("query") - 1, (const unsigned char *)"query")) fbreak; }
    action error_schema { if (cb->error_key(fsm->data, sizeof("schema") - 1, (const unsigned char *)"schema")) fbreak; }
    action error_severity { if (cb->error_key(fsm->data, sizeof("severity") - 1, (const unsigned char *)"severity")) fbreak; }
    action error_sqlstate { if (cb->error_key(fsm->data, sizeof("sqlstate") - 1, (const unsigned char *)"sqlstate")) fbreak; }
    action error_statement { if (cb->error_key(fsm->data, sizeof("statement") - 1, (const unsigned char *)"statement")) fbreak; }
    action error_table { if (cb->error_key(fsm->data, sizeof("table") - 1, (const unsigned char *)"table")) fbreak; }
    action error_val { if (fsm->string && cb->error_val(fsm->data, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action field_beg { if (cb->field_beg(fsm->data)) fbreak; }
    action field_column { if (cb->field_column(fsm->data, fsm->int2)) fbreak; }
    action field_count { fsm->field_count = fsm->int2; if (cb->field_count(fsm->data, fsm->field_count)) fbreak; if (!fsm->field_count) fnext main; }
    action field_format { if (cb->field_format(fsm->data, fsm->int2)) fbreak; if (!--fsm->field_count) fnext main; }
    action field { if (cb->field(fsm->data, fsm->int4)) fbreak; }
    action field_length { if (cb->field_length(fsm->data, fsm->int2)) fbreak; }
    action field_mod { if (cb->field_mod(fsm->data, fsm->int4)) fbreak; }
    action field_name { if (fsm->string && cb->field_name(fsm->data, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action field_oid { if (cb->field_oid(fsm->data, fsm->int4)) fbreak; }
    action field_table { if (cb->field_table(fsm->data, fsm->int4)) fbreak; }
    action function { if (cb->function(fsm->data, fsm->int4)) fbreak; }
    action int2 { if (!fsm->i) { fsm->i = sizeof(fsm->int2); fsm->int2 = 0; } fsm->int2 |= *p << ((2 << 2) * --fsm->i); }
    action int4 { if (!fsm->i) { fsm->i = sizeof(fsm->int4); fsm->int4 = 0; } fsm->int4 |= *p << ((2 << 2) * --fsm->i); }
    action key { if (cb->key(fsm->data, fsm->int4)) fbreak; }
    action method { if (cb->method(fsm->data, fsm->int4)) fbreak; }
    action option { if (cb->option(fsm->data, fsm->int4)) fbreak; }
    action option_key { if (fsm->string && cb->option_key(fsm->data, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action option_val { if (fsm->string && cb->option_val(fsm->data, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parse { if (cb->parse(fsm->data, fsm->int4)) fbreak; }
    action pid { if (cb->pid(fsm->data, fsm->int4)) fbreak; }
    action ready_idle { if (cb->ready_state(fsm->data, pg_ready_state_idle)) fbreak; }
    action ready { if (cb->ready(fsm->data, fsm->int4)) fbreak; }
    action ready_inerror { if (cb->ready_state(fsm->data, pg_ready_state_inerror)) fbreak; }
    action ready_intrans { if (cb->ready_state(fsm->data, pg_ready_state_intrans)) fbreak; }
    action result_count { fsm->result_count = fsm->int2; if (cb->result_count(fsm->data, fsm->result_count)) fbreak; if (!fsm->result_count) fnext main; }
    action result { if (cb->result(fsm->data, fsm->int4)) fbreak; }
    action result_len { fsm->result_len = fsm->int4; if (cb->result_len(fsm->data, fsm->result_len)) fbreak; if (!fsm->result_len || fsm->result_len == (uint32_t)-1) fnext main; }
    action results_len_next { if (!fsm->result_len || fsm->result_len == (uint32_t)-1) if (--fsm->result_count) fnext results; }
    action results_val_next { if (!fsm->string && --fsm->result_count) fnext results; }
    action result_val { if (p == eof || !fsm->result_len--) { if (fsm->string && cb->result_val(fsm->data, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; if (p != eof) { fhold; fnext main; } } }
    action secret { if (cb->secret(fsm->data, fsm->int4)) fbreak; }
    action str { if (!fsm->string) fsm->string = p; }

    char = any - 0;
    int2 = any{2} $int2;
    int4 = any{4} $int4;
    str0 = char ** $str 0;

    error_key =
    (  67 @error_sqlstate
    |  68 @error_detail
    |  70 @error_file
    |  72 @error_hint
    |  76 @error_line
    |  77 @error_primary
    |  80 @error_statement
    |  82 @error_function
    |  83 @error_severity
    |  86 @error_nonlocalized
    |  87 @error_context
    |  99 @error_column
    | 100 @error_datatype
    | 110 @error_constraint
    | 112 @error_internal
    | 113 @error_query
    | 115 @error_schema
    | 116 @error_table
    );

    error = error_key str0 @error_val @/error_val;
    field = str0 >field_beg @field_name @/field_name int4 @field_table int2 @field_column int4 @field_oid int2 @field_length int4 @field_mod int2 @field_format;
    ready = 69 @ready_inerror | 73 @ready_idle | 84 @ready_intrans;
    result = any @str @result_val @/result_val;
    results = int4 @result_len @results_len_next result ** @results_val_next;

    main :=
    (  49 int4 @parse
    |  50 int4 @bind
    |  51 int4 @close
    |  67 int4 @complete str0 @complete_val @/complete_val
    |  68 int4 @result int2 @result_count results **
    |  69 int4 @error error ** 0
    |  75 int4 @secret int4 @pid int4 @key
    |  82 int4 @auth int4 @method
    |  83 int4 @option str0 @option_key @/option_key str0 @option_val @/option_val
    |  84 int4 @field int2 @field_count field **
    |  86 int4 @function int4 @result_len result **
    |  90 int4 @ready ready
    | 110 int4 @empty
    ) ** $all;

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

void pg_fsm_init(pg_fsm_t *fsm, const pg_fsm_cb_t *cb, const void *data) {
    %% write init;
    fsm->cb = cb;
    fsm->data = data;
}
