#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const pg_parser_settings_t *settings;
    const void *data;
    int cs;
    int str;
    uint16_t field_count;
    uint16_t int2;
    uint16_t result_count;
    uint32_t int4;
    uint32_t result_len;
    uint8_t i;
} pg_parser_t;

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all(parser->data, 0, p)) fbreak; }
    action auth { if (settings->auth(parser->data, parser->int4)) fbreak; }
    action bind { if (settings->bind(parser->data, parser->int4)) fbreak; }
    action close { if (settings->close(parser->data, parser->int4)) fbreak; }
    action complete { if (settings->complete(parser->data, parser->int4)) fbreak; }
    action complete_val { if (str && settings->complete_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action error_column { if (settings->error_key(parser->data, sizeof("column") - 1, (const unsigned char *)"column")) fbreak; }
    action error_constraint { if (settings->error_key(parser->data, sizeof("constraint") - 1, (const unsigned char *)"constraint")) fbreak; }
    action error_context { if (settings->error_key(parser->data, sizeof("context") - 1, (const unsigned char *)"context")) fbreak; }
    action error_datatype { if (settings->error_key(parser->data, sizeof("datatype") - 1, (const unsigned char *)"datatype")) fbreak; }
    action error_detail { if (settings->error_key(parser->data, sizeof("detail") - 1, (const unsigned char *)"detail")) fbreak; }
    action error_file { if (settings->error_key(parser->data, sizeof("file") - 1, (const unsigned char *)"file")) fbreak; }
    action error_function { if (settings->error_key(parser->data, sizeof("function") - 1, (const unsigned char *)"function")) fbreak; }
    action error_hint { if (settings->error_key(parser->data, sizeof("hint") - 1, (const unsigned char *)"hint")) fbreak; }
    action error { if (settings->error(parser->data, parser->int4)) fbreak; }
    action error_internal { if (settings->error_key(parser->data, sizeof("internal") - 1, (const unsigned char *)"internal")) fbreak; }
    action error_line { if (settings->error_key(parser->data, sizeof("line") - 1, (const unsigned char *)"line")) fbreak; }
    action error_nonlocalized { if (settings->error_key(parser->data, sizeof("nonlocalized") - 1, (const unsigned char *)"nonlocalized")) fbreak; }
    action error_primary { if (settings->error_key(parser->data, sizeof("primary") - 1, (const unsigned char *)"primary")) fbreak; }
    action error_query { if (settings->error_key(parser->data, sizeof("query") - 1, (const unsigned char *)"query")) fbreak; }
    action error_schema { if (settings->error_key(parser->data, sizeof("schema") - 1, (const unsigned char *)"schema")) fbreak; }
    action error_severity { if (settings->error_key(parser->data, sizeof("severity") - 1, (const unsigned char *)"severity")) fbreak; }
    action error_sqlstate { if (settings->error_key(parser->data, sizeof("sqlstate") - 1, (const unsigned char *)"sqlstate")) fbreak; }
    action error_statement { if (settings->error_key(parser->data, sizeof("statement") - 1, (const unsigned char *)"statement")) fbreak; }
    action error_table { if (settings->error_key(parser->data, sizeof("table") - 1, (const unsigned char *)"table")) fbreak; }
    action error_val { if (str && settings->error_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action field_beg { if (settings->field_beg(parser->data)) fbreak; }
    action field_column { if (settings->field_column(parser->data, parser->int2)) fbreak; }
    action field_count { parser->field_count = parser->int2; if (settings->field_count(parser->data, parser->field_count)) fbreak; if (!parser->field_count) fnext main; }
    action field_format { if (settings->field_format(parser->data, parser->int2)) fbreak; if (!--parser->field_count) fnext main; }
    action field { if (settings->field(parser->data, parser->int4)) fbreak; }
    action field_length { if (settings->field_length(parser->data, parser->int2)) fbreak; }
    action field_mod { if (settings->field_mod(parser->data, parser->int4)) fbreak; }
    action field_name { if (str && settings->field_name(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action field_oid { if (settings->field_oid(parser->data, parser->int4)) fbreak; }
    action field_table { if (settings->field_table(parser->data, parser->int4)) fbreak; }
    action int2 { if (!parser->i) { parser->i = sizeof(parser->int2); parser->int2 = 0; } parser->int2 |= *p << ((2 << 2) * --parser->i); }
    action int4 { if (!parser->i) { parser->i = sizeof(parser->int4); parser->int4 = 0; } parser->int4 |= *p << ((2 << 2) * --parser->i); }
    action key { if (settings->key(parser->data, parser->int4)) fbreak; }
    action method { if (settings->method(parser->data, parser->int4)) fbreak; }
    action option { if (settings->option(parser->data, parser->int4)) fbreak; }
    action option_key { if (str && settings->option_key(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action option_val { if (str && settings->option_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action parse { if (settings->parse(parser->data, parser->int4)) fbreak; }
    action pid { if (settings->pid(parser->data, parser->int4)) fbreak; }
    action ready_idle { if (settings->ready_state(parser->data, pg_ready_state_idle)) fbreak; }
    action ready { if (settings->ready(parser->data, parser->int4)) fbreak; }
    action ready_inerror { if (settings->ready_state(parser->data, pg_ready_state_inerror)) fbreak; }
    action ready_intrans { if (settings->ready_state(parser->data, pg_ready_state_intrans)) fbreak; }
    action result_count { parser->result_count = parser->int2; if (settings->result_count(parser->data, parser->result_count)) fbreak; if (!parser->result_count) fnext main; }
    action result { if (settings->result(parser->data, parser->int4)) fbreak; }
    action result_len { parser->result_len = parser->int4; if (settings->result_len(parser->data, parser->result_len)) fbreak; if (!parser->result_len || parser->result_len == (uint32_t)-1) { if (!--parser->result_count) fnext main; else fnext result; } }
    action result_valeof { if (str && settings->result_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action result_val { if (!parser->result_len--) { if (str && settings->result_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; fhold; if (!--parser->result_count) fnext main; else fnext result; } }
    action secret { if (settings->secret(parser->data, parser->int4)) fbreak; }
    action str { if (!str) str = p; parser->str = cs; }

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

    byte = any @str @result_val @/result_valeof;
    error = error_key str0 @error_val @/error_val;
    field = str0 >field_beg @field_name @/field_name int4 @field_table int2 @field_column int4 @field_oid int2 @field_length int4 @field_mod int2 @field_format;
    ready = 69 @ready_inerror | 73 @ready_idle | 84 @ready_intrans;
    result = int4 @result_len byte **;

    main :=
    ( 49 int4 @parse
    | 50 int4 @bind
    | 51 int4 @close
    | 67 int4 @complete str0 @complete_val @/complete_val
    | 68 int4 @result int2 @result_count result **
    | 69 int4 @error error ** 0
    | 75 int4 @secret int4 @pid int4 @key
    | 82 int4 @auth int4 @method
    | 83 int4 @option str0 @option_key @/option_key str0 @option_val @/option_val
    | 84 int4 @field int2 @field_count field **
    | 90 int4 @ready ready
    ) ** $all;

    write data;
}%%

size_t pg_parser_execute(pg_parser_t *parser, const unsigned char *p, const unsigned char *pe) {
    const pg_parser_settings_t *settings = parser->settings;
    const unsigned char *b = p;
    const unsigned char *eof = pe;
    const unsigned char *str = parser->cs == parser->str ? p : NULL;
    int cs = parser->cs;
    %% write exec;
    parser->cs = cs;
    return p - b;
}

size_t pg_parser_size(void) {
    return sizeof(pg_parser_t);
}

void pg_parser_init(pg_parser_t *parser, const pg_parser_settings_t *settings, const void *data) {
    int cs = 0;
    %% write init;
    parser->cs = cs;
    parser->data = data;
    parser->settings = settings;
}
