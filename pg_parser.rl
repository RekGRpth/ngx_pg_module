#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const pg_parser_settings_t *settings;
    const void *data;
    int16_t field_count;
    int16_t int2;
    int16_t row_count;
    int32_t int4;
    int32_t row_len;
    int8_t i;
    int cs;
    int str;
} pg_parser_t;

%%{
    machine pg_parser;

    action all { if (settings->all(parser->data, 0, p)) fbreak; }
    action auth { if (settings->auth(parser->data)) fbreak; }
    action bind { if (settings->bind(parser->data)) fbreak; }
    action close { if (settings->close(parser->data)) fbreak; }
    action complete { if (settings->complete(parser->data, parser->int4)) fbreak; }
    action complete_val { if (str && settings->complete_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action error_column { if (settings->error_key(parser->data, sizeof("column") - 1, "column")) fbreak; }
    action error_constraint { if (settings->error_key(parser->data, sizeof("constraint") - 1, "constraint")) fbreak; }
    action error_context { if (settings->error_key(parser->data, sizeof("context") - 1, "context")) fbreak; }
    action error_datatype { if (settings->error_key(parser->data, sizeof("datatype") - 1, "datatype")) fbreak; }
    action error_detail { if (settings->error_key(parser->data, sizeof("detail") - 1, "detail")) fbreak; }
    action error_file { if (settings->error_key(parser->data, sizeof("file") - 1, "file")) fbreak; }
    action error_function { if (settings->error_key(parser->data, sizeof("function") - 1, "function")) fbreak; }
    action error_hint { if (settings->error_key(parser->data, sizeof("hint") - 1, "hint")) fbreak; }
    action error { if (settings->error(parser->data, parser->int4)) fbreak; }
    action error_internal { if (settings->error_key(parser->data, sizeof("internal") - 1, "internal")) fbreak; }
    action error_line { if (settings->error_key(parser->data, sizeof("line") - 1, "line")) fbreak; }
    action error_nonlocalized { if (settings->error_key(parser->data, sizeof("nonlocalized") - 1, "nonlocalized")) fbreak; }
    action error_primary { if (settings->error_key(parser->data, sizeof("primary") - 1, "primary")) fbreak; }
    action error_query { if (settings->error_key(parser->data, sizeof("query") - 1, "query")) fbreak; }
    action error_schema { if (settings->error_key(parser->data, sizeof("schema") - 1, "schema")) fbreak; }
    action error_severity { if (settings->error_key(parser->data, sizeof("severity") - 1, "severity")) fbreak; }
    action error_sqlstate { if (settings->error_key(parser->data, sizeof("sqlstate") - 1, "sqlstate")) fbreak; }
    action error_statement { if (settings->error_key(parser->data, sizeof("statement") - 1, "statement")) fbreak; }
    action error_table { if (settings->error_key(parser->data, sizeof("table") - 1, "table")) fbreak; }
    action error_val { if (str && settings->error_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action field_beg { if (settings->field_beg(parser->data)) fbreak; }
    action field_column { if (settings->field_column(parser->data, parser->int2)) fbreak; }
    action field_count { parser->field_count = parser->int2; if (settings->field_count(parser->data, parser->field_count)) fbreak; if (!parser->field_count) fnext main; }
    action field_format { if (settings->field_format(parser->data, parser->int2)) fbreak; if (!--parser->field_count) fnext main; }
    action field { if (settings->field(parser->data, parser->int4)) fbreak; }
    action field_len { if (settings->field_len(parser->data, parser->int2)) fbreak; }
    action field_mod { if (settings->field_mod(parser->data, parser->int4)) fbreak; }
    action field_name { if (str && settings->field_name(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action field_oid { if (settings->field_oid(parser->data, parser->int4)) fbreak; }
    action field_table { if (settings->field_table(parser->data, parser->int4)) fbreak; }
    action int2 { if (!parser->i) { parser->i = 2; parser->int2 = 0; } parser->int2 |= (uint8_t)*p << ((2 << 2) * --parser->i); }
    action int4 { if (!parser->i) { parser->i = 4; parser->int4 = 0; } parser->int4 |= (uint8_t)*p << ((2 << 2) * --parser->i); }
    action key { if (settings->key(parser->data, parser->int4)) fbreak; }
    action method { if (settings->method(parser->data, parser->int4)) fbreak; }
    action option { if (settings->option(parser->data, parser->int4)) fbreak; }
    action option_key { if (str && settings->option_key(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action option_val { if (str && settings->option_val(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action parse { if (settings->parse(parser->data)) fbreak; }
    action pid { if (settings->pid(parser->data, parser->int4)) fbreak; }
    action ready_idle { if (settings->ready_idle(parser->data)) fbreak; }
    action ready { if (settings->ready(parser->data)) fbreak; }
    action ready_inerror { if (settings->ready_inerror(parser->data)) fbreak; }
    action ready_intrans { if (settings->ready_intrans(parser->data)) fbreak; }
    action row_count { parser->row_count = parser->int2; if (settings->row_count(parser->data, parser->row_count)) fbreak; if (!parser->row_count) fnext main; }
    action row { if (settings->row(parser->data, parser->int4)) fbreak; }
    action row_len { parser->row_len = parser->int4; if (settings->row_len(parser->data, parser->row_len)) fbreak; if (!parser->row_len || parser->row_len == (int32_t)-1) { if (!--parser->row_count) fnext main; else fnext row; } }
    action rowvaleof { if (str && settings->rowval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action rowval { if (!parser->row_len) { if (str && settings->rowval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; fhold; if (!--parser->row_count) fnext main; else fnext row; } }
    action secret { if (settings->secret(parser->data)) fbreak; }
    action strend { parser->row_len-- }
    action str { if (!str) str = p; parser->str = cs; }

    any2 = any{2};
    any4 = any{4};
    int2 = any2 $int2;
    int4 = any4 $int4;
    str0 = (any - 0)** $str 0;
    str = any $str;

    error =
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
    | 116 @error_table );

    field = str0 >field_beg @field_name @/field_name int4 @field_table int2 @field_column int4 @field_oid int2 @field_len int4 @field_mod int2 @field_format;
    row = int4 @row_len ( str outwhen strend )** $rowval $/rowvaleof;

    main :=
    ( 49 any4 @parse
    | 50 any4 @bind
    | 51 any4 @close
    | 67 int4 @complete str0 @complete_val @/complete_val
    | 68 int4 @row int2 @row_count row **
    | 69 int4 @error ( error str0 @error_val @/error_val )** 0
    | 75 any4 @secret int4 @pid int4 @key
    | 82 any4 @auth int4 @method
    | 83 int4 @option str0 @option_key @/option_key str0 @option_val @/option_val
    | 84 int4 @field int2 @field_count field **
    | 90 any4 @ready ( 69 @ready_inerror | 73 @ready_idle | 84 @ready_intrans )
    )** $all;

    write data;
}%%

size_t pg_parser_execute(pg_parser_t *parser, const char *p, const char *pe) {
    const pg_parser_settings_t *settings = parser->settings;
    const char *b = p;
    const char *eof = pe;
    const char *str = parser->cs == parser->str ? p : NULL;
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
