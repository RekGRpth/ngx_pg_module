#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const pg_parser_settings_t *settings;
    const void *data;
    int16_t int2;
    int16_t ncols;
    int16_t nrows;
    int32_t int4;
    int32_t nbytes;
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
    action cmd { if (settings->cmd(parser->data, parser->int4)) fbreak; }
    action cmdval { if (str && settings->cmdval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action colbeg { if (settings->colbeg(parser->data)) fbreak; }
    action colend { --parser->ncols >= 0 }
    action col { if (settings->col(parser->data, parser->int4)) fbreak; }
    action columnid { if (settings->column(parser->data, parser->int2)) fbreak; }
    action column { if (settings->errkey(parser->data, sizeof("column") - 1, "column")) fbreak; }
    action constraint { if (settings->errkey(parser->data, sizeof("constraint") - 1, "constraint")) fbreak; }
    action context { if (settings->errkey(parser->data, sizeof("context") - 1, "context")) fbreak; }
    action datatype { if (settings->errkey(parser->data, sizeof("datatype") - 1, "datatype")) fbreak; }
    action detail { if (settings->errkey(parser->data, sizeof("detail") - 1, "detail")) fbreak; }
    action error { if (settings->error(parser->data, parser->int4)) fbreak; }
    action errval { if (str && settings->errval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action file { if (settings->errkey(parser->data, sizeof("file") - 1, "file")) fbreak; }
    action format { if (settings->format(parser->data, parser->int2)) fbreak; }
    action function { if (settings->errkey(parser->data, sizeof("function") - 1, "function")) fbreak; }
    action hint { if (settings->errkey(parser->data, sizeof("hint") - 1, "hint")) fbreak; }
    action idle { if (settings->idle(parser->data)) fbreak; }
    action inerror { if (settings->inerror(parser->data)) fbreak; }
    action int2 { if (!parser->i) { parser->i = 2; parser->int2 = 0; } parser->int2 |= (uint8_t)*p << ((2 << 2) * --parser->i); }
    action int4 { if (!parser->i) { parser->i = 4; parser->int4 = 0; } parser->int4 |= (uint8_t)*p << ((2 << 2) * --parser->i); }
    action internal { if (settings->errkey(parser->data, sizeof("internal") - 1, "internal")) fbreak; }
    action intrans { if (settings->intrans(parser->data)) fbreak; }
    action key { if (settings->key(parser->data, parser->int4)) fbreak; }
    action line { if (settings->errkey(parser->data, sizeof("line") - 1, "line")) fbreak; }
    action main { fnext main; }
    action method { if (settings->method(parser->data, parser->int4)) fbreak; }
    action mod { if (settings->mod(parser->data, parser->int4)) fbreak; }
    action name { if (str && settings->name(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action nbytes { parser->nbytes = parser->int4; if (settings->nbytes(parser->data, parser->nbytes)) fbreak; if (parser->nbytes == (int32_t)-1) { if (--parser->nrows <= 0) fnext main; else fnext row; } }
    action ncols { parser->ncols = parser->int2; if (settings->ncols(parser->data, parser->ncols)) fbreak; }
    action nonlocalized { if (settings->errkey(parser->data, sizeof("nonlocalized") - 1, "nonlocalized")) fbreak; }
    action nrows { parser->nrows = parser->int2; if (settings->nrows(parser->data, parser->nrows)) fbreak; }
    action oid { if (settings->oid(parser->data, parser->int4)) fbreak; }
    action oidlen { if (settings->oidlen(parser->data, parser->int2)) fbreak; }
    action opt { if (settings->opt(parser->data, parser->int4)) fbreak; }
    action optkey { if (str && settings->optkey(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action optval { if (str && settings->optval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action parse { if (settings->parse(parser->data)) fbreak; }
    action pid { if (settings->pid(parser->data, parser->int4)) fbreak; }
    action primary { if (settings->errkey(parser->data, sizeof("primary") - 1, "primary")) fbreak; }
    action query { if (settings->errkey(parser->data, sizeof("query") - 1, "query")) fbreak; }
    action ready { if (settings->ready(parser->data)) fbreak; }
    action rowend { --parser->nrows >= 0 }
    action row { if (settings->row(parser->data, parser->int4)) fbreak; }
    action rowval { if (parser->nbytes <= 0) { if (str && settings->rowval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; fhold; } }
    action schema { if (settings->errkey(parser->data, sizeof("schema") - 1, "schema")) fbreak; }
    action secret { if (settings->secret(parser->data)) fbreak; }
    action severity { if (settings->errkey(parser->data, sizeof("severity") - 1, "severity")) fbreak; }
    action sqlstate { if (settings->errkey(parser->data, sizeof("sqlstate") - 1, "sqlstate")) fbreak; }
    action statement { if (settings->errkey(parser->data, sizeof("statement") - 1, "statement")) fbreak; }
    action strend { --parser->nbytes >= 0 }
    action str { if (!str) str = p; if (str) parser->str = cs; }
    action tableid { if (settings->table(parser->data, parser->int4)) fbreak; }
    action table { if (settings->errkey(parser->data, sizeof("table") - 1, "table")) fbreak; }

    any2 = any{2};
    any4 = any{4};
    int2 = any2 $int2;
    int4 = any4 $int4;
    str0 = (any - 0)* $str 0;
    str = any $str;

    col = str0 @name @/name int4 @tableid int2 @columnid int4 @oid int2 @oidlen int4 @mod int2 @format;
    error = ( 67 @sqlstate | 68 @detail | 70 @file | 72 @hint | 76 @line | 77 @primary | 80 @statement | 82 @function | 83 @severity | 86 @nonlocalized | 87 @context | 99 @column | 100 @datatype | 110 @constraint | 112 @internal | 113 @query | 115 @schema | 116 @table );
    row = int4 @nbytes ( str %when strend )* @rowval @/rowval;

    main :=
    ( 49 any4 @parse
    | 50 any4 @bind
    | 51 any4 @close
    | 67 int4 @cmd str0 @cmdval @/cmdval
    | 68 int4 @row int2 @nrows ( row >when rowend )+
    | 69 int4 @error ( error str0 @errval @/errval )+ 0
    | 75 any4 @secret int4 @pid int4 @key
    | 82 any4 @auth int4 @method
    | 83 int4 @opt str0 @optkey @/optkey str0 @optval @/optval
    | 84 int4 @col int2 @ncols ( col >colbeg >when colend )+
    | 90 any4 @ready ( 69 @inerror | 73 @idle | 84 @intrans )
    ) $all %main;

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
