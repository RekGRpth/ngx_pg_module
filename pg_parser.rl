#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const pg_parser_settings_t *settings;
    const void *data;
    int16_t int2;
    int16_t n;
    int32_t int4;
    int8_t i;
    int cs;
    int str;
} pg_parser_t;

%%{
    machine pg_parser;

    action all { if (settings->all && settings->all(parser->data, p)) fbreak; }
    action auth { if (settings->auth && settings->auth(parser->data)) fbreak; }
    action bind { if (settings->bind && settings->bind(parser->data)) fbreak; }
    action byte { if (--parser->int4 >= 0) fgoto str; if (str && settings->byte && settings->byte(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; fhold; fnext row; }
    action close { if (settings->close && settings->close(parser->data)) fbreak; }
    action cmd { if (settings->cmd && settings->cmd(parser->data, &parser->int4)) fbreak; }
    action cmdval { if (str && settings->cmdval && settings->cmdval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action colbeg { if (settings->colbeg && settings->colbeg(parser->data)) fbreak; }
    action colend { if (--parser->n <= 0) fnext main; }
    action col { if (settings->col && settings->col(parser->data, &parser->int4)) fbreak; }
    action columnid { if (settings->columnid && settings->columnid(parser->data, &parser->int2)) fbreak; }
    action column { if (str && settings->column && settings->column(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action constraint { if (str && settings->constraint && settings->constraint(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action context { if (str && settings->context && settings->context(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action datatype { if (str && settings->datatype && settings->datatype(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action detail { if (str && settings->detail && settings->detail(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action errbeg { if (settings->errbeg && settings->errbeg(parser->data)) fbreak; }
    action error { if (settings->error && settings->error(parser->data, &parser->int4)) fbreak; }
    action file { if (str && settings->file && settings->file(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action format { if (settings->format && settings->format(parser->data, &parser->int2)) fbreak; }
    action function { if (str && settings->function && settings->function(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action hint { if (str && settings->hint && settings->hint(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action idle { if (settings->idle && settings->idle(parser->data)) fbreak; }
    action inerror { if (settings->inerror && settings->inerror(parser->data)) fbreak; }
    action int2 { if (!parser->i) { parser->i = 2; parser->int2 = 0; } parser->int2 |= (uint8_t)*p << ((2 << 2) * --parser->i); }
    action int4 { if (!parser->i) { parser->i = 4; parser->int4 = 0; } parser->int4 |= (uint8_t)*p << ((2 << 2) * --parser->i); }
    action internal { if (str && settings->internal && settings->internal(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action intrans { if (settings->intrans && settings->intrans(parser->data)) fbreak; }
    action key { if (settings->key && settings->key(parser->data, &parser->int4)) fbreak; }
    action line { if (str && settings->line && settings->line(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action main { fnext main; }
    action method { if (settings->method && settings->method(parser->data, &parser->int4)) fbreak; }
    action mod { if (settings->mod && settings->mod(parser->data, &parser->int4)) fbreak; }
    action name { if (str && settings->name && settings->name(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action nbytes { if (settings->nbytes && settings->nbytes(parser->data, &parser->int4)) fbreak; if (parser->int4 == (int32_t)-1) { if (--parser->n <= 0) fnext main; else fnext row; } }
    action ncols { parser->n = parser->int2; if (settings->ncols && settings->ncols(parser->data, &parser->n)) fbreak; }
    action nonlocalized { if (str && settings->nonlocalized && settings->nonlocalized(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action nrows { parser->n = parser->int2; if (settings->nrows && settings->nrows(parser->data, &parser->n)) fbreak; }
    action oid { if (settings->oid && settings->oid(parser->data, &parser->int4)) fbreak; }
    action oidlen { if (settings->oidlen && settings->oidlen(parser->data, &parser->int2)) fbreak; }
    action opt { if (settings->opt && settings->opt(parser->data, &parser->int4)) fbreak; }
    action optkey { if (str && settings->optkey && settings->optkey(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action optval { if (str && settings->optval && settings->optval(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action parse { if (settings->parse && settings->parse(parser->data)) fbreak; }
    action pid { if (settings->pid && settings->pid(parser->data, &parser->int4)) fbreak; }
    action primary { if (str && settings->primary && settings->primary(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action query { if (str && settings->query && settings->query(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action ready { if (settings->ready && settings->ready(parser->data)) fbreak; }
    action rowend { if (--parser->n <= 0) fnext main; }
    action row { if (settings->row && settings->row(parser->data, &parser->int4)) fbreak; }
    action schema { if (str && settings->schema && settings->schema(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action secret { if (settings->secret && settings->secret(parser->data)) fbreak; }
    action severity { if (str && settings->severity && settings->severity(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action sqlstate { if (str && settings->sqlstate && settings->sqlstate(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action statement { if (str && settings->statement && settings->statement(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action str { if (!str) str = p; if (str) parser->str = cs; }
    action tableid { if (settings->tableid && settings->tableid(parser->data, &parser->int4)) fbreak; }
    action table { if (str && settings->table && settings->table(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }

    any2 = any{2};
    any4 = any{4};
    str0 = (any - 0)* $str $str 0;
    str = any $str;
    int2 = any2 $int2;
    int4 = any4 $int4;

    error =
    (  67 str0 @sqlstate @/sqlstate
    |  68 str0 @detail @/detail
    |  70 str0 @file @/file
    |  72 str0 @hint @/hint
    |  76 str0 @line @/line
    |  77 str0 @primary @/primary
    |  80 str0 @statement @/statement
    |  82 str0 @function @/function
    |  83 str0 @severity @/severity
    |  86 str0 @nonlocalized @/nonlocalized
    |  87 str0 @context @/context
    |  99 str0 @column @/column
    | 100 str0 @datatype @/datatype
    | 110 str0 @constraint @/constraint
    | 112 str0 @internal @/internal
    | 113 str0 @query @/query
    | 115 str0 @schema @/schema
    | 116 str0 @table @/table
    );

    col = str0 @name @/name int4 @tableid int2 @columnid int4 @oid int2 @oidlen int4 @mod int2 @format;
    row = int4 @nbytes str @byte @/byte;

    main :=
    ( 49 any4 @parse
    | 50 any4 @bind
    | 51 any4 @close
    | 67 int4 @cmd str0 @cmdval @/cmdval
    | 68 int4 @row int2 @nrows (row @rowend)*
    | 69 int4 @error (error >errbeg)* 0
    | 75 any4 @secret int4 @pid int4 @key
    | 82 any4 @auth int4 @method
    | 83 int4 @opt str0 @optkey @/optkey str0 @optval @/optval
    | 84 int4 @col int2 @ncols (col >colbeg @colend)*
    | 90 any4 @ready (69 @inerror | 73 @idle | 84 @intrans)
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
