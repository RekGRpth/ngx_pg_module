#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const pg_parser_settings_t *settings;
    const void *data;
    int cs;
    int str;
    int16_t ncols;
    int16_t nrows;
    int16_t int16;
    int32_t nbytes;
    int32_t int32;
    int8_t int8;
} pg_parser_t;

%%{
    machine pg_parser;

    action all { if (settings->all && settings->all(parser->data, p)) fbreak; }
    action auth { if (settings->auth && settings->auth(parser->data)) fbreak; }
    action bind { if (settings->bind && settings->bind(parser->data)) fbreak; }
    action byte { if (--parser->nbytes >= 0) fgoto str; if (str && settings->byte && settings->byte(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; fhold; fnext row; }
    action close { if (settings->close && settings->close(parser->data)) fbreak; }
    action col { if (settings->col && settings->col(parser->data, &parser->int32)) fbreak; }
    action columnid { if (settings->columnid && settings->columnid(parser->data, &parser->int16)) fbreak; }
    action column { if (str && settings->column && settings->column(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action command { if (str && settings->command && settings->command(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action complete { if (settings->complete && settings->complete(parser->data, &parser->int32)) fbreak; }
    action constraint { if (str && settings->constraint && settings->constraint(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action context { if (str && settings->context && settings->context(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action datatype { if (str && settings->datatype && settings->datatype(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action detail { if (str && settings->detail && settings->detail(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action error { if (settings->error && settings->error(parser->data, &parser->int32)) fbreak; }
    action fatal { if (settings->fatal && settings->fatal(parser->data)) fbreak; }
    action file { if (str && settings->file && settings->file(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action format { if (settings->format && settings->format(parser->data, &parser->int16)) fbreak; }
    action function { if (str && settings->function && settings->function(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action hint { if (str && settings->hint && settings->hint(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action idle { if (settings->idle && settings->idle(parser->data)) fbreak; }
    action inerror { if (settings->inerror && settings->inerror(parser->data)) fbreak; }
    action internal { if (str && settings->internal && settings->internal(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action intrans { if (settings->intrans && settings->intrans(parser->data)) fbreak; }
    action key { if (settings->key && settings->key(parser->data, &parser->int32)) fbreak; }
    action line { if (str && settings->line && settings->line(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action main { fnext main; }
    action method { if (settings->method && settings->method(parser->data, &parser->int32)) fbreak; }
    action mod { if (settings->mod && settings->mod(parser->data, &parser->int32)) fbreak; }
    action name { if (str && settings->name && settings->name(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action nbytes { parser->nbytes = parser->int32; if (settings->nbytes && settings->nbytes(parser->data, &parser->nbytes)) fbreak; if (parser->nbytes == (int32_t)-1) { if (--parser->nrows <= 0) fnext main; else fnext row; } }
    action ncolscheck { if (--parser->ncols <= 0) fnext main; }
    action ncols { parser->ncols = parser->int16; if (settings->ncols && settings->ncols(parser->data, &parser->ncols)) fbreak; }
    action nonlocalized { if (str && settings->nonlocalized && settings->nonlocalized(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action nrowscheck { if (--parser->nrows <= 0) fnext main; }
    action nrows { parser->nrows = parser->int16; if (settings->nrows && settings->nrows(parser->data, &parser->nrows)) fbreak; }
    action oid { if (settings->oid && settings->oid(parser->data, &parser->int32)) fbreak; }
    action oidlen { if (settings->oidlen && settings->oidlen(parser->data, &parser->int16)) fbreak; }
    action option { if (str && settings->option && settings->option(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action parse { if (settings->parse && settings->parse(parser->data)) fbreak; }
    action pid { if (settings->pid && settings->pid(parser->data, &parser->int32)) fbreak; }
    action primary { if (str && settings->primary && settings->primary(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action query { if (str && settings->query && settings->query(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action ready { if (settings->ready && settings->ready(parser->data)) fbreak; }
    action row { if (settings->row && settings->row(parser->data, &parser->int32)) fbreak; }
    action schema { if (str && settings->schema && settings->schema(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action secret { if (settings->secret && settings->secret(parser->data)) fbreak; }
    action severity { if (str && settings->severity && settings->severity(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action sqlstate { if (str && settings->sqlstate && settings->sqlstate(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action statement { if (str && settings->statement && settings->statement(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action status { if (settings->status && settings->status(parser->data, &parser->int32)) fbreak; }
    action str { if (!str) str = p; if (str) parser->str = cs; }
    action tableid { if (settings->tableid && settings->tableid(parser->data, &parser->int32)) fbreak; }
    action table { if (str && settings->table && settings->table(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action int16 { if (!parser->int8) { parser->int8 = 2; parser->int16 = 0; } parser->int16 |= *p << ((2 << 2) * --parser->int8); }
    action int32 { if (!parser->int8) { parser->int8 = 4; parser->int32 = 0; } parser->int32 |= *p << ((2 << 2) * --parser->int8); }
    action unknown { if (settings->unknown && settings->unknown(parser->data, pe - p, p)) fbreak; }
    action value { if (str && settings->value && settings->value(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }

    any2 = any{2};
    any4 = any{4};
    str0 = (any - 0)* $str 0;
    str = any $str;
    int16 = any2 $int16;
    int32 = any4 $int32;

    error =
    (0 @fatal
    |"c" str0 @column
    |"C" str0 @sqlstate
    |"d" str0 @datatype
    |"D" str0 @detail
    |"F" str0 @file
    |"H" str0 @hint
    |"L" str0 @line
    |"M" str0 @primary
    |"n" str0 @constraint
    |"p" str0 @internal
    |"P" str0 @statement
    |"q" str0 @query
    |"R" str0 @function
    |"s" str0 @schema
    |"S" str0 @severity
    |"t" str0 @table
    |"V" str0 @nonlocalized
    |"W" str0 @context
    ) $!unknown;

    col = str0 @name int32 @tableid int16 @columnid int32 @oid int16 @oidlen int32 @mod int16 @format;
    row = int32 @nbytes str @byte;

    main :=
    ("1" any4 @parse
    |"2" any4 @bind
    |"3" any4 @close
    |"C" int32 @complete str0 @command
    |"D" int32 @row int16 @nrows (row @nrowscheck)*
    |"E" int32 @error error*
    |"K" any4 @secret int32 @pid int32 @key
    |"R" any4 @auth int32 @method
    |"S" int32 @status str0 @option str0 @value
    |"T" int32 @col int16 @ncols (col @ncolscheck)*
    |"Z" any4 @ready ("I" @idle | "E" @inerror | "T" @intrans)
    ) $all %main;

    write data;
}%%

size_t pg_parser_execute(pg_parser_t *parser, const char *p, const char *pe) {
    const pg_parser_settings_t *settings = parser->settings;
    const char *b = p;
    const char *eof = NULL;
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
