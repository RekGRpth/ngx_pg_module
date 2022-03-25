#include <stddef.h>
#include <stdint.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const pg_parser_settings_t *settings;
    const void *data;
    int cs;
    int str;
    uint16_t ncols;
    uint16_t nrows;
    uint16_t uint16;
    uint32_t nbytes;
    uint32_t uint32;
    uint8_t uint8;
} pg_parser_t;

%%{
    machine pg_parser;
    alphtype unsigned char;

#    action all { if (settings->all && settings->all(parser->data, p)) fbreak; }
    action auth { if (settings->auth && settings->auth(parser->data)) fbreak; }
    action bind { if (settings->bind && settings->bind(parser->data)) fbreak; }
    action close { if (settings->close && settings->close(parser->data)) fbreak; }
    action col { if (settings->col && settings->col(parser->data, &parser->uint32)) fbreak; }
    action columnid { if (settings->columnid && settings->columnid(parser->data, &parser->uint16)) fbreak; }
    action column { if (str && settings->column && settings->column(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action command { if (str && settings->command && settings->command(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action complete { if (settings->complete && settings->complete(parser->data, &parser->uint32)) fbreak; }
    action constraint { if (str && settings->constraint && settings->constraint(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action context { if (str && settings->context && settings->context(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action datatype { if (str && settings->datatype && settings->datatype(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action detail { if (str && settings->detail && settings->detail(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action error { if (settings->error && settings->error(parser->data, &parser->uint32)) fbreak; }
    action fatal { if (settings->fatal && settings->fatal(parser->data)) fbreak; }
    action file { if (str && settings->file && settings->file(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action format { if (settings->format && settings->format(parser->data, &parser->uint16)) fbreak; }
    action function { if (str && settings->function && settings->function(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action hint { if (str && settings->hint && settings->hint(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action idle { if (settings->idle && settings->idle(parser->data)) fbreak; }
    action inerror { if (settings->inerror && settings->inerror(parser->data)) fbreak; }
    action internal { if (str && settings->internal && settings->internal(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action intrans { if (settings->intrans && settings->intrans(parser->data)) fbreak; }
    action key { if (settings->key && settings->key(parser->data, &parser->uint32)) fbreak; }
    action line { if (str && settings->line && settings->line(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action main { fnext main; }
    action method { if (settings->method && settings->method(parser->data, &parser->uint32)) fbreak; }
    action mod { if (settings->mod && settings->mod(parser->data, &parser->uint32)) fbreak; }
    action name { if (str && settings->name && settings->name(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action nbytescheck { if (parser->nbytes == (uint32_t)-1) fnext row; if (parser->nbytes--) fgoto byte; if (str && settings->byte && settings->byte(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; fhold; fnext row; }
    action nbytes { parser->nbytes = parser->uint32; if (settings->nbytes && settings->nbytes(parser->data, &parser->nbytes)) fbreak; }
    action ncolscheck { if (!parser->ncols || !--parser->ncols) fnext main; }
    action ncols { parser->ncols = parser->uint16; if (settings->ncols && settings->ncols(parser->data, &parser->ncols)) fbreak; }
    action nonlocalized { if (str && settings->nonlocalized && settings->nonlocalized(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action nrowscheck { if (!parser->nrows || !--parser->nrows) fnext main; }
    action nrows { parser->nrows = parser->uint16; if (settings->nrows && settings->nrows(parser->data, &parser->nrows)) fbreak; }
    action oid { if (settings->oid && settings->oid(parser->data, &parser->uint32)) fbreak; }
    action oidlen { if (settings->oidlen && settings->oidlen(parser->data, &parser->uint16)) fbreak; }
    action option { if (str && settings->option && settings->option(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action parse { if (settings->parse && settings->parse(parser->data)) fbreak; }
    action pid { if (settings->pid && settings->pid(parser->data, &parser->uint32)) fbreak; }
    action primary { if (str && settings->primary && settings->primary(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action query { if (str && settings->query && settings->query(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action ready { if (settings->ready && settings->ready(parser->data)) fbreak; }
    action row { if (settings->row && settings->row(parser->data, &parser->uint32)) fbreak; }
    action schema { if (str && settings->schema && settings->schema(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action secret { if (settings->secret && settings->secret(parser->data)) fbreak; }
    action severity { if (str && settings->severity && settings->severity(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action sqlstate { if (str && settings->sqlstate && settings->sqlstate(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action statement { if (str && settings->statement && settings->statement(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action status { if (settings->status && settings->status(parser->data, &parser->uint32)) fbreak; }
    action str { if (!str) str = p; if (str) parser->str = cs; }
    action tableid { if (settings->tableid && settings->tableid(parser->data, &parser->uint32)) fbreak; }
    action table { if (str && settings->table && settings->table(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }
    action uint16 { if (!parser->uint8) { parser->uint8 = 2; parser->uint16 = 0; } parser->uint16 |= *p << ((2 << 2) * --parser->uint8); }
    action uint32 { if (!parser->uint8) { parser->uint8 = 4; parser->uint32 = 0; } parser->uint32 |= *p << ((2 << 2) * --parser->uint8); }
#    action unknown { if (settings->unknown && settings->unknown(parser->data, pe - p, p)) fbreak; }
    action value { if (str && settings->value && settings->value(parser->data, p - str, str)) fbreak; str = NULL; parser->str = 0; }

    any2 = any{2};
    any4 = any{4};
    byte = any $str;
    char = any - 0;
    str = char* $str 0;
    uint16 = any2 $uint16;
    uint32 = any4 $uint32;

    error =
    (0 @fatal
    |"c" str @column
    |"C" str @sqlstate
    |"d" str @datatype
    |"D" str @detail
    |"F" str @file
    |"H" str @hint
    |"L" str @line
    |"M" str @primary
    |"n" str @constraint
    |"p" str @internal
    |"P" str @statement
    |"q" str @query
    |"R" str @function
    |"s" str @schema
    |"S" str @severity
    |"t" str @table
    |"V" str @nonlocalized
    |"W" str @context
    );

    row = uint32 @nbytes (byte @nbytescheck)* @nrowscheck;

    main :=
    ("1" any4 @parse
    |"2" any4 @bind
    |"3" any4 @close
    |"C" uint32 @complete str @command
    |"D" uint32 @row uint16 @nrows row*
    |"E" uint32 @error error*
    |"K" any4 @secret uint32 @pid uint32 @key
    |"R" any4 @auth uint32 @method
    |"S" uint32 @status str @option str @value
    |"T" uint32 @col uint16 @ncols (str @name uint32 @tableid uint16 @columnid uint32 @oid uint16 @oidlen uint32 @mod uint16 @format @ncolscheck)*
    |"Z" any4 @ready ("I" @idle | "E" @inerror | "T" @intrans)
    ) %main;

    write data;
}%%

size_t pg_parser_execute(pg_parser_t *parser, const uint8_t *p, const uint8_t *pe) {
    const pg_parser_settings_t *settings = parser->settings;
    const uint8_t *b = p;
    const uint8_t *eof = NULL;
    const uint8_t *str = parser->cs == parser->str ? p : NULL;
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
