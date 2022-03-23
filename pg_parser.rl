#include <stddef.h>
#include <stdint.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const pg_parser_settings_t *settings;
    const void *data;
    int cs;
    int str;
    uint16_t nfields;
    uint16_t ntups;
    uint16_t uint16;
    uint32_t nbytes;
    uint32_t uint32;
    uint8_t uint8;
} pg_parser_t;

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser->data, p))) fbreak; }
    action atttypmod { if (settings->atttypmod && (rc = settings->atttypmod(parser->data, &parser->uint32))) fbreak; }
    action auth { if (settings->auth && (rc = settings->auth(parser->data))) fbreak; }
    action bind { if (settings->bind && (rc = settings->bind(parser->data))) fbreak; }
    action close { if (settings->close && (rc = settings->close(parser->data))) fbreak; }
    action columnid { if (settings->columnid && (rc = settings->columnid(parser->data, &parser->uint16))) fbreak; }
    action column { if (str && settings->column && (rc = settings->column(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action command { if (str && settings->command && (rc = settings->command(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action complete { if (settings->complete && (rc = settings->complete(parser->data))) fbreak; }
    action constraint { if (str && settings->constraint && (rc = settings->constraint(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action context { if (str && settings->context && (rc = settings->context(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action datatype { if (str && settings->datatype && (rc = settings->datatype(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action detail { if (str && settings->detail && (rc = settings->detail(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action error { if (settings->error && (rc = settings->error(parser->data, &parser->uint32))) fbreak; }
    action fatal { if (settings->fatal && (rc = settings->fatal(parser->data))) fbreak; }
    action field { if (settings->field && (rc = settings->field(parser->data))) fbreak; }
    action file { if (str && settings->file && (rc = settings->file(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action format { if (settings->format && (rc = settings->format(parser->data, &parser->uint16))) fbreak; }
    action function { if (str && settings->function && (rc = settings->function(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action hint { if (str && settings->hint && (rc = settings->hint(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) fbreak; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) fbreak; }
    action internal { if (str && settings->internal && (rc = settings->internal(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) fbreak; }
    action key { if (settings->key && (rc = settings->key(parser->data, &parser->uint32))) fbreak; }
    action line { if (str && settings->line && (rc = settings->line(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action method { if (settings->method && (rc = settings->method(parser->data, &parser->uint32))) fbreak; }
    action name { if (str && settings->name && (rc = settings->name(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action nbytescheck { if (parser->nbytes--) fgoto byte; if (str && settings->byte && (rc = settings->byte(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; fhold; fnext tup; }
    action nbytes { parser->nbytes = parser->uint32; if (settings->nbytes && (rc = settings->nbytes(parser->data, &parser->nbytes))) fbreak; }
    action nfieldscheck { if (!--parser->nfields) fnext main; }
    action nfields { parser->nfields = parser->uint16; if (settings->nfields && (rc = settings->nfields(parser->data, &parser->nfields))) fbreak; }
    action nonlocalized { if (str && settings->nonlocalized && (rc = settings->nonlocalized(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action ntupscheck { if (!--parser->ntups) fnext main; }
    action ntups { parser->ntups = parser->uint16; if (settings->ntups && (rc = settings->ntups(parser->data, &parser->ntups))) fbreak; }
    action option { if (str && settings->option && (rc = settings->option(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) fbreak; }
    action pid { if (settings->pid && (rc = settings->pid(parser->data, &parser->uint32))) fbreak; }
    action primary { if (str && settings->primary && (rc = settings->primary(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action query { if (str && settings->query && (rc = settings->query(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) fbreak; }
    action schema { if (str && settings->schema && (rc = settings->schema(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) fbreak; }
    action severity { if (str && settings->severity && (rc = settings->severity(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action sqlstate { if (str && settings->sqlstate && (rc = settings->sqlstate(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action statement { if (str && settings->statement && (rc = settings->statement(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action status { if (settings->status && (rc = settings->status(parser->data, &parser->uint32))) fbreak; }
    action str { if (!str) str = p; if (str) parser->str = cs; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser->data, &parser->uint32))) fbreak; }
    action table { if (str && settings->table && (rc = settings->table(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }
    action tup { if (settings->tup && (rc = settings->tup(parser->data))) fbreak; }
    action typid { if (settings->typid && (rc = settings->typid(parser->data, &parser->uint32))) fbreak; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser->data, &parser->uint16))) fbreak; }
    action uint16 { if (!parser->uint8) { parser->uint8 = 2; parser->uint16 = 0; } parser->uint16 |= *p << ((2 << 2) * --parser->uint8); }
    action uint32 { if (!parser->uint8) { parser->uint8 = 4; parser->uint32 = 0; } parser->uint32 |= *p << ((2 << 2) * --parser->uint8); }
    action unknown { if (settings->unknown && (rc = settings->unknown(parser->data, pe - p, p))) fbreak; }
    action value { if (str && settings->value && (rc = settings->value(parser->data, p - str, str))) fbreak; str = NULL; parser->str = 0; }

    byte = any $str @nbytescheck;
    char = any - 0;
    str = char* $str 0;
    uint16 = any{2} $uint16;
    uint32 = any{4} $uint32;

    atttypmod = uint32 @atttypmod;
    columnid = uint16 @columnid;
    command = str @command;
    format = uint16 @format;
    idle = "I" @idle;
    inerror = "E" @inerror;
    intrans = "T" @intrans;
    key = uint32 @key;
    method = uint32 @method;
    name = str @name;
    nbytes = uint32 @nbytes;
    nfields = uint16 @nfields;
    ntups = uint16 @ntups;
    pid = uint32 @pid;
    option = str @option;
    value = str @value;
    tableid = uint32 @tableid;
    typid = uint32 @typid;
    typlen = uint16 @typlen;

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
    ) $!unknown;
    field = name tableid columnid typid typlen atttypmod format @nfieldscheck;
    ready = idle | inerror | intrans;
    tup = nbytes byte @ntupscheck;

    main :=
    ("1" any{4} @parse
    |"2" any{4} @bind
    |"3" any{4} @close
    |"C" any{4} @complete command
    |"D" any{4} @tup ntups tup*
    |"E" uint32 @error error*
    |"K" any{4} @secret pid key
    |"R" any{4} @auth method
    |"S" uint32 @status option value
    |"T" any{4} @field nfields field*
    |"Z" any{4} @ready ready
    )** $all $!unknown;

    write data;
}%%

intptr_t pg_parser_execute(pg_parser_t *parser, size_t size, uint8_t **data) {
    const pg_parser_settings_t *settings = parser->settings;
    const uint8_t *eof = NULL;
    const uint8_t *p = *data;
    const uint8_t *pe = p + size;
    const uint8_t *str = parser->cs == parser->str ? p : NULL;
    int cs = parser->cs;
    intptr_t rc = 0;
    %% write exec;
    parser->cs = cs;
    *data = p;
    return rc;
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
