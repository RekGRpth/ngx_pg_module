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
    uint16_t s;
    uint32_t l;
    uint32_t nbytes;
    uint8_t i;
} pg_parser_t;

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser->data, p))) fbreak; }
    action atttypmod { if (settings->atttypmod && (rc = settings->atttypmod(parser->data, &parser->l))) fbreak; }
    action auth { if (settings->auth && (rc = settings->auth(parser->data))) fbreak; }
    action bind { if (settings->bind && (rc = settings->bind(parser->data))) fbreak; }
    action close { if (settings->close && (rc = settings->close(parser->data))) fbreak; }
    action columnid { if (settings->columnid && (rc = settings->columnid(parser->data, &parser->s))) fbreak; }
    action column { if (s && settings->column && (rc = settings->column(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action command { if (s && settings->command && (rc = settings->command(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action complete { if (settings->complete && (rc = settings->complete(parser->data))) fbreak; }
    action constraint { if (s && settings->constraint && (rc = settings->constraint(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action context { if (s && settings->context && (rc = settings->context(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action datatype { if (s && settings->datatype && (rc = settings->datatype(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action detail { if (s && settings->detail && (rc = settings->detail(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action error { if (settings->error && (rc = settings->error(parser->data))) fbreak; }
    action fatal { if (settings->fatal && (rc = settings->fatal(parser->data))) fbreak; }
    action field { if (settings->field && (rc = settings->field(parser->data))) fbreak; }
    action file { if (s && settings->file && (rc = settings->file(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action format { if (settings->format && (rc = settings->format(parser->data, &parser->s))) fbreak; }
    action function { if (s && settings->function && (rc = settings->function(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action hint { if (s && settings->hint && (rc = settings->hint(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) fbreak; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) fbreak; }
    action internal { if (s && settings->internal && (rc = settings->internal(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) fbreak; }
    action key { if (settings->key && (rc = settings->key(parser->data, &parser->l))) fbreak; }
    action line { if (s && settings->line && (rc = settings->line(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action long { if (!parser->i) { parser->i = 4; parser->l = 0; } parser->l |= *p << ((2 << 2) * --parser->i); }
    action method { if (settings->method && (rc = settings->method(parser->data, &parser->l))) fbreak; }
    action name { if (s && settings->name && (rc = settings->name(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action nbytescheck { if (parser->nbytes--) fgoto byte; if (s && settings->byte && (rc = settings->byte(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; fhold; fnext tup; }
    action nbytes { parser->nbytes = parser->l; if (settings->nbytes && (rc = settings->nbytes(parser->data, &parser->nbytes))) fbreak; }
    action nfieldscheck { if (!--parser->nfields) fnext main; }
    action nfields { parser->nfields = parser->s; if (settings->nfields && (rc = settings->nfields(parser->data, &parser->nfields))) fbreak; }
    action nonlocalized { if (s && settings->nonlocalized && (rc = settings->nonlocalized(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action ntupscheck { if (!--parser->ntups) fnext main; }
    action ntups { parser->ntups = parser->s; if (settings->ntups && (rc = settings->ntups(parser->data, &parser->ntups))) fbreak; }
    action option { if (s && settings->option && (rc = settings->option(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) fbreak; }
    action pid { if (settings->pid && (rc = settings->pid(parser->data, &parser->l))) fbreak; }
    action primary { if (s && settings->primary && (rc = settings->primary(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action query { if (s && settings->query && (rc = settings->query(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) fbreak; }
    action schema { if (s && settings->schema && (rc = settings->schema(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) fbreak; }
    action severity { if (s && settings->severity && (rc = settings->severity(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action short { if (!parser->i) { parser->i = 2; parser->s = 0; } parser->s |= *p << ((2 << 2) * --parser->i); }
    action sqlstate { if (s && settings->sqlstate && (rc = settings->sqlstate(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action statement { if (s && settings->statement && (rc = settings->statement(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action status { if (settings->status && (rc = settings->status(parser->data, &parser->l))) fbreak; }
    action str { if (!s) s = p; if (s) parser->str = cs; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser->data, &parser->l))) fbreak; }
    action table { if (s && settings->table && (rc = settings->table(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }
    action tup { if (settings->tup && (rc = settings->tup(parser->data))) fbreak; }
    action typid { if (settings->typid && (rc = settings->typid(parser->data, &parser->l))) fbreak; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser->data, &parser->s))) fbreak; }
    action unknown { if (settings->unknown && (rc = settings->unknown(parser->data, pe - p, p))) fbreak; }
    action value { if (s && settings->value && (rc = settings->value(parser->data, p - s, s))) fbreak; s = NULL; parser->str = 0; }

    byte = any $str @nbytescheck;
    char = any - 0;
    long = any{4} $long;
    short = any{2} $short;
    str = char* $str 0;

    atttypmod = long @atttypmod;
    columnid = short @columnid;
    command = str @command;
    format = short @format;
    idle = "I" @idle;
    inerror = "E" @inerror;
    intrans = "T" @intrans;
    key = long @key;
    method = long @method;
    name = str @name;
    nbytes = long @nbytes;
    nfields = short @nfields;
    ntups = short @ntups;
    pid = long @pid;
    option = str @option;
    value = str @value;
    tableid = long @tableid;
    typid = long @typid;
    typlen = short @typlen;

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
    |"E" any{4} @error error*
    |"K" any{4} @secret pid key
    |"R" any{4} @auth method
    |"S" long @status option value
    |"T" any{4} @field nfields field*
    |"Z" any{4} @ready ready
    )** $all $!unknown;

    write data;
}%%

long pg_parser_execute(pg_parser_t *parser, size_t size, uint8_t **data) {
    const pg_parser_settings_t *settings = parser->settings;
    const uint8_t *eof = NULL;
    const uint8_t *p = *data;
    const uint8_t *pe = p + size;
    const uint8_t *s = parser->cs == parser->str ? p : NULL;
    int cs = parser->cs;
    long rc = 0;
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
