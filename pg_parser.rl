#include <stddef.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const void *data;
    int cs;
    int str;
    unsigned char i;
    unsigned long l;
    unsigned long nbytes;
    unsigned short nfields;
    unsigned short ntups;
    unsigned short s;
} pg_parser_t;

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser->data, p))) return rc; }
    action atttypmod { if (settings->atttypmod && (rc = settings->atttypmod(parser->data, &parser->l))) return rc; }
    action auth { if (settings->auth && (rc = settings->auth(parser->data))) return rc; }
    action bind { if (settings->bind && (rc = settings->bind(parser->data))) return rc; }
    action close { if (settings->close && (rc = settings->close(parser->data))) return rc; }
    action columnid { if (settings->columnid && (rc = settings->columnid(parser->data, &parser->s))) return rc; }
    action complete { if (settings->complete && (rc = settings->complete(parser->data))) return rc; }
    action complete_val { if (s && settings->complete_val && (rc = settings->complete_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action field { if (settings->field && (rc = settings->field(parser->data))) return rc; }
    action format { if (settings->format && (rc = settings->format(parser->data, &parser->s))) return rc; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) return rc; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) return rc; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) return rc; }
    action key { if (settings->key && (rc = settings->key(parser->data, &parser->l))) return rc; }
    action long { if (!parser->i) { parser->i = 4; parser->l = 0; } parser->l |= *p << ((2 << 2) * --parser->i); }
    action method { if (settings->method && (rc = settings->method(parser->data, &parser->l))) return rc; }
    action name { if (s && settings->name && (rc = settings->name(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action nbytescheck { if (parser->nbytes--) fgoto byte; if (s && settings->byte && (rc = settings->byte(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; fhold; fnext tup; }
    action nbytes { parser->nbytes = parser->l; if (settings->nbytes && (rc = settings->nbytes(parser->data, &parser->nbytes))) return rc; }
    action nfieldscheck { if (!--parser->nfields) fnext main; }
    action nfields { parser->nfields = parser->s; if (settings->nfields && (rc = settings->nfields(parser->data, &parser->nfields))) return rc; }
    action ntupscheck { if (!--parser->ntups) fnext main; }
    action ntups { parser->ntups = parser->s; if (settings->ntups && (rc = settings->ntups(parser->data, &parser->ntups))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) return rc; }
    action pid { if (settings->pid && (rc = settings->pid(parser->data, &parser->l))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) return rc; }
    action short { if (!parser->i) { parser->i = 2; parser->s = 0; } parser->s |= *p << ((2 << 2) * --parser->i); }
    action status { if (settings->status && (rc = settings->status(parser->data, &parser->l))) return rc; }
    action status_key { if (s && settings->status_key && (rc = settings->status_key(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action status_val { if (s && settings->status_val && (rc = settings->status_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action str { if (!s) s = p; if (s) parser->str = cs; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser->data, &parser->l))) return rc; }
    action tup { if (settings->tup && (rc = settings->tup(parser->data))) return rc; }
    action typid { if (settings->typid && (rc = settings->typid(parser->data, &parser->l))) return rc; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser->data, &parser->s))) return rc; }
    action unknown { if (settings->unknown && (rc = settings->unknown(parser->data, pe - p, p))) return rc; }

    byte = any $str @nbytescheck;
    char = any - 0;
    long = any{4} $long;
    short = any{2} $short;
    str = char* $str 0;

    atttypmod = long @atttypmod;
    columnid = short @columnid;
    complete_val = str @complete_val;
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
    status_key = str @status_key;
    status_val = str @status_val;
    tableid = long @tableid;
    typid = long @typid;
    typlen = short @typlen;

    field = name tableid columnid typid typlen atttypmod format @nfieldscheck;
    ready = idle | inerror | intrans;
    tup = nbytes byte @ntupscheck;

    main :=
    (   "1" any{4} @parse
    |   "2" any{4} @bind
    |   "3" any{4} @close
    |   "C" any{4} @complete complete_val
    |   "D" any{4} @tup ntups tup*
    |   "K" any{4} @secret pid key
    |   "R" any{4} @auth method
    |   "S" long @status status_key status_val
    |   "T" any{4} @field nfields field*
    |   "Z" any{4} @ready ready
    )** $all $!unknown;

    write data;
}%%

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *b, const unsigned char *p, const unsigned char *pe, const unsigned char *eof) {
    const unsigned char *s = parser->cs == parser->str ? p : NULL;
    int cs = parser->cs;
    int rc = 0;
    %% write exec;
    parser->cs = cs;
    return p - b;
}

size_t pg_parser_size(void) {
    return sizeof(pg_parser_t);
}

void pg_parser_init(pg_parser_t *parser, const void *data) {
    int cs = 0;
    %% write init;
    parser->cs = cs;
    parser->data = data;
}
