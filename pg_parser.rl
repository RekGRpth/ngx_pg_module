#include <arpa/inet.h>
#include <stddef.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const void *data;
    int cs;
    int str;
    short int i;
    uint16_t nfields;
    uint16_t ntups;
    uint32_t nbytes;
    unsigned char any[4];
} pg_parser_t;

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser->data, (uintptr_t)p))) return rc; }
    action atttypmod { parser->i = 0; if (settings->atttypmod && (rc = settings->atttypmod(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action auth { if (settings->auth && (rc = settings->auth(parser->data))) return rc; }
    action bind { if (settings->bind && (rc = settings->bind(parser->data))) return rc; }
#    action byte { if (!s) s = p; if (s) parser->str = cs; }
    action close { if (settings->close && (rc = settings->close(parser->data))) return rc; }
    action columnid { parser->i = 0; if (settings->columnid && (rc = settings->columnid(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action complete { if (settings->complete && (rc = settings->complete(parser->data))) return rc; }
    action complete_val { if (s && settings->complete_val && (rc = settings->complete_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action field { if (settings->field && (rc = settings->field(parser->data))) return rc; }
    action format { parser->i = 0; if (settings->format && (rc = settings->format(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) return rc; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) return rc; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) return rc; }
    action key { parser->i = 0; if (settings->key && (rc = settings->key(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action len { parser->any[parser->i++] = *p; }
    action method { parser->i = 0; if (settings->method && (rc = settings->method(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action name { if (s && settings->name && (rc = settings->name(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action nbytescheck { if (parser->nbytes--) fgoto byte; if (s && settings->byte && (rc = settings->byte(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; fhold; fnext tup; }
    action nbytes { parser->i = 0; parser->nbytes = ntohl(*(uint32_t *)parser->any); if (settings->nbytes && (rc = settings->nbytes(parser->data, parser->nbytes))) return rc; }
    action nfieldscheck { if (!--parser->nfields) fnext main; }
    action nfields { parser->i = 0; parser->nfields = ntohs(*(uint16_t *)parser->any); if (settings->nfields && (rc = settings->nfields(parser->data, parser->nfields))) return rc; }
    action ntupscheck { if (!--parser->ntups) fnext main; }
    action ntups { parser->i = 0; parser->ntups = ntohs(*(uint16_t *)parser->any); if (settings->ntups && (rc = settings->ntups(parser->data, parser->ntups))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) return rc; }
    action pid { parser->i = 0; if (settings->pid && (rc = settings->pid(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) return rc; }
    action status_key { if (s && settings->status_key && (rc = settings->status_key(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action status { parser->i = 0; if (settings->status && (rc = settings->status(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action status_val { if (s && settings->status_val && (rc = settings->status_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action str { if (!s) s = p; if (s) parser->str = cs; }
    action tableid { parser->i = 0; if (settings->tableid && (rc = settings->tableid(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action tup { if (settings->tup && (rc = settings->tup(parser->data))) return rc; }
    action typid { parser->i = 0; if (settings->typid && (rc = settings->typid(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action typlen { parser->i = 0; if (settings->typlen && (rc = settings->typlen(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }

    char = any - 0;
    byte = any $str @nbytescheck;
    len = any $len;
    str = char* $str 0;

    atttypmod = len{4} @atttypmod;
    columnid = len{2} @columnid;
    complete_val = str @complete_val;
    format = len{2} @format;
    idle = "I" @idle;
    inerror = "E" @inerror;
    intrans = "T" @intrans;
    key = len{4} @key;
    method = len{4} @method;
    name = str @name;
    nbytes = len{4} @nbytes;
    nfields = len{2} @nfields;
    ntups = len{2} @ntups;
    pid = len{4} @pid;
    status_key = str @status_key;
    status_val = str @status_val;
    tableid = len{4} @tableid;
    typid = len{4} @typid;
    typlen = len{2} @typlen;

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
    |   "S" len{4} @status status_key status_val
    |   "T" any{4} @field nfields field*
    |   "Z" any{4} @ready ready
    )** $all;

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
