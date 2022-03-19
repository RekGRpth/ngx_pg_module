#include <arpa/inet.h>
#include <stddef.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const void *data;
    int cs;
    int str;
    uint16_t nfields;
    uint16_t ntups;
    uint32_t len;
    struct {
        short int i;
        unsigned char d[4];
    } l;
    struct {
        short int i;
        unsigned char d[2];
    } s;
} pg_parser_t;

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser->data, (uintptr_t)p))) return rc; }
    action atttypmod { if (settings->atttypmod && (rc = settings->atttypmod(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action auth { if (settings->auth && (rc = settings->auth(parser->data))) return rc; }
    action bind { if (settings->bind && (rc = settings->bind(parser->data))) return rc; }
    action close { if (settings->close && (rc = settings->close(parser->data))) return rc; }
    action columnid { if (settings->columnid && (rc = settings->columnid(parser->data, ntohs(*(uint16_t *)parser->s.d)))) return rc; }
    action complete { if (settings->complete && (rc = settings->complete(parser->data))) return rc; }
    action complete_val { if (s && settings->complete_val && (rc = settings->complete_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action field { if (settings->field && (rc = settings->field(parser->data))) return rc; }
    action format { if (settings->format && (rc = settings->format(parser->data, ntohs(*(uint16_t *)parser->s.d)))) return rc; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) return rc; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) return rc; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) return rc; }
    action key { if (settings->key && (rc = settings->key(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action long { if (parser->l.i >= 4) parser->l.i = 0; parser->l.d[parser->l.i++] = *p; }
    action method { if (settings->method && (rc = settings->method(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action morebyte { if (!--parser->len) fnext tup; }
    action morefields { if (!--parser->nfields) fnext main; }
    action moretups { if (!--parser->ntups) fnext main; }
    action name { if (s && settings->name && (rc = settings->name(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action nfields { parser->nfields = ntohs(*(uint16_t *)parser->s.d); if (settings->nfields && (rc = settings->nfields(parser->data, parser->nfields))) return rc; }
    action ntups { parser->ntups = ntohs(*(uint16_t *)parser->s.d); if (settings->ntups && (rc = settings->ntups(parser->data, parser->ntups))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) return rc; }
    action pid { if (settings->pid && (rc = settings->pid(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) return rc; }
    action short { if (parser->s.i >= 2) parser->s.i = 0; parser->s.d[parser->s.i++] = *p; }
    action status { if (settings->status && (rc = settings->status(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action status_key { if (s && settings->status_key && (rc = settings->status_key(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action status_val { if (s && settings->status_val && (rc = settings->status_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action str { if (!s) s = p; if (s) parser->str = cs; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action tup { if (settings->tup && (rc = settings->tup(parser->data))) return rc; }
    action tup_len { parser->len = ntohl(*(uint32_t *)parser->l.d); if (settings->tup_len && (rc = settings->tup_len(parser->data, parser->len))) return rc; }
    action tup_val { if (s && settings->tup_val && (rc = settings->tup_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action typid { if (settings->typid && (rc = settings->typid(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser->data, ntohs(*(uint16_t *)parser->s.d)))) return rc; }

    byte = any $str;
    bytestr = (byte @morebyte)**;
    long = any{4} $long;
    short = any{2} $short;
    str = (any - 0) $str;
    zerostr = str** 0;

    atttypmod = long @atttypmod;
    columnid = short @columnid;
    complete_val = zerostr @complete_val;
    format = short @format;
    idle = "I" @idle;
    inerror = "E" @inerror;
    intrans = "T" @intrans;
    key = long @key;
    method = long @method;
    name = zerostr @name;
    nfields = short @nfields;
    ntups = short @ntups;
    pid = long @pid;
    status_key = zerostr @status_key;
    status_val = zerostr @status_val;
    tableid = long @tableid;
    tup_len = long @tup_len;
    tup_val = bytestr @tup_val;
    typid = long @typid;
    typlen = short @typlen;

    field = name tableid columnid typid typlen atttypmod format;
    ready = idle | inerror | intrans;
    tup = tup_len tup_val;

    main :=
    (   "1" any{4} @parse
    |   "2" any{4} @bind
    |   "3" any{4} @close
    |   "C" any{4} @complete complete_val
    |   "D" any{4} @tup ntups (tup @moretups)**
    |   "K" any{4} @secret pid key
    |   "R" any{4} @auth method
    |   "S" long @status status_key status_val
    |   "T" any{4} @field nfields (field @morefields)**
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
