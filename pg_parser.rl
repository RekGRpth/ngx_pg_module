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
    action complete_val { if (s && p - s > 0 && settings->complete_val && (rc = settings->complete_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action field { if (settings->field && (rc = settings->field(parser->data))) return rc; }
    action format { if (settings->format && (rc = settings->format(parser->data, ntohs(*(uint16_t *)parser->s.d)))) return rc; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) return rc; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) return rc; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) return rc; }
    action key { if (settings->key && (rc = settings->key(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action long { if (parser->l.i >= 4) parser->l.i = 0; parser->l.d[parser->l.i++] = *p; }
    action method { if (settings->method && (rc = settings->method(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action morefields { --parser->nfields }
    action moretups { --parser->ntups }
    action name { if (s && p - s > 0 && settings->name && (rc = settings->name(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action nfields { parser->nfields = ntohs(*(uint16_t *)parser->s.d); if (settings->nfields && (rc = settings->nfields(parser->data, parser->nfields))) return rc; }
    action ntups { parser->ntups = ntohs(*(uint16_t *)parser->s.d); if (settings->ntups && (rc = settings->ntups(parser->data, parser->ntups))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) return rc; }
    action pid { if (settings->pid && (rc = settings->pid(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) return rc; }
    action short { if (parser->s.i >= 2) parser->s.i = 0; parser->s.d[parser->s.i++] = *p; }
    action status { if (settings->status && (rc = settings->status(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action status_key { if (s && p - s > 0 && settings->status_key && (rc = settings->status_key(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action status_val { if (s && p - s > 0 && settings->status_val && (rc = settings->status_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action str { if (!s) s = p; if (s) parser->str = cs; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action tup { if (settings->tup && (rc = settings->tup(parser->data))) return rc; }
    action tup_len { if (settings->tup_len && (rc = settings->tup_len(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action tup_val { if (s && p - s > 0 && settings->tup_val && (rc = settings->tup_val(parser->data, p - s, s))) return rc; s = NULL; parser->str = 0; }
    action typid { if (settings->typid && (rc = settings->typid(parser->data, ntohl(*(uint32_t *)parser->l.d)))) return rc; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser->data, ntohs(*(uint16_t *)parser->s.d)))) return rc; }

    char = extend - 0;
    extend4 = extend{4};
    long = extend{4} $long;
    short = extend{2} $short;
    str = char* $str;
    str0 = str 0;

    atttypmod = long @atttypmod;
    columnid = short @columnid;
    complete_val = str0 @complete_val;
    format = short @format;
    idle = "I" @idle;
    inerror = "E" @inerror;
    intrans = "T" @intrans;
    key = long @key;
    method = long @method;
    name = str0 @name;
    nfields = short @nfields;
    ntups = short @ntups;
    pid = long @pid;
    status_key = str0 @status_key;
    status_val = str0 @status_val;
    tableid = long @tableid;
    tup_len = long @tup_len;
    tup_val = str @tup_val;
    typid = long @typid;
    typlen = short @typlen;

    field = name tableid columnid typid typlen atttypmod format %when morefields;
    ready = idle | inerror | intrans;
    tup = tup_len tup_val %when moretups;

    main :=
    (   "1" extend4 @parse
    |   "2" extend4 @bind
    |   "3" extend4 @close
    |   "C" extend4 @complete complete_val
    |   "D" extend4 @tup ntups tup*
    |   "K" extend4 @secret pid key
    |   "R" extend4 @auth method
    |   "S" long @status status_key status_val
    |   "T" extend4 @field nfields field*
    |   "Z" extend4 @ready ready
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
