#include <arpa/inet.h>
#include <stddef.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser, (uintptr_t)p))) return rc; }
    action any_all { parser->any[parser->i++] = *p; }
    action any_open { parser->i = 0; }
    action atttypmod { if (settings->atttypmod && (rc = settings->atttypmod(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action auth { if (settings->auth && (rc = settings->auth(parser))) return rc; }
    action bind { if (settings->bind && (rc = settings->bind(parser))) return rc; }
    action char_all { if (s) parser->str = cs; }
    action char_open { if (!s) s = p; }
    action close { if (settings->close && (rc = settings->close(parser))) return rc; }
    action columnid { if (settings->columnid && (rc = settings->columnid(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action command { p < e }
    action complete { if (settings->complete && (rc = settings->complete(parser))) return rc; }
    action complete_val { if (s && p - s > 0 && settings->complete_val && (rc = settings->complete_val(parser, p - s, s))) return rc; s = NULL; }
    action data { if (settings->data && (rc = settings->data(parser))) return rc; }
    action data_len { if (settings->data_len && (rc = settings->data_len(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action data_val { if (s && p - s > 0 && settings->data_val && (rc = settings->data_val(parser, p - s, s))) return rc; s = NULL; }
    action desc { if (settings->desc && (rc = settings->desc(parser))) return rc; }
    action field { if (s && p - s > 0 && settings->field && (rc = settings->field(parser, p - s, s))) return rc; s = NULL; }
    action format { if (settings->format && (rc = settings->format(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action idle { if (settings->idle && (rc = settings->idle(parser))) return rc; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser))) return rc; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser))) return rc; }
    action key { if (settings->key && (rc = settings->key(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action len { if ((parser->len = ntohl(*(uint32_t *)parser->any))) e = p + parser->len - 4; if (settings->len && (rc = settings->len(parser, (uintptr_t)parser->len))) return rc; }
    action method { if (settings->method && (rc = settings->method(parser, (uintptr_t)ntohl(*(uint32_t *)parser->any)))) return rc; }
    action nfields { if (settings->nfields && (rc = settings->nfields(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser))) return rc; }
    action pid { if (settings->pid && (rc = settings->pid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser))) return rc; }
    action status { if (settings->status && (rc = settings->status(parser))) return rc; }
    action status_key { if (s && p - s > 0 && settings->status_key && (rc = settings->status_key(parser, p - s, s))) return rc; s = NULL; }
    action status_val { if (s && p - s > 0 && settings->status_val && (rc = settings->status_val(parser, p - s, s))) return rc; s = NULL; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action tupnfields { if (settings->tupnfields && (rc = settings->tupnfields(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action typid { if (settings->typid && (rc = settings->typid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }

    char = (any - 0)** >char_open $char_all;
    long = any{4} >any_open $any_all;
    small = any{2} >any_open $any_all;

    main :=
    (   "1" long %len >parse when command
    |   "2" long %len >bind when command
    |   "3" long %len >close when command
    |   "C" long %len >complete char %complete_val 0 when command
    |   "D" long %len >data small %tupnfields (long %data_len char %data_val)** when command
    |   "K" long %len >secret long %pid long %key when command
    |   "R" long %len >auth long %method when command
    |   "S" long %len char >status %status_key 0 char %status_val 0 when command
    |   "T" long %len >desc small %nfields (char %field 0 long %tableid small %columnid long %typid small %typlen long %atttypmod small %format)** when command
    |   "Z" long %len >ready ("I" %idle | "E" %inerror | "T" %intrans)
    )** $all;

    write data;
}%%

void pg_parser_init(pg_parser_t *parser) {
    int cs = 0;
    %% write init;
    parser->cs = cs;
}

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *p, const unsigned char *pe) {
    const unsigned char *b = p;
    const unsigned char *eof = pe;
    const unsigned char *e = parser->len ? p + parser->len - 4: pe;
    const unsigned char *s = parser->cs == parser->str ? p : NULL;
    int cs = parser->cs;
    int rc = 0;
    %% write exec;
    parser->cs = cs;
    return p - b;
}
