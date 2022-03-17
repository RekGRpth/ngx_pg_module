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
    action len { if (settings->len && (rc = settings->len(parser, (uintptr_t)ntohl(*(uint32_t *)parser->any)))) return rc; if (parser->len) e = p + parser->len; }
    action method { if (settings->method && (rc = settings->method(parser, (uintptr_t)ntohl(*(uint32_t *)parser->any)))) return rc; }
    action nfields { if (settings->nfields && (rc = settings->nfields(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser))) return rc; }
    action pid { if (settings->pid && (rc = settings->pid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser))) return rc; }
    action status { if (settings->status && (rc = settings->status(parser))) return rc; }
    action status_key { if (s && p - s > 0 && settings->status_key && (rc = settings->status_key(parser, p - s, s))) return rc; s = NULL; }
    action status_val { if (s && p - s > 0 && settings->status_val && (rc = settings->status_val(parser, p - s, s))) return rc; s = NULL; }
    action str_all { if (s) parser->str = cs; }
    action str_open { if (!s) s = p; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action tupnfields { if (settings->tupnfields && (rc = settings->tupnfields(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action typid { if (settings->typid && (rc = settings->typid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }

    eos = 0;
    char = any - eos;
    any2 = any{2} >any_open $any_all;
    any4 = any{4} >any_open $any_all;
    str = char* >str_open $str_all;
    len = any4 %len;

    main :=
    (   "1" any4 >parse
    |   "2" any4 >bind
    |   "3" any4 >close
    |   "C" any4 >complete str %complete_val eos
    |   "D" len >data any2 %tupnfields (any4 %data_len str %data_val)** when command
    |   "K" any4 >secret any4 %pid any4 %key
    |   "R" len >auth any4 %method when command
    |   "S" len str >status %status_key eos str %status_val eos when command
    |   "T" len >desc any2 %nfields (str %field eos any4 %tableid any2 %columnid any4 %typid any2 %typlen any4 %atttypmod any2 %format)** when command
    |   "Z" any4 >ready ("I" %idle | "E" %inerror | "T" %intrans)
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
    const unsigned char *e = parser->len ? p + parser->len : pe;
    const unsigned char *s = parser->cs == parser->str ? p : NULL;
    int cs = parser->cs;
    int rc = 0;
    %% write exec;
    parser->cs = cs;
    return p - b;
}
