#include <arpa/inet.h>
#include <stddef.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const void *data;
    int cmd;
    int cs;
    int i;
    int len;
    int str;
    unsigned char any[4];
} pg_parser_t;

static int when(pg_parser_t *parser, const pg_parser_settings_t *settings, int c) {
    int rc;
    if (settings->when && (rc = settings->when(parser->data, (uintptr_t)c))) return rc;
    return c;
}

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser->data, parser->len, p))) return rc; }
    action any_all { parser->any[parser->i++] = *p; }
    action any_open { parser->i = 0; }
    action atttypmod { if (settings->atttypmod && (rc = settings->atttypmod(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action auth { if (settings->auth && (rc = settings->auth(parser->data))) return rc; }
    action bind { if (settings->bind && (rc = settings->bind(parser->data))) return rc; }
    action char_all { if (s) parser->str = cs; }
    action char_open { if (!s) s = p; }
    action close { if (settings->close && (rc = settings->close(parser->data))) return rc; }
    action columnid { if (settings->columnid && (rc = settings->columnid(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action complete { if (settings->complete && (rc = settings->complete(parser->data))) return rc; }
    action complete_val { if (s && p - s > 0 && settings->complete_val && (rc = settings->complete_val(parser->data, p - s, s))) return rc; s = NULL; }
    action data { if (settings->data && (rc = settings->data(parser->data))) return rc; }
    action data_len { if (settings->data_len && (rc = settings->data_len(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action data_val { if (s && p - s > 0 && settings->data_val && (rc = settings->data_val(parser->data, p - s, s))) return rc; s = NULL; }
    action desc { if (settings->desc && (rc = settings->desc(parser->data))) return rc; }
    action field { if (s && p - s > 0 && settings->field && (rc = settings->field(parser->data, p - s, s))) return rc; s = NULL; }
    action format { if (settings->format && (rc = settings->format(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) return rc; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) return rc; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) return rc; }
    action key { if (settings->key && (rc = settings->key(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action len { if (settings->len && (rc = settings->len(parser->data, (uintptr_t)(parser->len = ntohl(*(uint32_t *)parser->any) - 4)))) return rc; if (!c) c = p; if (c) parser->cmd = cs; }
    action method { if (settings->method && (rc = settings->method(parser->data, (uintptr_t)ntohl(*(uint32_t *)parser->any)))) return rc; }
    action nfields { if (settings->nfields && (rc = settings->nfields(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) return rc; }
    action pid { if (settings->pid && (rc = settings->pid(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) return rc; }
    action status { if (settings->status && (rc = settings->status(parser->data))) return rc; }
    action status_key { if (s && p - s > 0 && settings->status_key && (rc = settings->status_key(parser->data, p - s, s))) return rc; s = NULL; }
    action status_val { if (s && p - s > 0 && settings->status_val && (rc = settings->status_val(parser->data, p - s, s))) return rc; s = NULL; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action then { when(parser, settings, !parser->len || p < c + parser->len) }
    action tupnfields { if (settings->tupnfields && (rc = settings->tupnfields(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action typid { if (settings->typid && (rc = settings->typid(parser->data, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser->data, ntohs(*(uint16_t *)parser->any)))) return rc; }

    char = (any - 0)** >char_open $char_all;
    long = any{4} >any_open $any_all;
    small = any{2} >any_open $any_all;

    main :=
    (   "1" long %len %parse when then
    |   "2" long %len %bind when then
    |   "3" long %len %close when then
    |   "C" long %len %complete char %complete_val 0 when then
    |   "D" long %len %data small %tupnfields (long %data_len char %data_val)** when then
    |   "K" long %len %secret long %pid long %key when then
    |   "R" long %len %auth long %method when then
    |   "S" long %len %status char %status_key 0 char %status_val 0
    |   "T" long %len %desc small %nfields (char %field 0 long %tableid small %columnid long %typid small %typlen long %atttypmod small %format)** when then
    |   "Z" long %len %ready ("I" %idle | "E" %inerror | "T" %intrans) when then
    )** $all;

    write data;
}%%

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *b, const unsigned char *p, const unsigned char *pe, const unsigned char *eof) {
    const unsigned char *c = parser->cs == parser->cmd ? p : NULL;
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
