#include <arpa/inet.h>
#include <stddef.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_parser_t {
    const void *data;
    int cs;
    int i;
    int str;
    uint16_t nfields;
    uint16_t tupnfields;
//    uint32_t len;
    unsigned char extend[4];
} pg_parser_t;

/*static int moredesc(pg_parser_t *parser, const pg_parser_settings_t *settings, int c) {
    int rc;
    if (settings->moredesc && (rc = settings->moredesc(parser->data, c))) return rc;
    return c;
}*/

/*static int morelen(pg_parser_t *parser, const pg_parser_settings_t *settings, int c) {
    int rc;
    if (settings->morelen && (rc = settings->morelen(parser->data, c))) return rc;
    return c;
}*/

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser->data, (uintptr_t)p))) return rc; /*if (parser->len) parser->len--;*/ }
    action atttypmod { if (settings->atttypmod && (rc = settings->atttypmod(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
    action auth { if (settings->auth && (rc = settings->auth(parser->data))) return rc; }
    action bind { if (settings->bind && (rc = settings->bind(parser->data))) return rc; }
    action char_all { if (s) parser->str = cs; }
    action char_open { if (!s) s = p; }
    action close { if (settings->close && (rc = settings->close(parser->data))) return rc; }
    action columnid { if (settings->columnid && (rc = settings->columnid(parser->data, ntohs(*(uint16_t *)parser->extend)))) return rc; }
    action complete { if (settings->complete && (rc = settings->complete(parser->data))) return rc; }
    action complete_val { if (s && p - s > 0 && settings->complete_val && (rc = settings->complete_val(parser->data, p - s, s))) return rc; s = NULL; }
    action data { if (settings->data && (rc = settings->data(parser->data))) return rc; }
    action data_len { if (settings->data_len && (rc = settings->data_len(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
    action data_val { if (s && p - s > 0 && settings->data_val && (rc = settings->data_val(parser->data, p - s, s))) return rc; s = NULL; }
    action desc { if (settings->desc && (rc = settings->desc(parser->data))) return rc; }
    action extend_all { parser->extend[parser->i++] = *p; }
    action extend_open { parser->i = 0; }
    action field { if (s && p - s > 0 && settings->field && (rc = settings->field(parser->data, p - s, s))) return rc; s = NULL; }
    action format { if (settings->format && (rc = settings->format(parser->data, ntohs(*(uint16_t *)parser->extend)))) return rc; }
    action idle { if (settings->idle && (rc = settings->idle(parser->data))) return rc; }
    action inerror { if (settings->inerror && (rc = settings->inerror(parser->data))) return rc; }
    action intrans { if (settings->intrans && (rc = settings->intrans(parser->data))) return rc; }
    action key { if (settings->key && (rc = settings->key(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
#    action len { if (settings->len && (rc = settings->len(parser->data, parser->len = ntohl(*(uint32_t *)parser->extend) - 4))) return rc; }
    action method { if (settings->method && (rc = settings->method(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
    action moredata { --parser->tupnfields }
    action moredesc { --parser->nfields }
#    action morelen { morelen(parser, settings, parser->len) }
    action nfields { if (settings->nfields && (rc = settings->nfields(parser->data, parser->nfields = ntohs(*(uint16_t *)parser->extend)))) return rc; }
    action parse { if (settings->parse && (rc = settings->parse(parser->data))) return rc; }
    action pid { if (settings->pid && (rc = settings->pid(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser->data))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser->data))) return rc; }
    action status { if (settings->status && (rc = settings->status(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
    action status_key { if (s && p - s > 0 && settings->status_key && (rc = settings->status_key(parser->data, p - s, s))) return rc; s = NULL; }
    action status_val { if (s && p - s > 0 && settings->status_val && (rc = settings->status_val(parser->data, p - s, s))) return rc; s = NULL; }
    action tableid { if (settings->tableid && (rc = settings->tableid(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
    action tupnfields { if (settings->tupnfields && (rc = settings->tupnfields(parser->data, parser->tupnfields = ntohs(*(uint16_t *)parser->extend)))) return rc; }
    action typid { if (settings->typid && (rc = settings->typid(parser->data, ntohl(*(uint32_t *)parser->extend)))) return rc; }
    action typlen { if (settings->typlen && (rc = settings->typlen(parser->data, ntohs(*(uint16_t *)parser->extend)))) return rc; }

    char = (extend - 0)** >char_open $char_all;
    long = extend{4} >extend_open $extend_all;
    small = extend{2} >extend_open $extend_all;

    main :=
    (   "1" long %~parse
    |   "2" long %~bind
    |   "3" long %~close
    |   "C" long %~complete char %~complete_val 0
    |   "D" long %~data small %~tupnfields (long %~data_len char %~data_val %when moredata)**
    |   "K" long %~secret long %~pid long %~key
    |   "R" long %~auth long %~method
    |   "S" long %~status char %status_key 0 char %status_val 0
    |   "T" long %~desc small %~nfields (char %~field 0 long %~tableid small %~columnid long %~typid small %~typlen long %~atttypmod small %~format %when moredesc)**
    |   "Z" long %~ready ("I" %~idle | "E" %~inerror | "T" %~intrans)
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
