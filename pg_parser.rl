#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pg_parser.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

%%{
    machine pg_parser;
    alphtype unsigned char;

    action all { if (settings->all && (rc = settings->all(parser, (uintptr_t)p))) return rc; }
    action any_all { parser->any[parser->i++] = *p; }
    action any_open { parser->i = 0; }
    action auth { if (settings->auth && (rc = settings->auth(parser))) return rc; }
    action auth_method { if (settings->auth_method && (rc = settings->auth_method(parser, (uintptr_t)ntohl(*(uint32_t *)parser->any)))) return rc; }
    action bind { if (settings->bind && (rc = settings->bind(parser))) return rc; }
    action close { if (settings->close && (rc = settings->close(parser))) return rc; }
    action command { p < e }
    action complete { if (settings->complete && (rc = settings->complete(parser))) return rc; }
    action complete_val { if (s && p - s > 0 && settings->complete_val && (rc = settings->complete_val(parser, p - s, s))) return rc; s = NULL; }
    action data { if (settings->data && (rc = settings->data(parser))) return rc; }
    action data_len { if (settings->data_len && (rc = settings->data_len(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action data_nfields { if (settings->data_nfields && (rc = settings->data_nfields(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action data_val { if (s && p - s > 0 && settings->data_val && (rc = settings->data_val(parser, p - s, s))) return rc; s = NULL; }
    action len { parser->len = ntohl(*(uint32_t *)parser->any) - 4; if (settings->len && (rc = settings->len(parser))) return rc; if (parser->len) e = p + parser->len; }
    action parse { if (settings->parse && (rc = settings->parse(parser))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser))) return rc; }
    action ready_idle { if (settings->ready_idle && (rc = settings->ready_idle(parser))) return rc; }
    action ready_inerror { if (settings->ready_inerror && (rc = settings->ready_inerror(parser))) return rc; }
    action ready_intrans { if (settings->ready_intrans && (rc = settings->ready_intrans(parser))) return rc; }
    action tup_atttypmod { fprintf(stderr, "tup_atttypmod = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action tup_columnid { if (settings->tup_columnid && (rc = settings->tup_columnid(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action tup_format { if (settings->tup_format && (rc = settings->tup_format(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action tup_name { if (s && p - s > 0 && settings->tup_name && (rc = settings->tup_name(parser, p - s, s))) return rc; s = NULL; }
    action tup_tableid { if (settings->tup_tableid && (rc = settings->tup_tableid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action tup_typid { if (settings->tup_typid && (rc = settings->tup_typid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action tup_typlen { if (settings->tup_typlen && (rc = settings->tup_typlen(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action tup { if (settings->tup && (rc = settings->tup(parser))) return rc; }
    action tup_nfields { if (settings->tup_nfields && (rc = settings->tup_nfields(parser, ntohs(*(uint16_t *)parser->any)))) return rc; }
    action secret_pid { if (settings->secret_pid && (rc = settings->secret_pid(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action secret { if (settings->secret && (rc = settings->secret(parser))) return rc; }
    action secret_key { if (settings->secret_key && (rc = settings->secret_key(parser, ntohl(*(uint32_t *)parser->any)))) return rc; }
    action status_done { if (settings->status_done && (rc = settings->status_done(parser))) return rc; }
    action status { if (settings->status && (rc = settings->status(parser))) return rc; }
    action status_key { if (s && p - s > 0 && settings->status_key && (rc = settings->status_key(parser, p - s, s))) return rc; s = NULL; }
    action status_open { if (settings->status_open && (rc = settings->status_open(parser))) return rc; }
    action status_val { if (s && p - s > 0 && settings->status_val && (rc = settings->status_val(parser, p - s, s))) return rc; s = NULL; }
    action str_all { if (s) parser->str = cs; }
    action str_open { if (!s) s = p; }

    eos = 0;
    char = any - eos;
    any2 = any{2} >(any_open) $(any_all);
    any4 = any{4} >(any_open) $(any_all);
    str = char* >(str_open) $(str_all);
    len = any4 %(len);

    ready_idle = "I" %(ready_idle);
    ready_inerror = "E" %(ready_inerror);
    ready_intrans = "T" %(ready_intrans);

    main :=
    (   "1" %(parse) len
    |   "2" %(bind) len
    |   "3" %(close) len
    |   "C" %(complete) len str %(complete_val) eos
    |   "D" %(data) len any2 %(data_nfields) (any4 %(data_len) str %(data_val))** when command
    |   "K" %(secret) len any4 %(secret_pid) any4 %(secret_key)
    |   "R" %(auth) len any4 %(auth_method)
    |   "S" %(status) len str >(status_open) %(status_key) eos str %(status_val) %(status_done) eos
    |   "T" %(tup) len any2 %(tup_nfields) (str %(tup_name) eos any4 %(tup_tableid) any2 %(tup_columnid) any4 %(tup_typid) any2 %(tup_typlen) any4 %(tup_atttypmod) any2 %(tup_format))** when command
    |   "Z" %(ready) len (ready_idle | ready_inerror | ready_intrans)
    )** $(all);

    write data;
}%%

void pg_parser_init(pg_parser_t *parser) {
    int cs = 0;
    void *data = parser->data;
    %% write init;
    memset(parser, 0, sizeof(*parser));
    parser->data = data;
    parser->cs = cs;
}

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *p, const unsigned char *pe) {
    const unsigned char *b = p;
    const unsigned char *eof = pe;
    const unsigned char *e = parser->len ? p + parser->len : pe;
    const unsigned char *s = parser->cs == parser->str ? p : NULL;
    int cs = parser->cs;
    int rc = 0;
    fprintf(stderr, "got = %i\n", (int)(pe - p));
    %% write exec;
    parser->cs = cs;
    fprintf(stderr, "ret = %i\n", (int)(p - b));
    return p - b;
}
