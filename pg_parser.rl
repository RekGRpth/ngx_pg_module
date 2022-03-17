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
    action data_tupfield_len { fprintf(stderr, "data_tupfield_len = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action data_tupfield_val { if (s && p - s > 0) fprintf(stderr, "data_tupfield_val = %.*s\n", (int)(p - s), s); s = NULL; }
    action data_tupnfields { fprintf(stderr, "data_tupnfields = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action len { parser->len = ntohl(*(uint32_t *)parser->any) - 4; if (settings->len && (rc = settings->len(parser))) return rc; if (parser->len) e = p + parser->len; }
    action parse { if (settings->parse && (rc = settings->parse(parser))) return rc; }
    action ready { if (settings->ready && (rc = settings->ready(parser))) return rc; }
    action ready_trans_idle { fprintf(stderr, "ready_trans_idle\n"); }
    action ready_trans_inerror { fprintf(stderr, "ready_trans_inerror\n"); }
    action ready_trans_intrans { fprintf(stderr, "ready_trans_intrans\n"); }
    action ready_trans_unknown { fprintf(stderr, "ready_trans_unknown = %i:%c\n", *p, *p); }
    action row_field_atttypmod { fprintf(stderr, "row_field_atttypmod = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action row_field_columnid { fprintf(stderr, "row_field_columnid = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action row_field_format { fprintf(stderr, "row_field_format = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action row_field_name { if (s && p - s > 0) fprintf(stderr, "row_field_name = %.*s\n", (int)(p - s), s); s = NULL; }
    action row_field_tableid { fprintf(stderr, "row_field_tableid = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action row_field_typid { fprintf(stderr, "row_field_typid = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action row_field_typlen { fprintf(stderr, "row_field_typlen = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action row { if (settings->row && (rc = settings->row(parser))) return rc; }
    action row_nfields { fprintf(stderr, "row_nfields = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action secret_backend { fprintf(stderr, "secret_backend = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action secret { if (settings->secret && (rc = settings->secret(parser))) return rc; }
    action secret_key { fprintf(stderr, "secret_key = %i\n", ntohl(*(uint32_t *)parser->any)); }
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

    ready_trans_idle = "I" %(ready_trans_idle);
    ready_trans_inerror = "E" %(ready_trans_inerror);
    ready_trans_intrans = "T" %(ready_trans_intrans);
    ready_trans_unknown = any - [EIT] %(ready_trans_unknown);

    main :=
    (   "1" %(parse) len
    |   "2" %(bind) len
    |   "3" %(close) len
    |   "C" %(complete) len str %(complete_val) eos
    |   "D" %(data) len any2 %(data_tupnfields) (any4 %(data_tupfield_len) str %(data_tupfield_val))** when command
    |   "K" %(secret) len any4 %(secret_backend) any4 %(secret_key)
    |   "R" %(auth) len any4 %(auth_method)
    |   "S" %(status) len str >(status_open) %(status_key) eos str %(status_val) %(status_done) eos
    |   "T" %(row) len any2 %(row_nfields) (str %(row_field_name) eos any4 %(row_field_tableid) any2 %(row_field_columnid) any4 %(row_field_typid) any2 %(row_field_typlen) any4 %(row_field_atttypmod) any2 %(row_field_format))** when command
    |   "Z" %(ready) len (ready_trans_idle | ready_trans_inerror | ready_trans_intrans | ready_trans_unknown)
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
