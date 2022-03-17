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

    action all { fprintf(stderr, "all = %i:%c\n", *p, *p); }
    action any_all { parser->any[parser->index++] = *p; }
    action any_open { parser->index = 0; }
    action auth { if (settings->auth) settings->auth(parser); }
    action auth_method { fprintf(stderr, "auth_method = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action bind { if (settings->bind) settings->bind(parser); }
    action close { if (settings->close) settings->close(parser); }
    action command { p < e }
    action complete { if (settings->complete) settings->complete(parser); }
    action complete_value { if (string && p - string > 0) fprintf(stderr, "complete_value = %.*s\n", (int)(p - string), string); string = NULL; }
    action data { if (settings->data) settings->data(parser); }
    action data_tupfield_length { fprintf(stderr, "data_tupfield_length = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action data_tupfield_value { if (string && p - string > 0) fprintf(stderr, "data_tupfield_value = %.*s\n", (int)(p - string), string); string = NULL; }
    action data_tupnfields { fprintf(stderr, "data_tupnfields = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action length { parser->length = ntohl(*(uint32_t *)parser->any) - 4; fprintf(stderr, "length = %i\n", parser->length); if (parser->length) e = p + parser->length; }
    action parse { if (settings->parse) settings->parse(parser); }
    action ready { if (settings->ready) settings->ready(parser); }
    action ready_trans_idle { fprintf(stderr, "ready_trans_idle\n"); }
    action ready_trans_inerror { fprintf(stderr, "ready_trans_inerror\n"); }
    action ready_trans_intrans { fprintf(stderr, "ready_trans_intrans\n"); }
    action ready_trans_unknown { fprintf(stderr, "ready_trans_unknown = %i:%c\n", *p, *p); }
    action row_field_atttypmod { fprintf(stderr, "row_field_atttypmod = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action row_field_columnid { fprintf(stderr, "row_field_columnid = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action row_field_format { fprintf(stderr, "row_field_format = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action row_field_name { if (string && p - string > 0) fprintf(stderr, "row_field_name = %.*s\n", (int)(p - string), string); string = NULL; }
    action row_field_tableid { fprintf(stderr, "row_field_tableid = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action row_field_typid { fprintf(stderr, "row_field_typid = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action row_field_typlen { fprintf(stderr, "row_field_typlen = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action row { if (settings->row) settings->row(parser); }
    action row_nfields { fprintf(stderr, "row_nfields = %i\n", ntohs(*(uint16_t *)parser->any)); }
    action secret_backend { fprintf(stderr, "secret_backend = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action secret { if (settings->secret) settings->secret(parser); }
    action secret_key { fprintf(stderr, "secret_key = %i\n", ntohl(*(uint32_t *)parser->any)); }
    action status { if (settings->status) settings->status(parser); }
    action status_key { if (string && p - string > 0) fprintf(stderr, "status_key = %.*s\n", (int)(p - string), string); string = NULL; }
    action status_value { if (string && p - string > 0) fprintf(stderr, "status_value = %.*s\n", (int)(p - string), string); string = NULL; }
    action string_all { if (string) parser->string = cs; }
    action string_open { if (!string) string = p; }

    eos = 0;
    char = any - eos;
    any2 = any{2} >(any_open) $(any_all);
    any4 = any{4} >(any_open) $(any_all);
    str = char* >(string_open) $(string_all);
    length = any4 %(length);

    ready_trans_idle = "I" %(ready_trans_idle);
    ready_trans_inerror = "E" %(ready_trans_inerror);
    ready_trans_intrans = "T" %(ready_trans_intrans);
    ready_trans_unknown = any - [EIT] %(ready_trans_unknown);

    main :=
    (   "1" %(parse) length when command
    |   "2" %(bind) length when command
    |   "3" %(close) length when command
    |   "C" %(complete) length str %(complete_value) eos when command
    |   "D" %(data) length any2 %(data_tupnfields) (any4 %(data_tupfield_length) str %(data_tupfield_value))** when command
    |   "K" %(secret) length any4 %(secret_backend) any4 %(secret_key) when command
    |   "R" %(auth) length any4 %(auth_method) when command
    |   "S" %(status) length str %(status_key) eos str %(status_value) eos when command
    |   "T" %(row) length any2 %(row_nfields) (str %(row_field_name) eos any4 %(row_field_tableid) any2 %(row_field_columnid) any4 %(row_field_typid) any2 %(row_field_typlen) any4 %(row_field_atttypmod) any2 %(row_field_format))** when command
    |   "Z" %(ready) length (ready_trans_idle | ready_trans_inerror | ready_trans_intrans | ready_trans_unknown) when command
    )** $(all);

    write data;
}%%

void pg_parser_init(pg_parser_t *parser) {
    int cs = 0;
    void *data = parser->data;
    %% write init;
    memset(parser, 0, sizeof(*parser));
    parser->data = data;
    parser->state = cs;
}

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *p, const unsigned char *pe) {
    const unsigned char *b = p;
    const unsigned char *eof = pe;
    const unsigned char *e = pe;
    const unsigned char *string = parser->state == parser->string ? p : NULL;
    int cs = parser->state;
    if (parser->length) e = p + parser->length;
    fprintf(stderr, "got = %i\n", (int)(pe - p));
    %% write exec;
    parser->state = cs;
    fprintf(stderr, "ret = %i\n", (int)(p - b));
    return p - b;
}
