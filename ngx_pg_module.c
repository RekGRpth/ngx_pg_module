#include <ngx_http.h>

#define PG_DIAG_COLUMN_NAME 'c'
#define PG_DIAG_CONSTRAINT_NAME 'n'
#define PG_DIAG_CONTEXT 'W'
#define PG_DIAG_DATATYPE_NAME 'd'
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_INTERNAL_QUERY 'q'
#define PG_DIAG_MESSAGE_DETAIL 'D'
#define PG_DIAG_MESSAGE_HINT 'H'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SCHEMA_NAME 's'
#define PG_DIAG_SEVERITY_NONLOCALIZED 'V'
#define PG_DIAG_SEVERITY 'S'
#define PG_DIAG_SOURCE_FILE 'F'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_SOURCE_LINE 'L'
#define PG_DIAG_SQLSTATE 'C'
#define PG_DIAG_STATEMENT_POSITION 'P'
#define PG_DIAG_TABLE_NAME 't'
/*typedef struct {
    const u_char *column_name;
    const u_char *constraint_name;
    const u_char *context;
    const u_char *datatype_name;
    const u_char *internal_position;
    const u_char *internal_query;
    const u_char *message_detail;
    const u_char *message_hint;
    const u_char *message_primary;
    const u_char *schema_name;
    const u_char *severity_nonlocalized;
    const u_char *severity;
    const u_char *source_file;
    const u_char *source_function;
    const u_char *source_line;
    const u_char *sqlstate;
    const u_char *statement_position;
    const u_char *table_name;
} ngx_pg_error_t;

typedef struct {
    char *message;
    ngx_log_handler_pt handler;
    void *data;
} ngx_pg_log_t;

#define ngx_pg_log_error(level, log, err, msg, fmt, ...) do { \
    ngx_pg_log_t ngx_log_original = { \
        .data = log->data, \
        .handler = log->handler, \
        .message = (msg), \
    }; \
    (log)->data = &ngx_log_original; \
    (log)->handler = ngx_pg_log_error_handler; \
    ngx_log_error(level, log, err, fmt, ##__VA_ARGS__); \
} while (0)

static u_char *ngx_pg_log_error_handler(ngx_log_t *log, u_char *buf, size_t len) {
    u_char *p = buf;
    ngx_pg_log_t *ngx_log_original = log->data;
    log->data = ngx_log_original->data;
    log->handler = ngx_log_original->handler;
    if (log->handler) p = log->handler(log, buf, len);
    len -= p - buf;
    buf = p;
    p = ngx_snprintf(buf, len, "\n%s", ngx_log_original->message);
    len -= p - buf;
    buf = p;
    return buf;
}*/

ngx_module_t ngx_pg_module;

typedef struct {
    ngx_http_request_t *request;
    struct {
        ngx_event_free_peer_pt free;
        ngx_event_get_peer_pt get;
#if (NGX_SSL || NGX_COMPAT)
        ngx_event_save_peer_session_pt save_session;
        ngx_event_set_peer_session_pt set_session;
#endif
        void *data;
    } peer;
} ngx_pg_data_t;

typedef struct {
    ngx_str_t key;
    ngx_str_t val;
} ngx_pg_connect_t;

typedef struct {
    ngx_array_t *connect;
    ngx_flag_t read_request_body;
    ngx_http_complex_value_t cv;
//    ngx_http_complex_value_t send_buf;
    ngx_http_upstream_conf_t upstream;
} ngx_pg_loc_conf_t;

typedef struct {
    ngx_array_t *connect;
    struct {
        ngx_http_upstream_init_peer_pt init;
        ngx_http_upstream_init_pt init_upstream;
    } peer;
} ngx_pg_srv_conf_t;

static ngx_int_t ngx_pg_pipe_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, p->log, 0, "%s", __func__);
    return NGX_OK;
}

static ngx_int_t ngx_pg_pipe_output_filter(void *data, ngx_chain_t *chain) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return NGX_OK;
}

static ngx_int_t ngx_pg_create_request(ngx_http_request_t *r) {
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
//    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
//    if (!plcf->send_buf.value.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no buffer to write?"); return NGX_ERROR; }
//    ngx_str_t send_buf;
//    if (ngx_http_complex_value(r, &plcf->send_buf, &send_buf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
//    ngx_chain_t *cl;
//    if (!(cl = r->upstream->request_bufs = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
//    cl->next = NULL;
//    ngx_buf_t *b;
//    if (!(b = cl->buf = ngx_create_temp_buf(r->pool, send_buf.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
//    b->last = ngx_copy(b->last, send_buf.data, send_buf.len);
//    return NGX_OK;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    /*ngx_buf_t *b;
    ngx_chain_t *cl;
    ngx_http_upstream_t *u = r->upstream;
    uint32_t len = 0;
    static const struct {
        ngx_str_t key;
        ngx_str_t val;
    } o[] = {
        { ngx_string("application_name"), ngx_string("nginx") },
        { ngx_string("database"), ngx_string("test") },
//        { ngx_string("fallback_application_name"), ngx_string("nginx") },
//        { ngx_string("host"), ngx_string("postgres") },
//        { ngx_string("port"), ngx_string("5432") },
        { ngx_string("user"), ngx_string("test") },
        { ngx_null_string, ngx_null_string },
    };
    if (!(cl = u->request_bufs = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += sizeof(len)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += sizeof(uint32_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    *(uint32_t *)b->last = htonl(0x00030000);
    b->last += sizeof(uint32_t);
    for (ngx_uint_t i = 0; o[i].key.len; i++) {
        if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += o[i].key.len + 1 + o[i].val.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
        b->last = ngx_copy(b->last, o[i].key.data, o[i].key.len);
        *b->last++ = (u_char)0;
        b->last = ngx_copy(b->last, o[i].val.data, o[i].val.len);
        *b->last++ = (u_char)0;
    }
    if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += sizeof(u_char)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    *b->last++ = (u_char)0;
    cl->next = NULL;
    *(uint32_t *)u->request_bufs->buf->last = htonl(len);
    u->request_bufs->buf->last += sizeof(len);
    ngx_uint_t i = 0;
    for (ngx_chain_t *cl = u->request_bufs; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        for (u_char *p = b->start; p < b->last; p++) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
        }
    }*/
    return NGX_OK;


    /*uint32_t len = sizeof(uint32_t);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
    len += sizeof(uint32_t);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
    len += sizeof("user") - 1 + 1;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
    len += ngx_strlen("test") + 1;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
//    len += sizeof("database") - 1 + 1;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
//    len += ngx_strlen("test") + 1;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
    len += sizeof(*b->last);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
    if (!(b = ngx_create_temp_buf(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }

//    *((size_t *)b->last) = len;
    *(uint32_t *)b->last = htonl(len);

    b->last += sizeof(uint32_t);
    *(uint32_t *)b->last = htonl(0x00030000);
//    *(uint32_t *)b->last = 0x00030000;
//    *((ProtocolVersion *)b->last) = 0x00030000;
    b->last += sizeof(uint32_t);
    b->last = ngx_copy(b->last, "user", sizeof("user") - 1);
    *b->last++ = (u_char)0;
    b->last = ngx_copy(b->last, "test", ngx_strlen("test"));
    *b->last++ = (u_char)0;
//    b->last = ngx_copy(b->last, "database", sizeof("database") - 1);
//    *b->last++ = (u_char)0;
//    b->last = ngx_copy(b->last, "test", ngx_strlen("test"));
//    *b->last++ = (u_char)0;
    *((typeof(*b->last) *)b->last) = 0;
    b->last += sizeof(*b->last);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", b->last - b->start);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%*s", b->last - b->start, b->start);
            for (u_char *c = b->start; c < b->last; c++) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%c", *c, *c);
            }
    if (!(cl = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    cl->buf = b;
    u->request_bufs = cl;
    cl->next = NULL;
//    u->request_sent = 1; // force to reinit_request
    return NGX_OK;*/
}

static ngx_int_t ngx_pg_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_buf_t *b = &u->buffer;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", b->last - b->start);
//    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%*s", b->last - b->start, b->start);
//    u_char *p = b->start + 2 * sizeof(uint32_t) + 1;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%c", *p);
//    u_char id = *p;
//    p++;
    ngx_uint_t i = 0;
    for (u_char *p = b->start; p < b->last; p++) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    }
    for (u_char *p = b->start; p < b->last; ) switch (*p++) {
        case 'E': { // Error Response
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
//            ngx_pg_error_t e = {0};
            while (p < b->last) {
                switch (*p++) {
                    case PG_DIAG_COLUMN_NAME:ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_COLUMN_NAME = %s", p); break;
                    case PG_DIAG_CONSTRAINT_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_CONSTRAINT_NAME = %s", p); break;
                    case PG_DIAG_CONTEXT: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_CONTEXT = %s", p); break;
                    case PG_DIAG_DATATYPE_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_DATATYPE_NAME = %s", p); break;
                    case PG_DIAG_INTERNAL_POSITION: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_INTERNAL_POSITION = %s", p); break;
                    case PG_DIAG_INTERNAL_QUERY: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_INTERNAL_QUERY = %s", p); break;
                    case PG_DIAG_MESSAGE_DETAIL: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_MESSAGE_DETAIL = %s", p); break;
                    case PG_DIAG_MESSAGE_HINT: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_MESSAGE_HINT = %s", p); break;
                    case PG_DIAG_MESSAGE_PRIMARY: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", p); break;
                    case PG_DIAG_SCHEMA_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SCHEMA_NAME = %s", p); break;
                    case PG_DIAG_SEVERITY_NONLOCALIZED: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SEVERITY_NONLOCALIZED = %s", p); break;
                    case PG_DIAG_SEVERITY: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SEVERITY = %s", p); break;
                    case PG_DIAG_SOURCE_FILE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_FILE = %s", p); break;
                    case PG_DIAG_SOURCE_FUNCTION: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_FUNCTION = %s", p); break;
                    case PG_DIAG_SOURCE_LINE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_LINE = %s", p); break;
                    case PG_DIAG_SQLSTATE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SQLSTATE = %s", p); break;
                    case PG_DIAG_STATEMENT_POSITION: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_STATEMENT_POSITION = %s", p); break;
                    case PG_DIAG_TABLE_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_TABLE_NAME = %s", p); break;
                }
                while (*p++);
            }
//            ngx_pg_log_error(NGX_LOG_ERR, r->connection->log, 0, "msg", "fmt = %s", e.message_primary);
            return NGX_ERROR;
        } break;
        case 'K': { // secret key data from the backend
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pid = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "key = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
        } break;
        case 'R': { // Authentication
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "method = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
        } break;
        case 'S': { // Parameter Status
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "key = %s", p);
            while (*p++);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "val = %s", p);
            while (*p++);
        } break;
        case 'Z': { // Ready For Query
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)p));
            p += sizeof(uint32_t);
            switch (*p++) {
                case 'E': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_INERROR"); break;
                case 'I': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_IDLE"); return NGX_OK; break;
                case 'T': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_INTRANS"); break;
                default: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_UNKNOWN"); break;
            }
        } break;
    }
//    u->pipe->input_ctx = r;
//    u->pipe->input_filter = ngx_pg_pipe_input_filter;
//    u->pipe->output_ctx = r;
//    u->pipe->output_filter = ngx_pg_pipe_output_filter;
    return NGX_OK;
/*//    uint32_t len = ntohl(*(uint32_t *)p);
//    uint32_t len = *(uint32_t *)p;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", len);
    p += sizeof(uint32_t);
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%c", *p);
    ngx_uint_t i = 0;
    for (u_char *c = b->start; c < b->last; c++) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *c, *c);
    }
    switch (id) {
        case 'E': {
            ngx_pg_error_t e = {0};
            while (p < b->last) {
                switch (*p++) {
                    case PG_DIAG_COLUMN_NAME: e.column_name = p; break;
                    case PG_DIAG_CONSTRAINT_NAME: e.constraint_name = p; break;
                    case PG_DIAG_CONTEXT: e.context = p; break;
                    case PG_DIAG_DATATYPE_NAME: e.datatype_name = p; break;
                    case PG_DIAG_INTERNAL_POSITION: e.internal_position = p; break;
                    case PG_DIAG_INTERNAL_QUERY: e.internal_query = p; break;
                    case PG_DIAG_MESSAGE_DETAIL: e.message_detail = p; break;
                    case PG_DIAG_MESSAGE_HINT: e.message_hint = p; break;
                    case PG_DIAG_MESSAGE_PRIMARY: e.message_primary = p; break;
                    case PG_DIAG_SCHEMA_NAME: e.schema_name = p; break;
                    case PG_DIAG_SEVERITY_NONLOCALIZED: e.severity_nonlocalized = p; break;
                    case PG_DIAG_SEVERITY: e.severity = p; break;
                    case PG_DIAG_SOURCE_FILE: e.source_file = p; break;
                    case PG_DIAG_SOURCE_FUNCTION: e.source_function = p; break;
                    case PG_DIAG_SOURCE_LINE: e.source_line = p; break;
                    case PG_DIAG_SQLSTATE: e.sqlstate = p; break;
                    case PG_DIAG_STATEMENT_POSITION: e.statement_position = p; break;
                    case PG_DIAG_TABLE_NAME: e.table_name = p; break;
//                    case 'C': ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SQLSTATE = %s", p); break;
//                    case 'F': ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_FILE = %s", p); break;
//                    case 'L': ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_LINE = %s", p); break;
//                    case 'M': ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_MESSAGE_PRIMARY = %s", p); break;
//                    case 'R': ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_FUNCTION = %s", p); break;
//                    case 'S': ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SEVERITY = %s", p); break;
//                    case 'V': ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SEVERITY_NONLOCALIZED = %s", p); break;
                }
                while (*p++);
            }
            ngx_pg_log_error(NGX_LOG_ERR, r->connection->log, 0, "msg", "fmt = %s", e.message_primary);
            return NGX_ERROR;
        } break;
        case 'S': {
        } break;
    }
//    u->pipe->input_ctx = r;
//    u->pipe->input_filter = ngx_pg_pipe_input_filter;
//    u->pipe->output_ctx = r;
//    u->pipe->output_filter = ngx_pg_pipe_output_filter;
//    u->write_event_handler = ngx_http_upstream_send_request_handler;
//    u->read_event_handler = ngx_http_upstream_process_header;
    return NGX_OK;*/
}

/*static void ngx_pg_read_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
}*/

/*static void ngx_pg_write_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
//    ngx_http_upstream_t *u = r->upstream;
    ngx_int_t rc = ngx_output_chain(&u->output, u->request_bufs);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", rc);
}*/

static ngx_int_t ngx_pg_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
/*    ngx_http_upstream_t *u = r->upstream;
    r->state = 0;
    u->process_header = ngx_pg_process_header;
    u->read_event_handler = ngx_pg_read_event_handler;
    u->write_event_handler = ngx_pg_write_event_handler;*/
    return NGX_OK;
}

static void ngx_pg_abort_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
}

static void ngx_pg_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", rc);
}

static ngx_int_t ngx_pg_input_filter_init(void *data) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
/*    ngx_http_upstream_t *u = r->upstream;
    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED) {
        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;
    } else if (u->headers_in.content_length_n == 0) {
        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;
    } else {
        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }*/
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter(void *data, ssize_t bytes) {
    ngx_http_request_t   *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
/*    ngx_http_upstream_t *u = r->upstream;
    ngx_chain_t *cl, **ll;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
    if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) return NGX_ERROR;
    *ll = cl;
    cl->buf->flush = 1;
    cl->buf->memory = 1;
    ngx_buf_t *b = &u->buffer;
    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;
    if (u->length == -1) return NGX_OK;
    u->length -= bytes;
    if (!u->length) u->keepalive = !u->headers_in.connection_close;*/
    return NGX_OK;
}

static ngx_int_t ngx_pg_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_int_t rc;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->read_request_body && (rc = ngx_http_discard_request_body(r)) != NGX_OK) return rc;
    if (ngx_http_set_content_type(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_set_content_type != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    ngx_str_set(&u->schema, "pg://");
    u->output.tag = (ngx_buf_tag_t)&ngx_pg_module;
    u->conf = &plcf->upstream;
    u->abort_request = ngx_pg_abort_request;
    u->create_request = ngx_pg_create_request;
    u->finalize_request = ngx_pg_finalize_request;
    u->process_header = ngx_pg_process_header;
    u->reinit_request = ngx_pg_reinit_request;
    r->state = 0;
    u->buffering = plcf->upstream.buffering;
    if (!(u->pipe = ngx_pcalloc(r->pool, sizeof(*u->pipe)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u->pipe->input_ctx = r;
    u->pipe->input_filter = ngx_pg_pipe_input_filter;
    u->pipe->output_ctx = r;
    u->pipe->output_filter = ngx_pg_pipe_output_filter;
    u->input_filter_init = ngx_pg_input_filter_init;
    u->input_filter = ngx_pg_input_filter;
    u->input_filter_ctx = r;
    if (!plcf->upstream.request_buffering && plcf->upstream.pass_request_body && !r->headers_in.chunked) r->request_body_no_buffering = 1;
    if ((rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init)) >= NGX_HTTP_SPECIAL_RESPONSE) return rc;
    return NGX_DONE;
/*    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) return rc;
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    ngx_str_set(&u->schema, "pg://");
    u->output.tag = (ngx_buf_tag_t)&ngx_pg_module;
    u->conf = &plcf->upstream;
    u->conf->connect_timeout = 60 * 1000;
    u->abort_request = ngx_pg_abort_request;
    u->create_request = ngx_pg_create_request;
    u->finalize_request = ngx_pg_finalize_request;
    u->process_header = ngx_pg_process_header;
    u->reinit_request = ngx_pg_reinit_request;
    r->state = 0;
    u->buffering = plcf->upstream.buffering;
    if (!(u->pipe = ngx_pcalloc(r->pool, sizeof(*u->pipe)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u->pipe->input_ctx = r;
    u->pipe->input_filter = ngx_pg_pipe_input_filter;
    u->pipe->output_ctx = r;
    u->pipe->output_filter = ngx_pg_pipe_output_filter;
//    u->input_filter_init = ngx_pg_input_filter_init;
//    u->input_filter = ngx_pg_input_filter;
//    u->input_filter_ctx = r;
    if (!plcf->upstream.request_buffering && plcf->upstream.pass_request_body && !r->headers_in.chunked) r->request_body_no_buffering = 1;
    if ((rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init)) >= NGX_HTTP_SPECIAL_RESPONSE) return rc;
    return NGX_DONE;*/
}

/*static char *ngx_pg_conn_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->connect) return "duplicate";
    if (!(plcf->connect = ngx_pcalloc(cf->pool, sizeof(*plcf->connect)))) return "!ngx_pcalloc";
    return ngx_pg_connect(cf, cmd, plcf->connect);
}*/

static void *ngx_pg_create_srv_conf(ngx_conf_t *cf) {
    ngx_pg_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (!conf) return NULL;
    return conf;
}

static void *ngx_pg_create_loc_conf(ngx_conf_t *cf) {
    ngx_pg_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (!conf) return NULL;
    conf->read_request_body = NGX_CONF_UNSET;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;
    conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
    ngx_str_set(&conf->upstream.module, "pg");
    return conf;
}

static ngx_path_init_t ngx_pg_temp_path = {
#ifdef NGX_CONF_PREFIX
    ngx_string(NGX_CONF_PREFIX "pg_temp"), { 1, 2, 0 }
#else
    ngx_string(NGX_PREFIX "pg_temp"), { 1, 2, 0 }
#endif
};

static ngx_str_t ngx_pg_hide_headers[] = {
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

static char *ngx_pg_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_pg_loc_conf_t *prev = parent;
    ngx_pg_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->read_request_body, prev->read_request_body, 0);
    if (!conf->cv.value.data) conf->cv = prev->cv;
    if (!conf->upstream.upstream) conf->upstream = prev->upstream;
    if (conf->upstream.store == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);
        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }
    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers, prev->upstream.ignore_headers, NGX_CONF_BITMASK_SET);
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_ERROR|NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs, 8, ngx_pagesize);
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);
    ngx_conf_merge_ptr_value(conf->upstream.local, prev->upstream.local, NULL);
    ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t)ngx_pagesize);
    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf, prev->upstream.busy_buffers_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_size_value(conf->upstream.limit_rate, prev->upstream.limit_rate, 0);
    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf, prev->upstream.max_temp_file_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf, prev->upstream.temp_file_write_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_uint_value(conf->upstream.store_access, prev->upstream.store_access, 0600);
    ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering, 1);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);
    ngx_conf_merge_value(conf->upstream.request_buffering, prev->upstream.request_buffering, 1);
    ngx_conf_merge_value(conf->upstream.socket_keepalive, prev->upstream.socket_keepalive, 0);
    if (conf->upstream.bufs.num < 2) return "there must be at least 2 \"pg_buffers\"";
    size_t size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) size = conf->upstream.bufs.size;
    conf->upstream.busy_buffers_size = conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE ? 2 * size : conf->upstream.busy_buffers_size_conf;
    if (conf->upstream.busy_buffers_size < size) return "\"pg_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
    if (conf->upstream.busy_buffers_size > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) return "\"pg_busy_buffers_size\" must be less than the size of all \"pg_buffers\" minus one buffer";
    conf->upstream.temp_file_write_size = conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE ? 2 * size : conf->upstream.temp_file_write_size_conf;
    if (conf->upstream.temp_file_write_size < size) return "\"pg_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
    conf->upstream.max_temp_file_size = conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE ? 1024 * 1024 * 1024 : conf->upstream.max_temp_file_size_conf;
    if (conf->upstream.max_temp_file_size && conf->upstream.max_temp_file_size < size) return "\"pg_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path, prev->upstream.temp_path, &ngx_pg_temp_path) != NGX_OK) return NGX_CONF_ERROR;
    ngx_hash_init_t hash = {0};
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "pg_hide_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, ngx_pg_hide_headers, &hash) != NGX_OK) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_pg_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_pg_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_pg_create_loc_conf,
    .merge_loc_conf = ngx_pg_merge_loc_conf
};

static ngx_int_t ngx_pg_open(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pg_data_t *d = data;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    ngx_array_t *array = plcf->connect;
    ngx_pg_srv_conf_t *pscf = u->conf->upstream->srv_conf ? ngx_http_conf_upstream_srv_conf(u->conf->upstream, ngx_pg_module) : NULL;
    if (pscf && !array) array = plcf->connect;
    if (!array) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!connect"); return NGX_ERROR; }
    ngx_buf_t *b;
    ngx_chain_t *cl;
    uint32_t len = 0;
    if (!(cl = u->request_bufs = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += sizeof(len)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += sizeof(uint32_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    *(uint32_t *)b->last = htonl(0x00030000);
    b->last += sizeof(uint32_t);
    ngx_pg_connect_t *connect = array->elts;
    for (ngx_uint_t i = 0; i < array->nelts; i++) {
        if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += connect[i].key.len + 1 + connect[i].val.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
        b->last = ngx_copy(b->last, connect[i].key.data, connect[i].key.len);
        *b->last++ = (u_char)0;
        b->last = ngx_copy(b->last, connect[i].val.data, connect[i].val.len);
        *b->last++ = (u_char)0;
    }
    if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    if (!(cl->buf = b = ngx_create_temp_buf(r->pool, len += sizeof(u_char)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    *b->last++ = (u_char)0;
    cl->next = NULL;
    *(uint32_t *)u->request_bufs->buf->last = htonl(len);
    u->request_bufs->buf->last += sizeof(len);
    ngx_uint_t i = 0;
    for (ngx_chain_t *cl = u->request_bufs; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        for (u_char *p = b->start; p < b->last; p++) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
        }
    }
    return NGX_AGAIN;

    /*
//#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
//    ngx_postgres_connect_t *connect = pc->peer_data;
//#else
//    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
//    ngx_postgres_connect_t *connect = location->connect ? location->connect : usc->connect.elts;
//    if (!location->connect) {
//        ngx_uint_t i;
//        for (i = 0; i < usc->connect.nelts; i++) for (ngx_uint_t j = 0; j < connect[i].url.naddrs; j++) if (!ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)connect[i].url.addrs[j].sockaddr, pc->socklen, connect[i].url.addrs[j].socklen)) { connect = &connect[i]; goto found; }
//found:
//        if (i == usc->connect.nelts) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connect not found"); return NGX_BUSY; }
//    }
//#endif
    u->conf->connect_timeout = connect->timeout;
    const char *host = connect->values[0];
    if (host) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "host = %s", host); }
    ngx_str_t addr;
    if (!(addr.data = ngx_pcalloc(r->pool, NGX_SOCKADDR_STRLEN + 1))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto error; }
    if (!(addr.len = ngx_sock_ntop(pc->sockaddr, pc->socklen, addr.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_sock_ntop"); goto error; }
    connect->values[0] = (const char *)addr.data + (pc->sockaddr->sa_family == AF_UNIX ? 5 : 0);
    for (int i = 0; connect->keywords[i]; i++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i: %s = %s", i, connect->keywords[i], connect->values[i]);
    PGconn *conn = pgconnectStartParams(connect->keywords, connect->values, 0);
    connect->values[0] = host;
    if (pgstatus(conn) == CONNECTION_BAD) { ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, pgerrorMessageMy(conn), "pgstatus == CONNECTION_BAD"); goto declined; }
    (void)pgsetErrorVerbosity(conn, connect->verbosity);
    if (pgsetnonblocking(conn, 1) == -1) { ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, pgerrorMessageMy(conn), "pgsetnonblocking == -1"); goto declined; }
    if (usc && usc->trace.log) pgtrace(conn, fdopen(usc->trace.log->file->fd, "a+"));
    pgsocket fd;
    if ((fd = pgsocket(conn)) == PGINVALID_SOCKET) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "pgsocket == PGINVALID_SOCKET"); goto declined; }
    ngx_connection_t *c = ngx_get_connection(fd, pc->log);
    if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_get_connection"); goto finish; }
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->read->log = pc->log;
    c->shared = 1;
    c->start_time = ngx_current_msec;
    c->type = pc->type ? pc->type : SOCK_STREAM;
    c->write->log = pc->log;
    if (!(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); goto close; }
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(c) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_conn != NGX_OK"); goto destroy; }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_conn");
    } else {
        if (ngx_add_event(c->read, NGX_READ_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_event(read)");
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_event(write)");
    }
    ngx_postgres_save_t *s;
    switch (pgconnectPoll(conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, pgerrorMessageMy(conn), "PGRES_POLLING_FAILED"); goto destroy;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_OK"); c->read->active = 0; c->write->active = 1; break;
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_READING"); c->read->active = 1; c->write->active = 0; break;
        case PGRES_POLLING_WRITING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_WRITING"); c->read->active = 0; c->write->active = 1; break;
    }
    if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto destroy; }
    s->conn = conn;
    s->connect = connect;
    s->connection = c;
    s->peer.sockaddr = pc->sockaddr;
    s->peer.socklen = pc->socklen;
    s->read_handler = ngx_postgres_connect_handler;
    s->usc = usc;
    s->write_handler = ngx_postgres_connect_handler;
    pc->connection = c;
    if (usc) queue_insert_head(&usc->work.queue, &s->queue);
    return NGX_AGAIN;
declined:
    pgfinish(conn);
    return NGX_DECLINED;
destroy:
    ngx_destroy_pool(c->pool);
    c->pool = NULL;
close:
    ngx_close_connection(c);
finish:
    pgfinish(conn);
error:*/
    return NGX_ERROR;
}

static ngx_int_t ngx_pg_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pg_data_t *d = data;
    ngx_int_t rc = d->peer.get(pc, d->peer.data);
    if (rc != NGX_OK) return rc;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "rc = %i", rc);
//    ngx_http_request_t *r = d->request;
//    ngx_http_upstream_t *u = r->upstream;
//    ngx_pg_srv_conf_t *pscf = u->conf->upstream->srv_conf ? ngx_http_conf_upstream_srv_conf(u->conf->upstream, ngx_pg_module) : NULL;
    /*if (usc && usc->keep.max) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "keep.max = %i, keep.size = %i, work.size = %i", usc->keep.max, queue_size(&usc->keep.queue), queue_size(&usc->work.queue));
        queue_each(&usc->keep.queue, q) {
            ngx_postgres_save_t *s = queue_data(q, typeof(*s), queue);
            if (ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)s->peer.sockaddr, pc->socklen, s->peer.socklen)) continue;
            d->save = s;
            ngx_postgres_log_to_work(pc->log, s);
            pc->cached = 1;
            pc->connection = s->connection;
            s->connection->data = d;
            return ngx_postgres_send_query(s);
        }
        if (queue_size(&usc->keep.queue) + queue_size(&usc->work.queue) < usc->keep.max) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "keep.size = %i, work.size = %i", queue_size(&usc->keep.queue), queue_size(&usc->work.queue));
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
        } else if (usc->data.max) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "data.max = %i, data.size = %i", usc->data.max, queue_size(&usc->data.queue));
            if (queue_size(&usc->data.queue) < usc->data.max) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "d = %p", d);
                ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(d->request->pool, 0);
                if (!cln) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
                cln->handler = ngx_postgres_data_cleanup_handler;
                cln->data = d;
                queue_insert_tail(&usc->data.queue, &d->queue);
                if (usc->data.timeout) {
                    d->timeout.handler = ngx_postgres_data_timeout_handler;
                    d->timeout.log = pc->log;
                    d->timeout.data = r;
                    ngx_add_timer(&d->timeout, usc->data.timeout);
                }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "data.size = %i", queue_size(&usc->data.queue));
                return NGX_YIELD;
            }
            if (usc->data.reject) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0, "data.size = %i", queue_size(&usc->data.queue));
                return NGX_BUSY;
            }
#endif
        } else if (usc->keep.reject) {
            ngx_log_error(NGX_LOG_WARN, pc->log, 0, "keep.size = %i, work.size = %i", queue_size(&usc->keep.queue), queue_size(&usc->work.queue));
            return NGX_BUSY;
        }
    }*/
    return ngx_pg_open(pc, data);
}

static void ngx_pg_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %i", state);
    if (ngx_terminate) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "ngx_terminate"); goto close; }
    if (ngx_exiting) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "ngx_exiting"); goto close; }
    ngx_connection_t *c = pc->connection;
    if (!c) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "!c"); goto close; }
    if (c->error) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "c->error"); goto close; }
    if (c->read->error) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "c->read->error"); goto close; }
    if (c->write->error) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "c->write->error"); goto close; }
    if (state & NGX_PEER_FAILED && !c->read->timedout && !c->write->timedout) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "state & NGX_PEER_FAILED = %s, c->read->timedout = %s, c->write->timedout = %s", state & NGX_PEER_FAILED ? "true" : "false", c->read->timedout ? "true" : "false", c->write->timedout ? "true" : "false"); goto close; }
//    ngx_pg_free_peer(pc, data);
close:;
    ngx_pg_data_t *d = data;
    if (pc->connection) { /*ngx_pg_close(d->save); */pc->connection = NULL; }
    d->peer.free(pc, d->peer.data, state);
//    d->save = NULL;
}

static ngx_int_t ngx_pg_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_pg_srv_conf_t *pscf = uscf->srv_conf ? ngx_http_conf_upstream_srv_conf(uscf, ngx_pg_module) : NULL;
    ngx_http_upstream_t *u = r->upstream;
    if ((pscf && pscf->peer.init ? pscf->peer.init : ngx_http_upstream_init_round_robin_peer)(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
    ngx_pg_data_t *d = ngx_pcalloc(r->pool, sizeof(*d));
    if (!d) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    u->conf->upstream = uscf;
    d->request = r;
    d->peer.data = u->peer.data;
    u->peer.data = d;
    d->peer.get = u->peer.get;
    u->peer.get = ngx_pg_peer_get;
    d->peer.free = u->peer.free;
    u->peer.free = ngx_pg_peer_free;
/*#if (NGX_HTTP_SSL)
    d->peer.save_session = u->peer.save_session;
    u->peer.save_session = ngx_pg_save_session;
    d->peer.set_session = u->peer.set_session;
    u->peer.set_session = ngx_pg_set_session;
#endif*/
    return NGX_OK;
}

static ngx_int_t ngx_pg_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_pg_srv_conf_t *pscf = uscf->srv_conf ? ngx_http_conf_upstream_srv_conf(uscf, ngx_pg_module) : NULL;
    if (((pscf && pscf->peer.init_upstream) ? pscf->peer.init_upstream : ngx_http_upstream_init_round_robin)(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "peer.init_upstream != NGX_OK"); return NGX_ERROR; }
    if (pscf) pscf->peer.init = uscf->peer.init;
    uscf->peer.init = ngx_pg_peer_init;
//    pscf->peer.init = uscf->peer.init;
//    uscf->peer.init = ngx_pg_peer_init;
    if (!pscf) return NGX_OK;
//#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
//    queue_init(&pscf->data.queue);
//#endif
//    queue_init(&pscf->keep.queue);
//    queue_init(&pscf->work.queue);
//    if (!pscf->keep.max) return NGX_OK;

//    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
//    if (!cln) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
//    cln->handler = ngx_pg_srv_conf_cln_handler;
//    cln->data = pscf;
    return NGX_OK;
}

static char *ngx_pg_connect(ngx_conf_t *cf, ngx_command_t *cmd, ngx_array_t *array) {
//    if (ngx_array_init(array, cf->pool, 1, sizeof(ngx_pg_connect_t)) != NGX_OK) return "ngx_array_init != NGX_OK";
    ngx_pg_connect_t *connect;
    ngx_str_t *args = cf->args->elts;
//    u_char *eq;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
//        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "args[%i] = %V", i, &args[i]);
        if (!(connect = ngx_array_push(array))) return "!ngx_array_push";
        ngx_memzero(connect, sizeof(*connect));
        connect->key = args[i];
//        if (!(eq = (u_char *)strtok((char *)connect->key.data, "="))) return "Parameters in form of key=val required!";
//        connect->key.len = ngx_strlen();
        while (connect->key.len-- > 0 && connect->key.data[connect->key.len] != '=');
        if (!connect->key.len) return "!key";
        if (connect->key.len >= args[i].len - 1) return "!val";
        connect->val = args[i];
        connect->val.data += connect->key.len + 1;
        connect->val.len -= connect->key.len + 1;
//        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "%V = %V", &connect->key, &connect->val);
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_conn_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    if (pscf->connect) return "duplicate";
    ngx_http_upstream_srv_conf_t *uscf = /*pscf->upstream =*/ ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
//    pscf->peer.init = uscf->peer.init;
//    uscf->peer.init = ngx_pg_peer_init;
    pscf->peer.init_upstream = uscf->peer.init_upstream;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    if (!(pscf->connect = ngx_array_create(cf->pool, 2 * (cf->args->nelts - 1), sizeof(ngx_pg_connect_t)))) return "!ngx_array_create";
    return ngx_pg_connect(cf, cmd, pscf->connect);
}

/*static char *ngx_pg_conn_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->connect) return "duplicate";
    if (!(plcf->connect = ngx_array_create(cf->pool, 2 * (cf->args->nelts - 1), sizeof(ngx_pg_connect_t)))) return "!ngx_array_create";
    return ngx_pg_connect(cf, cmd, plcf->connect);
}*/

static char *ngx_pg_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->upstream.upstream || plcf->cv.value.data) return "duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pg_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_url_t u = {0};
    u.no_resolve = 1;
    if (cf->args->nelts == 2) {
        ngx_str_t *elts = cf->args->elts;
        u.url = elts[1];
        if (ngx_http_script_variables_count(&u.url)) {
            ngx_http_compile_complex_value_t ccv = {cf, &u.url, &plcf->cv, 0, 0, 0};
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
            return NGX_CONF_OK;
        }
    } else {
//        ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
        //pscf->peer.init_upstream = uscf->peer.init_upstream;
//        uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
        if (plcf->connect) return "duplicate";
        if (!(plcf->connect = ngx_array_create(cf->pool, 2 * (cf->args->nelts - 1), sizeof(ngx_pg_connect_t)))) return "!ngx_array_create";
        char *rv;
        if ((rv = ngx_pg_connect(cf, cmd, plcf->connect)) != NGX_CONF_OK) return rv;
        ngx_pg_connect_t *elts = plcf->connect->elts;
        for (ngx_uint_t i = 0; i < plcf->connect->nelts; i++) if (elts[i].key.len == sizeof("host") - 1 && !ngx_strncasecmp(elts[i].key.data, "host", sizeof("host") - 1)) { u.url = elts[i].val; break; }
    }
    if (!u.url.len) return "!url";
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0))) return NGX_CONF_ERROR;
    if (cf->args->nelts == 2) return NGX_CONF_OK;
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    //pscf->peer.init_upstream = uscf->peer.init_upstream;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
//    if (plcf->connect) return "duplicate";
//    if (!(plcf->connect = ngx_array_create(cf->pool, 2 * (cf->args->nelts - 1), sizeof(ngx_pg_connect_t)))) return "!ngx_array_create";
//    return ngx_pg_connect(cf, cmd, plcf->connect);
    return NGX_CONF_OK;
}

static ngx_command_t ngx_pg_commands[] = {
  { .name = ngx_string("pg_conn"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_conn_ups_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  /*{ .name = ngx_string("pg_conn"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_conn_loc_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },*/
  { .name = ngx_string("pg_pass"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_pass_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("pg_read_request_body"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_pg_loc_conf_t, read_request_body),
    .post = NULL },
  { .name = ngx_string("pg_connect_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_pg_loc_conf_t, upstream.connect_timeout),
    .post = NULL },
    ngx_null_command
};

ngx_module_t ngx_pg_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_pg_ctx,
    .commands = ngx_pg_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
