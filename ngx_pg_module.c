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

ngx_module_t ngx_pg_module;

typedef struct {
    ngx_chain_t *query;
    ngx_chain_t *parse;
    ngx_chain_t *bind;
    ngx_chain_t *describe;
    ngx_chain_t *execute;
    ngx_chain_t *close;
    ngx_chain_t *sync;
} ngx_pg_query_t;

typedef struct {
    ngx_chain_t *connect;
    ngx_flag_t read_request_body;
    ngx_http_upstream_conf_t upstream;
    ngx_pg_query_t query;
} ngx_pg_loc_conf_t;

typedef struct {
    ngx_chain_t *connect;
    ngx_log_t *log;
    struct {
        ngx_http_upstream_init_peer_pt init;
        ngx_http_upstream_init_pt init_upstream;
    } peer;
} ngx_pg_srv_conf_t;

typedef struct {
    ngx_chain_t *connect;
    ngx_http_request_t *request;
    ngx_pg_query_t query;
    ngx_pg_srv_conf_t *conf;
    struct {
        ngx_event_free_peer_pt free;
        ngx_event_get_peer_pt get;
        void *data;
    } peer;
} ngx_pg_data_t;

static ngx_int_t ngx_pg_pipe_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, p->log, 0, "%s", __func__);
    if (buf->pos == buf->last) return NGX_OK;
    ngx_chain_t *cl;
    if (!(cl = ngx_chain_get_free_buf(p->pool, &p->free))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
    ngx_buf_t *b = cl->buf;
    ngx_memcpy(b, buf, sizeof(*b));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);
    if (p->in) *p->last_in = cl;
    else p->in = cl;
    p->last_in = &cl->next;
    if (p->length == -1) return NGX_OK;
    p->length -= b->last - b->pos;
    if (!p->length) {
        ngx_http_request_t *r = p->input_ctx;
        p->upstream_done = 1;
        r->upstream->keepalive = !r->upstream->headers_in.connection_close;
    } else if (p->length < 0) {
        ngx_http_request_t *r = p->input_ctx;
        p->upstream_done = 1;
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "upstream sent more data than specified in \"Content-Length\" header");
    }
    return NGX_OK;
}

static ngx_int_t ngx_pg_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pg_data_t *d = data;
    ngx_int_t rc = d->peer.get(pc, d->peer.data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "rc = %i", rc);
    ngx_connection_t *c = pc->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "c = %p", c);
    if (rc != NGX_OK && rc != NGX_DONE) return rc;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    if (c) u->request_bufs = d->query.query; else {
        ngx_chain_t *cl;
        if (!(cl = u->request_bufs = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        for (ngx_chain_t *connect = d->connect; connect; connect = connect->next) {
            if (connect != d->connect && !(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
            cl->buf = connect->buf;
        }
        cl->next = d->query.query;
    }
    ngx_uint_t i = 0;
    for (ngx_chain_t *cl = u->request_bufs; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        b->pos = b->start;
        for (u_char *p = b->pos; p < b->last; p++) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i:%i:%c", i++, *p, *p);
        }
    }
    return rc;
}

static void ngx_pg_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %i", state);
    ngx_pg_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    ngx_connection_t *c = pc->connection;
    ngx_pg_srv_conf_t *pscf = d->conf;
    if (!c) return;
    if (!pscf) return;
    if (!pscf->log) return;
    c->log = pscf->log;
    c->pool->log = pscf->log;
    c->read->log = pscf->log;
    c->write->log = pscf->log;
}

static ngx_int_t ngx_pg_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    ngx_pg_data_t *d = ngx_pcalloc(r->pool, sizeof(*d));
    if (!d) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    d->query = plcf->query;
    if (uscf->srv_conf) {
        ngx_pg_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pg_module);
        if (pscf->peer.init(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
        d->conf = pscf;
        d->connect = pscf->connect;
    } else {
        if (ngx_http_upstream_init_round_robin_peer(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_init_round_robin_peer != NGX_OK"); return NGX_ERROR; }
        d->connect = plcf->connect;
    }
    ngx_http_upstream_t *u = r->upstream;
    u->conf->upstream = uscf;
    d->request = r;
    d->peer.data = u->peer.data;
    u->peer.data = d;
    d->peer.get = u->peer.get;
    u->peer.get = ngx_pg_peer_get;
    d->peer.free = u->peer.free;
    u->peer.free = ngx_pg_peer_free;
    return NGX_OK;
}

static ngx_int_t ngx_pg_create_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init = ngx_pg_peer_init;
    return NGX_OK;
}

static void ngx_pg_cln_handler(void *data) {
    ngx_connection_t *c = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);

    ngx_buf_t *b;
    ngx_chain_t *cl, *cl_len, *out, *last;
    uint32_t len = 0;

    if (!(cl = out = ngx_alloc_chain_link(c->pool))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_alloc_chain_link"); return; }
    if (!(cl->buf = b = ngx_create_temp_buf(c->pool, sizeof(u_char)))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_create_temp_buf"); return; }
    *b->last++ = (u_char)'X';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(c->pool))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_alloc_chain_link"); return; }
    if (!(cl->buf = b = ngx_create_temp_buf(c->pool, len += sizeof(len)))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_create_temp_buf"); return; }

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    cl->next = NULL;
    ngx_uint_t i = 0;
    for (ngx_chain_t *cl = out; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        for (u_char *p = b->pos; p < b->last; p++) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "%i:%i:%c", i++, *p, *p);
        }
    }

    ngx_chain_writer_ctx_t ctx = { .out = out, .last = &last, .connection = c, .pool = c->pool, .limit = 0 };

    ngx_chain_writer(&ctx, NULL);
}

static ngx_int_t ngx_pg_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", u->buffer.last - u->buffer.pos);
    ngx_connection_t *c = u->peer.connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", c->requests);
    if (c->requests == 1) {
        if (!(c->pool = ngx_create_pool(128, c->log))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_pool"); return NGX_ERROR; }
        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(c->pool, 0);
        if (!cln) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
        cln->handler = ngx_pg_cln_handler;
        cln->data = c;
    }
    ngx_uint_t i = 0;
    for (u_char *p = u->buffer.pos; p < u->buffer.last; p++) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    }
    ngx_int_t rc = NGX_OK;
    u_char *last = NULL;
    u_char *pos = NULL;
    while (u->buffer.pos < u->buffer.last) switch (*u->buffer.pos++) {
        case 'C': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Command Complete");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "command = %s", u->buffer.pos);
            while (*u->buffer.pos++);
        } break;
        case 'D': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Data Row");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            uint16_t tupnfields = ntohs(*(uint16_t *)u->buffer.pos);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "tupnfields = %i", tupnfields);
            u->buffer.pos += sizeof(uint16_t);
            for (uint16_t i = 0; i < tupnfields; i++) {
                uint32_t len = ntohl(*(uint32_t *)u->buffer.pos);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", len);
                u->buffer.pos += sizeof(uint32_t);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "val = %*s", len, u->buffer.pos);
                pos = u->buffer.pos;
                u->buffer.pos += len;
                last = u->buffer.pos;
            }
        } break;
        case 'E': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Error Response");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            while (u->buffer.pos < u->buffer.last) {
                switch (*u->buffer.pos++) {
                    case PG_DIAG_COLUMN_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_COLUMN_NAME = %s", u->buffer.pos); break;
                    case PG_DIAG_CONSTRAINT_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_CONSTRAINT_NAME = %s", u->buffer.pos); break;
                    case PG_DIAG_CONTEXT: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_CONTEXT = %s", u->buffer.pos); break;
                    case PG_DIAG_DATATYPE_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_DATATYPE_NAME = %s", u->buffer.pos); break;
                    case PG_DIAG_INTERNAL_POSITION: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_INTERNAL_POSITION = %s", u->buffer.pos); break;
                    case PG_DIAG_INTERNAL_QUERY: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_INTERNAL_QUERY = %s", u->buffer.pos); break;
                    case PG_DIAG_MESSAGE_DETAIL: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_MESSAGE_DETAIL = %s", u->buffer.pos); break;
                    case PG_DIAG_MESSAGE_HINT: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_MESSAGE_HINT = %s", u->buffer.pos); break;
                    case PG_DIAG_MESSAGE_PRIMARY: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", u->buffer.pos); break;
                    case PG_DIAG_SCHEMA_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SCHEMA_NAME = %s", u->buffer.pos); break;
                    case PG_DIAG_SEVERITY_NONLOCALIZED: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SEVERITY_NONLOCALIZED = %s", u->buffer.pos); break;
                    case PG_DIAG_SEVERITY: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SEVERITY = %s", u->buffer.pos); break;
                    case PG_DIAG_SOURCE_FILE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_FILE = %s", u->buffer.pos); break;
                    case PG_DIAG_SOURCE_FUNCTION: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_FUNCTION = %s", u->buffer.pos); break;
                    case PG_DIAG_SOURCE_LINE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SOURCE_LINE = %s", u->buffer.pos); break;
                    case PG_DIAG_SQLSTATE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_SQLSTATE = %s", u->buffer.pos); break;
                    case PG_DIAG_STATEMENT_POSITION: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_STATEMENT_POSITION = %s", u->buffer.pos); break;
                    case PG_DIAG_TABLE_NAME: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PG_DIAG_TABLE_NAME = %s", u->buffer.pos); break;
                }
                while (*u->buffer.pos++);
            }
            if (c->requests > 1) u->keepalive = !u->headers_in.connection_close;
            rc = NGX_ERROR;
        } break;
        case 'K': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "secret key data from the backend");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pid = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "key = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
        } break;
        case 'R': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Authentication");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "method = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
        } break;
        case 'S': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Parameter Status");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "key = %s", u->buffer.pos);
            while (*u->buffer.pos++);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "val = %s", u->buffer.pos);
            while (*u->buffer.pos++);
        } break;
        case 'T': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Row Description");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            uint16_t nfields = ntohs(*(uint16_t *)u->buffer.pos);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "nfields = %i", nfields);
            u->buffer.pos += sizeof(uint16_t);
            for (uint16_t i = 0; i < nfields; i++) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "name = %s", u->buffer.pos);
                while (*u->buffer.pos++);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "tableid = %i", ntohl(*(uint32_t *)u->buffer.pos));
                u->buffer.pos += sizeof(uint32_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "columnid = %i", ntohs(*(uint16_t *)u->buffer.pos));
                u->buffer.pos += sizeof(uint16_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "typid = %i", ntohl(*(uint32_t *)u->buffer.pos));
                u->buffer.pos += sizeof(uint32_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "typlen = %i", ntohs(*(uint16_t *)u->buffer.pos));
                u->buffer.pos += sizeof(uint16_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "atttypmod = %i", ntohl(*(uint32_t *)u->buffer.pos));
                u->buffer.pos += sizeof(uint32_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "format = %i", ntohs(*(uint16_t *)u->buffer.pos));
                u->buffer.pos += sizeof(uint16_t);
            }
        } break;
        case 'Z': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Ready For Query");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "len = %i", ntohl(*(uint32_t *)u->buffer.pos));
            u->buffer.pos += sizeof(uint32_t);
            switch (*u->buffer.pos++) {
                case 'E': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_INERROR"); break;
                case 'I': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_IDLE");
                    if (c->requests > 1) u->keepalive = !u->headers_in.connection_close; else {
                        c->requests++;
                        rc = NGX_AGAIN;
                    }
                    break;
                case 'T': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_INTRANS"); break;
                default: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TRANS_UNKNOWN"); break;
            }
        } break;
    }
    u->headers_in.content_length_n = last - pos;
    if (last) u->buffer.last = last;
    if (pos) u->buffer.pos = pos;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", rc);
    return rc;
}

static ngx_int_t ngx_pg_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
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
    ngx_http_upstream_t *u = r->upstream;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%O", u->headers_in.content_length_n);
    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED) {
        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;
    } else if (!u->headers_in.content_length_n) {
        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;
    } else {
        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter(void *data, ssize_t bytes) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i", bytes);
    ngx_http_upstream_t *u = r->upstream;
    ngx_chain_t *cl, **ll;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
    if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) return NGX_ERROR;
    *ll = cl;
    cl->buf->flush = 1;
    cl->buf->memory = 1;
    cl->buf->pos = u->buffer.last;
    u->buffer.last += bytes;
    cl->buf->last = u->buffer.last;
    cl->buf->tag = u->output.tag;
    if (u->length == -1) return NGX_OK;
    u->length -= bytes;
    if (!u->length) u->keepalive = !u->headers_in.connection_close;
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
    u->input_filter_init = ngx_pg_input_filter_init;
    u->input_filter = ngx_pg_input_filter;
    u->input_filter_ctx = r;
    if (!plcf->upstream.request_buffering && plcf->upstream.pass_request_body && !r->headers_in.chunked) r->request_body_no_buffering = 1;
    if ((rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init)) >= NGX_HTTP_SPECIAL_RESPONSE) return rc;
    return NGX_DONE;
}

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

static char *ngx_pg_log_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_log_set_log(cf, &pscf->log);
}

static ngx_int_t ngx_pg_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    if (uscf->srv_conf) {
        ngx_pg_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pg_module);
        if (pscf->peer.init_upstream(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "peer.init_upstream != NGX_OK"); return NGX_ERROR; }
        pscf->peer.init = uscf->peer.init ? uscf->peer.init : ngx_http_upstream_init_round_robin_peer;
    } else {
        if (ngx_http_upstream_init_round_robin(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_http_upstream_init_round_robin != NGX_OK"); return NGX_ERROR; }
    }
    uscf->peer.init = ngx_pg_peer_init;
    return NGX_OK;
}

static char *ngx_pg_parse_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, ngx_url_t *u, ngx_chain_t *connect, ngx_http_upstream_server_t *us) {
    ngx_buf_t *b;
    ngx_chain_t *cl = connect;
    uint32_t len = 0;

    ngx_str_t application_name = ngx_string("nginx");
    ngx_str_set(&u->url, "unix:///run/postgresql");
    u->default_port = 5432;

    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint32_t)))) return "!ngx_create_temp_buf";
    *(uint32_t *)b->last = htonl(0x00030000);
    b->last += sizeof(uint32_t);

    ngx_str_t *elts = cf->args->elts;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (us) {
            if (elts[i].len > sizeof("weight=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"weight=", sizeof("weight=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("weight=") - 1),
                    .data = &elts[i].data[sizeof("weight=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be positive", &cmd->name, &str); return NGX_CONF_ERROR; }
                us->weight = (ngx_uint_t)n;
                continue;
            }
            if (elts[i].len > sizeof("max_conns=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("max_conns=") - 1),
                    .data = &elts[i].data[sizeof("max_conns=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_conns\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                us->max_conns = (ngx_uint_t)n;
                continue;
            }
            if (elts[i].len > sizeof("max_fails=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("max_fails=") - 1),
                    .data = &elts[i].data[sizeof("max_fails=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_fails\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                us->max_fails = (ngx_uint_t)n;
                continue;
            }
            if (elts[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("fail_timeout=") - 1),
                    .data = &elts[i].data[sizeof("fail_timeout=") - 1],
                };
                ngx_int_t n = ngx_parse_time(&str, 1);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"fail_timeout\" value \"%V\" must be time", &cmd->name, &str); return NGX_CONF_ERROR; }
                us->fail_timeout = (time_t)n;
                continue;
            }
            if (elts[i].len == sizeof("backup") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"backup", sizeof("backup") - 1)) {
                us->backup = 1;
                continue;
            }
            if (elts[i].len == sizeof("down") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"down", sizeof("down") - 1)) {
                us->down = 1;
                continue;
            }
        }
        if (elts[i].len > sizeof("application_name=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"application_name=", sizeof("application_name=") - 1)) {
            ngx_str_t str = {
                .len = elts[i].len - (sizeof("application_name=") - 1),
                .data = &elts[i].data[sizeof("application_name=") - 1],
            };
            application_name = str;
            continue;
        }
        if (elts[i].len > sizeof("host=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"host=", sizeof("host=") - 1)) {
            ngx_str_t str = {
                .len = elts[i].len - (sizeof("host=") - 1),
                .data = &elts[i].data[sizeof("host=") - 1],
            };
            u->url = str;
            continue;
        }
        if (elts[i].len > sizeof("port=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"port=", sizeof("port=") - 1)) {
            ngx_str_t str = {
                .len = elts[i].len - (sizeof("port=") - 1),
                .data = &elts[i].data[sizeof("port=") - 1],
            };
            ngx_int_t n = ngx_atoi(str.data, str.len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"port\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
            if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"port\" value \"%V\" must be positive", &cmd->name, &str); return NGX_CONF_ERROR; }
            u->default_port = (ngx_uint_t)n;
            continue;
        }
        if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
        if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += elts[i].len + sizeof(u_char)))) return "!ngx_create_temp_buf";
        for (ngx_uint_t j = 0; j < elts[i].len; j++) *b->last++ = elts[i].data[j] == '=' ? (u_char)0 : elts[i].data[j];
        *b->last++ = (u_char)0;
    }

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof("application_name") - 1 + sizeof(u_char) + application_name.len + sizeof(u_char)))) return "!ngx_create_temp_buf";
    b->last = ngx_copy(b->last, "application_name", sizeof("application_name") - 1);
    *b->last++ = (u_char)0;
    b->last = ngx_copy(b->last, application_name.data, application_name.len);
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    *(uint32_t *)connect->buf->last = htonl(len);
    connect->buf->last += sizeof(len);

    cl->next = NULL;

    ngx_uint_t i = 0;
    for (ngx_chain_t *cl = connect; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        for (u_char *p = b->pos; p < b->last; p++) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%i:%i:%c", i++, *p, *p);
        }
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->connect || plcf->upstream.upstream) return "duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pg_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_url_t u = {0};
    char *rv;
    if (!(plcf->connect = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if ((rv = ngx_pg_parse_url(cf, cmd, conf, &u, plcf->connect, NULL)) != NGX_CONF_OK) return rv;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "url = %V", &u.url);
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0))) return NGX_CONF_ERROR;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "u.naddrs = %i", u.naddrs);
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    return NGX_CONF_OK;
}

static char *ngx_pg_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;

    ngx_buf_t *b;
    ngx_chain_t *cl, *cl_len;
    uint32_t len = 0;

    ngx_str_t *elts = cf->args->elts;
    ngx_str_t query = elts[1];

    if (!(cl = plcf->query.query = plcf->query.parse = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'P';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += query.len + sizeof(u_char)))) return "!ngx_create_temp_buf";
    b->last = ngx_copy(b->last, query.data, query.len);
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint16_t)))) return "!ngx_create_temp_buf";
    *(uint16_t *)b->last = htons(0);
    b->last += sizeof(uint16_t);

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    len = 0;

    if (!(cl = cl->next = plcf->query.bind = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'B';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint16_t)))) return "!ngx_create_temp_buf";
    *(uint16_t *)b->last = htons(0);
    b->last += sizeof(uint16_t);

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint16_t)))) return "!ngx_create_temp_buf";
    *(uint16_t *)b->last = htons(0);
    b->last += sizeof(uint16_t);

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint16_t)))) return "!ngx_create_temp_buf";
    *(uint16_t *)b->last = htons(0);
    b->last += sizeof(uint16_t);

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    len = 0;

    if (!(cl = cl->next = plcf->query.describe = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'D';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'P';

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    len = 0;

    if (!(cl = cl->next = plcf->query.execute = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'E';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint32_t)))) return "!ngx_create_temp_buf";
    *(uint32_t *)b->last = htonl(0);
    b->last += sizeof(uint32_t);

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    len = 0;

    if (!(cl = cl->next = plcf->query.close = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'C';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'P';

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    len = 0;

    if (!(cl = cl->next = plcf->query.sync = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'S';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    cl->next = NULL;
    ngx_uint_t i = 0;
    for (ngx_chain_t *cl = plcf->query.query; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        for (u_char *p = b->pos; p < b->last; p++) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%i:%i:%c", i++, *p, *p);
        }
    }

    return NGX_CONF_OK;
}

static char *ngx_pg_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    if (pscf->connect) return "duplicate";
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    ngx_url_t u = {0};
    ngx_http_upstream_server_t *us;
    if (!(us = ngx_array_push(uscf->servers))) return "!ngx_array_push";
    ngx_memzero(us, sizeof(*us));
    us->fail_timeout = 10;
    us->max_fails = 1;
    us->weight = 1;
    char *rv;
    if (!(pscf->connect = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if ((rv = ngx_pg_parse_url(cf, cmd, conf, &u, pscf->connect, us)) != NGX_CONF_OK) return rv;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "url = %V", &u.url);
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) return u.err ? u.err : "ngx_parse_url != NGX_OK";
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "u.naddrs = %i", u.naddrs);
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->name = u.url;
    return NGX_CONF_OK;
}

static char *ngx_pg_upstream_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->upstream.upstream) return "duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pg_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_url_t u = {0};
    ngx_str_t *elts = cf->args->elts;
    u.no_resolve = 1;
    u.url = elts[1];
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "url = %V", &u.url);
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0))) return NGX_CONF_ERROR;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "u.naddrs = %i", u.naddrs);
    return NGX_CONF_OK;
}

static ngx_command_t ngx_pg_commands[] = {
  { .name = ngx_string("pg_connect_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_pg_loc_conf_t, upstream.connect_timeout),
    .post = NULL },
  { .name = ngx_string("pg_log"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_log_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("pg_pass"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_pass_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("pg_query"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_pg_query_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("pg_read_request_body"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_pg_loc_conf_t, read_request_body),
    .post = NULL },
  { .name = ngx_string("pg_server"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_server_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("pg_upstream"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_pg_upstream_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
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
