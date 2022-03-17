#include <ngx_http.h>
#include "pg_parser.h"

ngx_module_t ngx_pg_module;

typedef struct {
    ngx_chain_t *cl;
    ngx_http_upstream_server_t *us;
    ngx_url_t url;
} ngx_pg_connect_t;

typedef struct {
    ngx_chain_t *bind;
    ngx_chain_t *close;
    ngx_chain_t *describe;
    ngx_chain_t *execute;
    ngx_chain_t *parse;
    ngx_chain_t *sync;
} ngx_pg_query_t;

typedef struct {
    ngx_chain_t *cmd;
    ngx_http_request_t *request;
    ngx_queue_t queue;
} ngx_pg_cmd_queue_t;

typedef struct {
    ngx_array_t query;
    ngx_http_upstream_conf_t upstream;
    ngx_pg_connect_t connect;
} ngx_pg_loc_conf_t;

typedef struct {
    ngx_array_t connect;
    ngx_log_t *log;
    struct {
        ngx_http_upstream_init_peer_pt init;
        ngx_http_upstream_init_pt init_upstream;
    } peer;
    struct {
        ngx_queue_t queue;
    } save;
} ngx_pg_srv_conf_t;

typedef struct {
    ngx_str_t key;
    ngx_str_t val;
} ngx_pg_status_t;

typedef struct {
    ngx_array_t status;
    ngx_buf_t buffer;
    ngx_connection_t *connection;
    ngx_queue_t queue;
    pg_parser_t parser;
    struct {
        ngx_queue_t queue;
    } cmd;
    struct {
        ngx_event_handler_pt read_handler;
        ngx_event_handler_pt write_handler;
        void *data;
    } keep;
} ngx_pg_save_t;

typedef struct {
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_pg_save_t *save;
    ngx_pg_srv_conf_t *conf;
} ngx_pg_data_t;

static int ngx_pg_parser_all(pg_parser_t *parser, const uintptr_t data) {
    const unsigned char *p = (const unsigned char *)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i:%c", *p, *p);
    return 0;
}

static int ngx_pg_parser_auth_method(pg_parser_t *parser, const uintptr_t data) {
    uint32_t method = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", method);
    return 0;
}

static int ngx_pg_parser_auth(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_bind(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_close(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_complete(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_complete_val(pg_parser_t *parser, size_t len, const unsigned char *data) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return 0;
}

static int ngx_pg_parser_data(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_data_len(pg_parser_t *parser, const uintptr_t data) {
    uint32_t length = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_data_val(pg_parser_t *parser, size_t len, const unsigned char *data) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return 0;
}

static int ngx_pg_parser_data_tupnfields(pg_parser_t *parser, const uintptr_t data) {
    uint16_t length = (uint16_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_len(pg_parser_t *parser, const uintptr_t data) {
    uint32_t length = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    parser->len = length - 4;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_parse(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_ready(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_ready_idle(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_ready_inerror(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_ready_intrans(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_secret_key(pg_parser_t *parser, const uintptr_t data) {
    uint32_t length = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_secret(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_secret_pid(pg_parser_t *parser, const uintptr_t data) {
    uint32_t length = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_status_done(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (!s->status.nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!s->status.nelts"); return NGX_ERROR; }
    ngx_pg_status_t *status = s->status.elts;
    status = &status[s->status.nelts - 1];
    status->val.len = ngx_strlen(status->val.data);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%V = %V", &status->key, &status->val);
    return 0;
}

static int ngx_pg_parser_status_key(pg_parser_t *parser, size_t len, const unsigned char *data) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    if (!s->status.nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!s->status.nelts"); return NGX_ERROR; }
    ngx_pg_status_t *status = s->status.elts;
    status = &status[s->status.nelts - 1];
    (void)strncat((char *)status->key.data, (char *)data, len);
    return 0;
}

static int ngx_pg_parser_status(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_status_open(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (!parser->len) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!parser->len"); return NGX_ERROR; }
    ngx_pg_status_t *status;
    if (!(status = ngx_array_push(&s->status))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
    ngx_memzero(status, sizeof(*status));
    if (!(status->key.data = ngx_pcalloc(s->connection->pool, parser->len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    return 0;
}

static int ngx_pg_parser_status_val(pg_parser_t *parser, size_t len, const unsigned char *data) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    if (!s->status.nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!s->status.nelts"); return NGX_ERROR; }
    ngx_pg_status_t *status = s->status.elts;
    status = &status[s->status.nelts - 1];
    if (!status->val.data) status->val.data = status->key.data + (status->key.len = ngx_strlen(status->key.data)) + 1;
    (void)strncat((char *)status->val.data, (char *)data, len);
    return 0;
}

static int ngx_pg_parser_tup_atttypmod(pg_parser_t *parser, const uintptr_t data) {
    uint32_t length = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_tup_columnid(pg_parser_t *parser, const uintptr_t data) {
    uint16_t length = (uint16_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_tup_format(pg_parser_t *parser, const uintptr_t data) {
    uint16_t length = (uint16_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_tup_name(pg_parser_t *parser, size_t len, const unsigned char *data) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return 0;
}

static int ngx_pg_parser_tup_nfields(pg_parser_t *parser, const uintptr_t data) {
    uint16_t length = (uint16_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_tup(pg_parser_t *parser) {
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return 0;
}

static int ngx_pg_parser_tup_tableid(pg_parser_t *parser, const uintptr_t data) {
    uint32_t length = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_tup_typid(pg_parser_t *parser, const uintptr_t data) {
    uint32_t length = (uint32_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static int ngx_pg_parser_tup_typlen(pg_parser_t *parser, const uintptr_t data) {
    uint16_t length = (uint16_t)data;
    ngx_pg_save_t *s = parser->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", length);
    return 0;
}

static const pg_parser_settings_t ngx_pg_parser_settings = {
    .all = ngx_pg_parser_all,
    .auth_method = ngx_pg_parser_auth_method,
    .auth = ngx_pg_parser_auth,
    .bind = ngx_pg_parser_bind,
    .close = ngx_pg_parser_close,
    .complete = ngx_pg_parser_complete,
    .complete_val = ngx_pg_parser_complete_val,
    .data_len = ngx_pg_parser_data_len,
    .data = ngx_pg_parser_data,
    .data_tupnfields = ngx_pg_parser_data_tupnfields,
    .data_val = ngx_pg_parser_data_val,
    .len = ngx_pg_parser_len,
    .parse = ngx_pg_parser_parse,
    .ready_idle = ngx_pg_parser_ready_idle,
    .ready_inerror = ngx_pg_parser_ready_inerror,
    .ready_intrans = ngx_pg_parser_ready_intrans,
    .ready = ngx_pg_parser_ready,
    .secret_key = ngx_pg_parser_secret_key,
    .secret = ngx_pg_parser_secret,
    .secret_pid = ngx_pg_parser_secret_pid,
    .status_done = ngx_pg_parser_status_done,
    .status_key = ngx_pg_parser_status_key,
    .status = ngx_pg_parser_status,
    .status_open = ngx_pg_parser_status_open,
    .status_val = ngx_pg_parser_status_val,
    .tup_atttypmod = ngx_pg_parser_tup_atttypmod,
    .tup_columnid = ngx_pg_parser_tup_columnid,
    .tup_format = ngx_pg_parser_tup_format,
    .tup_name = ngx_pg_parser_tup_name,
    .tup_nfields = ngx_pg_parser_tup_nfields,
    .tup = ngx_pg_parser_tup,
    .tup_tableid = ngx_pg_parser_tup_tableid,
    .tup_typid = ngx_pg_parser_tup_typid,
    .tup_typlen = ngx_pg_parser_tup_typlen,
};

static void ngx_pg_save_cln_handler(void *data) {
    ngx_pg_save_t *s = data;
    ngx_queue_remove(&s->queue);
//    for (ngx_queue_t *q = ngx_queue_head(&s->cmd.queue), *_; q != ngx_queue_sentinel(&s->cmd.queue) && (_ = ngx_queue_next(q)); q = _) ngx_queue_remove(q);

    ngx_connection_t *c = s->connection;
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
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = out; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "%i:%i:%c", i++, *p, *p);

    ngx_chain_writer_ctx_t ctx = { .out = out, .last = &last, .connection = c, .pool = c->pool, .limit = 0 };

    ngx_chain_writer(&ctx, NULL);
}

static ngx_int_t ngx_pg_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pg_data_t *d = data;
    ngx_int_t rc;
    switch ((rc = d->peer.get(pc, d->peer.data))) {
        case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_DONE"); break;
        case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_OK"); break;
        default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc); return rc; break;
    }
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    ngx_pg_srv_conf_t *pscf = d->conf;
    if (pc->connection) {
        if (pscf) for (ngx_queue_t *q = ngx_queue_head(&pscf->save.queue), *_; q != ngx_queue_sentinel(&pscf->save.queue) && (_ = ngx_queue_next(q)); q = _) {
            ngx_pg_save_t *s = d->save = ngx_queue_data(q, ngx_pg_save_t, queue);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "s = %p", s);
            if (s->connection == pc->connection) break;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "sizeof(*pc->connection->pool) = %i", sizeof(*pc->connection->pool));
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "sizeof(*d->save) = %i", sizeof(*d->save));
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "pc->connection->pool = %p", pc->connection->pool);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "d->save = %p", d->save);
        if (sizeof(*d->save) <= pc->connection->pool->max) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "pc->connection->pool + sizeof(*pc->connection->pool) = %p", (char *)pc->connection->pool + sizeof(*pc->connection->pool));
        } else {}
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "d->save - pc->connection->pool = %p", (char *)d->save - (char *)pc->connection->pool);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "pc->connection->pool - d->save = %p", (char *)pc->connection->pool - (char *)d->save);
    } else {
        pc->get = ngx_event_get_peer;
        switch ((rc = ngx_event_connect_peer(pc))) {
            case NGX_AGAIN: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_AGAIN"); break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_DONE"); break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_OK"); break;
            default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc); return rc; break;
        }
        pc->get = ngx_pg_peer_get;
        ngx_connection_t *c = pc->connection;
        if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!c"); return NGX_ERROR; }
        if (c->pool) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "c->pool"); return NGX_ERROR; }
        if (!(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); return NGX_ERROR; }
        ngx_pg_save_t *s;
        if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        if (ngx_array_init(&s->status, c->pool, 1, sizeof(ngx_pg_status_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        s->parser.data = s;
        pg_parser_init(&s->parser);
        if (pscf) { ngx_queue_insert_tail(&pscf->save.queue, &s->queue); } else { ngx_queue_init(&s->queue); }
        s->connection = c;
        ngx_pool_cleanup_t *cln;
        if (!(cln = ngx_pool_cleanup_add(c->pool, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
        cln->data = s;
        cln->handler = ngx_pg_save_cln_handler;
        ngx_queue_init(&s->cmd.queue);
        ngx_pg_cmd_queue_t *cq;
        if (!(cq = ngx_pcalloc(r->pool, sizeof(*cq)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        cq->request = r;
        ngx_queue_insert_tail(&s->cmd.queue, &cq->queue);
        if (pscf) {
            ngx_pg_connect_t *connect = pscf->connect.elts;
            ngx_uint_t i;
            for (i = 0; i < pscf->connect.nelts; i++) for (ngx_uint_t j = 0; j < connect[i].url.naddrs; j++) if (!ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)connect[i].url.addrs[j].sockaddr, pc->socklen, connect[i].url.addrs[j].socklen)) { cq->cmd = connect[i].cl; goto found; }
found:
            if (i == pscf->connect.nelts) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connect not found"); return NGX_BUSY; }
        } else cq->cmd = plcf->connect.cl;
    }
    ngx_pg_save_t *s = d->save;
    ngx_pg_cmd_queue_t *cq;
    ngx_pg_query_t *elts = plcf->query.elts;
    for (ngx_uint_t i = 0; i < plcf->query.nelts; i++) {
        if (!(cq = ngx_pcalloc(r->pool, sizeof(*cq)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        cq->cmd = elts[i].parse;
        cq->request = r;
        ngx_queue_insert_tail(&s->cmd.queue, &cq->queue);
    }
    ngx_chain_t *cl;
    ngx_http_upstream_t *u = r->upstream;
    if (!(cl = u->request_bufs = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    ngx_uint_t j = 0;
    for (ngx_queue_t *q = ngx_queue_head(&s->cmd.queue), *_; q != ngx_queue_sentinel(&s->cmd.queue) && (_ = ngx_queue_next(q)); q = _) {
        ngx_pg_cmd_queue_t *cq = ngx_queue_data(q, ngx_pg_cmd_queue_t, queue);
        for (ngx_chain_t *cmd = cq->cmd; cmd; cmd = cmd->next) {
            if (j++ && !(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
            cl->buf = cmd->buf;
        }
    }
    cl->next = NULL;
//    ngx_uint_t i = 0;
    for (ngx_chain_t *cl = u->request_bufs; cl; cl = cl->next) {
        ngx_buf_t *b = cl->buf;
        b->pos = b->start;
//        for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i:%i:%c", i++, *p, *p);
    }
    return NGX_DONE;
}

static ngx_int_t ngx_pg_process_response(ngx_http_request_t *r, u_char *pos, u_char *last) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_chain_t *cl, **ll;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
    if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
    *ll = cl;
//    ll = &cl->next;
    ngx_buf_t *b = cl->buf;
    b->flush = 1;
    b->last = last;
    b->memory = 1;
    b->pos = pos;
    b->tag = u->output.tag;
    for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%c", *p, *p);
    return NGX_OK;
}

static ngx_int_t ngx_pg_parse(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_buf_t *b = &s->buffer;
    ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", b->last - b->pos);
    while (b->pos < b->last) switch (*b->pos++) {
        case '1': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Parse Complete");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
        } break;
        case '2': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Bind Complete");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
        } break;
        case '3': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Close Complete");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
        } break;
        case 'C': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Command Complete");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "command = %s", b->pos);
            while (*b->pos++);
        } break;
        case 'D': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Data Row");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            uint16_t tupnfields = ntohs(*(uint16_t *)b->pos);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "tupnfields = %i", tupnfields);
            b->pos += sizeof(uint16_t);
            for (uint16_t i = 0; i < tupnfields; i++) {
                uint32_t len = ntohl(*(uint32_t *)b->pos);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", len);
                b->pos += sizeof(uint32_t);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "val = %*s", len, b->pos);
                u_char *pos = b->pos;
                b->pos += len;
                u_char *last = b->pos;
                if (!ngx_queue_empty(&s->cmd.queue)) {
                    ngx_queue_t *q = ngx_queue_head(&s->cmd.queue);
                    ngx_pg_cmd_queue_t *cq = ngx_queue_data(q, ngx_pg_cmd_queue_t, queue);
                    ngx_http_request_t *r = cq->request;
                    if (r && ngx_pg_process_response(r, pos, last) == NGX_ERROR) return NGX_ERROR;
                }
            }
        } break;
        case 'E': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Error Response");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            while (b->pos < b->last) switch (*b->pos++) {
                case 0: {
                    if (!ngx_queue_empty(&s->cmd.queue)) {
                        ngx_queue_t *q = ngx_queue_head(&s->cmd.queue);
                        ngx_pg_cmd_queue_t *cq = ngx_queue_data(q, ngx_pg_cmd_queue_t, queue);
                        ngx_http_request_t *r = cq->request;
                        if (r) {
                            ngx_http_upstream_t *u = r->upstream;
                            u->headers_in.status_n = NGX_HTTP_INTERNAL_SERVER_ERROR;
                            if (u->conf->intercept_errors) goto cont;
                            u->keepalive = 1;
                        }
                    }
                    return NGX_ERROR;
                } break;
                case 'c': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "column_name = %s", b->pos); while (*b->pos++); break;
                case 'C': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "sqlstate = %s", b->pos); while (*b->pos++); break;
                case 'd': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "datatype_name = %s", b->pos); while (*b->pos++); break;
                case 'D': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "message_detail = %s", b->pos); while (*b->pos++); break;
                case 'F': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "source_file = %s", b->pos); while (*b->pos++); break;
                case 'H': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "message_hint = %s", b->pos); while (*b->pos++); break;
                case 'L': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "source_line = %s", b->pos); while (*b->pos++); break;
                case 'M': {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "message_primary = %s", b->pos);
                    u_char *pos = b->pos;
                    while (*b->pos++);
                    u_char *last = b->pos - 1;
                    if (!ngx_queue_empty(&s->cmd.queue)) {
                        ngx_queue_t *q = ngx_queue_head(&s->cmd.queue);
                        ngx_pg_cmd_queue_t *cq = ngx_queue_data(q, ngx_pg_cmd_queue_t, queue);
                        ngx_http_request_t *r = cq->request;
                        if (r) {
                            ngx_http_upstream_t *u = r->upstream;
                            if (u->conf->intercept_errors && ngx_pg_process_response(r, pos, last) == NGX_ERROR) return NGX_ERROR;
                        }
                    }
                } break;
                case 'n': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "constraint_name = %s", b->pos); while (*b->pos++); break;
                case 'p': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "internal_position = %s", b->pos); while (*b->pos++); break;
                case 'P': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "statement_position = %s", b->pos); while (*b->pos++); break;
                case 'q': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "internal_query = %s", b->pos); while (*b->pos++); break;
                case 'R': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "source_function = %s", b->pos); while (*b->pos++); break;
                case 's': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "schema_name = %s", b->pos); while (*b->pos++); break;
                case 'S': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "severity = %s", b->pos); while (*b->pos++); break;
                case 't': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "table_name = %s", b->pos); while (*b->pos++); break;
                case 'V': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "severity_nonlocalized = %s", b->pos); while (*b->pos++); break;
                case 'W': ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "context = %s", b->pos); while (*b->pos++); break;
                default: {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "unknown error %i:%c", *(b->pos - 1), *(b->pos - 1));
                    ngx_uint_t i = 0; for (u_char *p = b->pos - 1; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i:%i:%c", i++, *p, *p);
                    return NGX_ERROR;
                } break;
            }
            cont:;
        } break;
        case 'K': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "secret key data from the backend");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "pid = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "key = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
        } break;
        case 'R': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Authentication");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "method = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
        } break;
        case 'S': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Parameter Status");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "key = %s", b->pos);
            ngx_str_t key;
            key.data = b->pos;
            while (*b->pos++);
            key.len = b->pos - key.data - 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "value = %s", b->pos);
            ngx_str_t value;
            value.data = b->pos;
            while (*b->pos++);
            value.len = b->pos - value.data - 1;
            if (!ngx_queue_empty(&s->cmd.queue)) {
                ngx_queue_t *q = ngx_queue_head(&s->cmd.queue);
                ngx_pg_cmd_queue_t *cq = ngx_queue_data(q, ngx_pg_cmd_queue_t, queue);
                ngx_http_request_t *r = cq->request;
                if (r) {
                    ngx_table_elt_t *h;
                    if (!(h = ngx_list_push(&r->headers_out.headers))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_list_push"); return NGX_ERROR; }
                    h->hash = 1;
                    h->key = key;
                    h->value = value;
                }
            }
        } break;
        case 'T': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Row Description");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            uint16_t nfields = ntohs(*(uint16_t *)b->pos);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "nfields = %i", nfields);
            b->pos += sizeof(uint16_t);
            for (uint16_t i = 0; i < nfields; i++) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "name = %s", b->pos);
                while (*b->pos++);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "tableid = %i", ntohl(*(uint32_t *)b->pos));
                b->pos += sizeof(uint32_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "columnid = %i", ntohs(*(uint16_t *)b->pos));
                b->pos += sizeof(uint16_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "typid = %i", ntohl(*(uint32_t *)b->pos));
                b->pos += sizeof(uint32_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "typlen = %i", ntohs(*(uint16_t *)b->pos));
                b->pos += sizeof(uint16_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "atttypmod = %i", ntohl(*(uint32_t *)b->pos));
                b->pos += sizeof(uint32_t);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "format = %i", ntohs(*(uint16_t *)b->pos));
                b->pos += sizeof(uint16_t);
            }
        } break;
        case 'Z': {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "Ready For Query");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "len = %i", ntohl(*(uint32_t *)b->pos));
            b->pos += sizeof(uint32_t);
            switch (*b->pos++) {
                case 'E': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "TRANS_INERROR"); break;
                case 'I': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "TRANS_IDLE"); break;
                case 'T': ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "TRANS_INTRANS"); break;
                default: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "TRANS_UNKNOWN"); break;
            }
            if (!ngx_queue_empty(&s->cmd.queue)) { ngx_queue_t *q = ngx_queue_head(&s->cmd.queue); ngx_queue_remove(q); }
        } break;
        default: {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "unknown command %i:%c", *(b->pos - 1), *(b->pos - 1));
            ngx_uint_t i = 0; for (u_char *p = b->pos - 1; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i:%i:%c", i++, *p, *p);
            return NGX_ERROR;
        } break;
    }
//    b->last = b->pos = b->start;
    return ngx_queue_empty(&s->cmd.queue) ? NGX_OK : NGX_AGAIN;
}

static void ngx_pg_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_pg_save_t *s = c->data;
    if (ngx_pg_parse(s) == NGX_OK) return;
    c->data = s->keep.data;
    s->keep.read_handler(ev);
    c->data = s;
}

static void ngx_pg_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_pg_save_t *s = c->data;
    c->data = s->keep.data;
    s->keep.write_handler(ev);
    c->data = s;
}

static void ngx_pg_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %i", state);
    ngx_pg_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    if (pc->connection) return;
    ngx_pg_srv_conf_t *pscf = d->conf;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "pscf = %p", pscf);
    if (!pscf) return;
    ngx_pg_save_t *s = d->save;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "s = %p", s);
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "c = %p", c);
    s->keep.data = c->data;
    s->keep.read_handler = c->read->handler;
    s->keep.write_handler = c->write->handler;
    c->data = s;
    c->read->handler = ngx_pg_read_handler;
    c->write->handler = ngx_pg_write_handler;
    if (!pscf->log) return;
    c->log = pscf->log;
    c->pool->log = pscf->log;
    c->read->log = pscf->log;
    c->write->log = pscf->log;
}

static ngx_int_t ngx_pg_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    ngx_pg_data_t *d;
    if (!(d = ngx_pcalloc(r->pool, sizeof(*d)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    if (uscf->srv_conf) {
        ngx_pg_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pg_module);
        if (pscf->peer.init(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
        d->conf = pscf;
    } else {
        if (ngx_http_upstream_init_round_robin_peer(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_init_round_robin_peer != NGX_OK"); return NGX_ERROR; }
    }
    ngx_http_upstream_t *u = r->upstream;
    d->peer = u->peer;
    d->request = r;
    u->conf->upstream = uscf;
    u->peer.data = d;
    u->peer.free = ngx_pg_peer_free;
    u->peer.get = ngx_pg_peer_get;
    return NGX_OK;
}

static void ngx_pg_abort_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
}

static ngx_int_t ngx_pg_create_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    if (uscf->peer.init != ngx_pg_peer_init) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "uscf->peer.init != ngx_pg_peer_init");
    uscf->peer.init = ngx_pg_peer_init;
    return NGX_OK;
}

static void ngx_pg_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
}

static ngx_int_t ngx_pg_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    u->headers_in.status_n = NGX_HTTP_OK;
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    ngx_buf_t *b = &u->buffer;
//    ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    for (int i; (b->pos < b->last) && (i = pg_parser_execute(&s->parser, &ngx_pg_parser_settings, b->pos, b->last)) > 0; b->pos += i) ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "i = %i", i);
    s->buffer = u->buffer;
    ngx_int_t rc = ngx_pg_parse(s);
    u->buffer = s->buffer;
    return rc;
}

static ngx_int_t ngx_pg_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter_init(void *data) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    u->keepalive = !u->headers_in.connection_close;
    u->length = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter(void *data, ssize_t bytes) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bytes = %i", bytes);
    ngx_http_upstream_t *u = r->upstream;
    ngx_buf_t *b = &u->buffer;
    ngx_uint_t i = 0; for (u_char *p = b->last; p < b->last + bytes; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    b->last += bytes;
    if (!(u->length -= bytes)) u->keepalive = !u->headers_in.connection_close;
    return NGX_OK;
}

static ngx_int_t ngx_pg_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_int_t rc;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (plcf->upstream.pass_request_body && (rc = ngx_http_discard_request_body(r)) != NGX_OK) return rc;
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
//    u->buffering = u->conf->buffering;
    u->input_filter_init = ngx_pg_input_filter_init;
    u->input_filter = ngx_pg_input_filter;
    u->input_filter_ctx = r;
//    if (!u->conf->request_buffering && u->conf->pass_request_body && !r->headers_in.chunked) r->request_body_no_buffering = 1;
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
//    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
//    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;
//    conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
//    conf->upstream.local = NGX_CONF_UNSET_PTR;
//    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
//    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
//    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
//    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
//    conf->upstream.store = NGX_CONF_UNSET;
//    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
    ngx_str_set(&conf->upstream.module, "pg");
    return conf;
}

/*static ngx_path_init_t ngx_pg_temp_path = {
#ifdef NGX_CONF_PREFIX
    ngx_string(NGX_CONF_PREFIX "pg_temp"), { 1, 2, 0 }
#else
    ngx_string(NGX_PREFIX "pg_temp"), { 1, 2, 0 }
#endif
};*/

/*static ngx_str_t ngx_pg_hide_headers[] = {
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};*/

static char *ngx_pg_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_pg_loc_conf_t *prev = parent;
    ngx_pg_loc_conf_t *conf = child;
    if (!conf->upstream.upstream) conf->upstream = prev->upstream;
//    if (conf->upstream.store == NGX_CONF_UNSET) {
//        ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);
//        conf->upstream.store_lengths = prev->upstream.store_lengths;
//        conf->upstream.store_values = prev->upstream.store_values;
//    }
//    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers, prev->upstream.ignore_headers, NGX_CONF_BITMASK_SET);
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_ERROR|NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs, 8, ngx_pagesize);
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);
//    ngx_conf_merge_ptr_value(conf->upstream.local, prev->upstream.local, NULL);
    ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t)ngx_pagesize);
    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf, prev->upstream.busy_buffers_size_conf, NGX_CONF_UNSET_SIZE);
//    ngx_conf_merge_size_value(conf->upstream.limit_rate, prev->upstream.limit_rate, 0);
//    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf, prev->upstream.max_temp_file_size_conf, NGX_CONF_UNSET_SIZE);
//    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf, prev->upstream.temp_file_write_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);
//    ngx_conf_merge_uint_value(conf->upstream.store_access, prev->upstream.store_access, 0600);
//    ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering, 0);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);
    ngx_conf_merge_value(conf->upstream.pass_request_body, prev->upstream.pass_request_body, 0);
//    ngx_conf_merge_value(conf->upstream.request_buffering, prev->upstream.request_buffering, 0);
    ngx_conf_merge_value(conf->upstream.socket_keepalive, prev->upstream.socket_keepalive, 0);
    if (conf->upstream.bufs.num < 2) return "there must be at least 2 \"pg_buffers\"";
    size_t size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) size = conf->upstream.bufs.size;
    conf->upstream.busy_buffers_size = conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE ? 2 * size : conf->upstream.busy_buffers_size_conf;
    if (conf->upstream.busy_buffers_size < size) return "\"pg_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
    if (conf->upstream.busy_buffers_size > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) return "\"pg_busy_buffers_size\" must be less than the size of all \"pg_buffers\" minus one buffer";
//    conf->upstream.temp_file_write_size = conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE ? 2 * size : conf->upstream.temp_file_write_size_conf;
//    if (conf->upstream.temp_file_write_size < size) return "\"pg_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
//    conf->upstream.max_temp_file_size = conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE ? 1024 * 1024 * 1024 : conf->upstream.max_temp_file_size_conf;
//    if (conf->upstream.max_temp_file_size && conf->upstream.max_temp_file_size < size) return "\"pg_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
//    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path, prev->upstream.temp_path, &ngx_pg_temp_path) != NGX_OK) return NGX_CONF_ERROR;
//    ngx_hash_init_t hash = {0};
//    hash.max_size = 512;
//    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
//    hash.name = "pg_hide_headers_hash";
//    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, ngx_pg_hide_headers, &hash) != NGX_OK) return NGX_CONF_ERROR;
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

static void ngx_pg_srv_cln_handler(void *data) {
    ngx_pg_srv_conf_t *pscf = data;
    for (ngx_queue_t *q = ngx_queue_head(&pscf->save.queue), *_; q != ngx_queue_sentinel(&pscf->save.queue) && (_ = ngx_queue_next(q)); q = _) {
        ngx_pg_save_t *s = ngx_queue_data(q, ngx_pg_save_t, queue);
        ngx_pg_save_cln_handler(s);
    }
}

static ngx_int_t ngx_pg_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    if (uscf->srv_conf) {
        ngx_pg_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pg_module);
        if (pscf->peer.init_upstream(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "peer.init_upstream != NGX_OK"); return NGX_ERROR; }
        pscf->peer.init = uscf->peer.init ? uscf->peer.init : ngx_http_upstream_init_round_robin_peer;
        ngx_queue_init(&pscf->save.queue);
        ngx_pool_cleanup_t *cln;
        if (!(cln = ngx_pool_cleanup_add(cf->pool, 0))) { ngx_log_error(NGX_LOG_ERR, cf->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
        cln->data = pscf;
        cln->handler = ngx_pg_srv_cln_handler;
    } else {
        if (ngx_http_upstream_init_round_robin(cf, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_http_upstream_init_round_robin != NGX_OK"); return NGX_ERROR; }
    }
    uscf->peer.init = ngx_pg_peer_init;
    return NGX_OK;
}

static char *ngx_pg_parse_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_buf_t *b;
    ngx_pg_connect_t *connect = conf;
    ngx_chain_t *cl = connect->cl;
    uint32_t len = 0;

    ngx_str_t application_name = ngx_string("nginx");
    ngx_str_set(&connect->url.url, "unix:///run/postgresql");
    connect->url.default_port = 5432;

    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint32_t)))) return "!ngx_create_temp_buf";
    *(uint32_t *)b->last = htonl(0x00030000);
    b->last += sizeof(uint32_t);

    ngx_str_t *elts = cf->args->elts;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (connect->us) {
            if (elts[i].len > sizeof("weight=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"weight=", sizeof("weight=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("weight=") - 1),
                    .data = &elts[i].data[sizeof("weight=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be positive", &cmd->name, &str); return NGX_CONF_ERROR; }
                connect->us->weight = (ngx_uint_t)n;
                continue;
            }
            if (elts[i].len > sizeof("max_conns=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("max_conns=") - 1),
                    .data = &elts[i].data[sizeof("max_conns=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_conns\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                connect->us->max_conns = (ngx_uint_t)n;
                continue;
            }
            if (elts[i].len > sizeof("max_fails=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("max_fails=") - 1),
                    .data = &elts[i].data[sizeof("max_fails=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_fails\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                connect->us->max_fails = (ngx_uint_t)n;
                continue;
            }
            if (elts[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1)) {
                ngx_str_t str = {
                    .len = elts[i].len - (sizeof("fail_timeout=") - 1),
                    .data = &elts[i].data[sizeof("fail_timeout=") - 1],
                };
                ngx_int_t n = ngx_parse_time(&str, 1);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"fail_timeout\" value \"%V\" must be time", &cmd->name, &str); return NGX_CONF_ERROR; }
                connect->us->fail_timeout = (time_t)n;
                continue;
            }
            if (elts[i].len == sizeof("backup") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"backup", sizeof("backup") - 1)) {
                connect->us->backup = 1;
                continue;
            }
            if (elts[i].len == sizeof("down") - 1 && !ngx_strncmp(elts[i].data, (u_char *)"down", sizeof("down") - 1)) {
                connect->us->down = 1;
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
            connect->url.url = str;
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
            connect->url.default_port = (ngx_uint_t)n;
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

    *(uint32_t *)connect->cl->buf->last = htonl(len);
    connect->cl->buf->last += sizeof(len);

    cl->next = NULL;

//    ngx_uint_t i = 0; for (ngx_chain_t *cl = connect->cl; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%i:%i:%c", i++, *p, *p);
    return NGX_CONF_OK;
}

static char *ngx_pg_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->connect.cl || plcf->upstream.upstream) return "duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pg_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    char *rv;
    if (!(plcf->connect.cl = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if ((rv = ngx_pg_parse_url(cf, cmd, &plcf->connect)) != NGX_CONF_OK) return rv;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "url = %V", &plcf->connect.url);
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &plcf->connect.url, 0))) return NGX_CONF_ERROR;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "naddrs = %i", plcf->connect.url.naddrs);
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    return NGX_CONF_OK;
}

static char *ngx_pg_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;

    ngx_pg_query_t *query;
    if (!plcf->query.nelts && ngx_array_init(&plcf->query, cf->pool, 1, sizeof(*query)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(query = ngx_array_push(&plcf->query))) return "!ngx_array_push";
    ngx_memzero(query, sizeof(*query));

    ngx_buf_t *b;
    ngx_chain_t *cl, *cl_len;
    uint32_t len = 0;

    ngx_str_t *elts = cf->args->elts;

    if (!(cl = query->parse = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'P';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += elts[1].len + sizeof(u_char)))) return "!ngx_create_temp_buf";
    b->last = ngx_copy(b->last, elts[1].data, elts[1].len);
    *b->last++ = (u_char)0;

    if (!(cl = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(uint16_t)))) return "!ngx_create_temp_buf";
    *(uint16_t *)b->last = htons(0);
    b->last += sizeof(uint16_t);

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    len = 0;

    if (!(cl = cl->next = query->bind = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
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

    if (!(cl = cl->next = query->describe = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
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

    if (!(cl = cl->next = query->execute = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
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

    if (!(cl = cl->next = query->close = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
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

    if (!(cl = cl->next = query->sync = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, sizeof(u_char)))) return "!ngx_create_temp_buf";
    *b->last++ = (u_char)'S';

    if (!(cl = cl_len = cl->next = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if (!(cl->buf = b = ngx_create_temp_buf(cf->pool, len += sizeof(len)))) return "!ngx_create_temp_buf";

    *(uint32_t *)cl_len->buf->last = htonl(len);
    cl_len->buf->last += sizeof(len);

    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = query->parse; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%i:%i:%c", i++, *p, *p);

    return NGX_CONF_OK;
}

static char *ngx_pg_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    ngx_pg_connect_t *connect;
    if (!pscf->connect.nelts && ngx_array_init(&pscf->connect, cf->pool, 1, sizeof(*connect)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(connect = ngx_array_push(&pscf->connect))) return "!ngx_array_push";
    ngx_memzero(connect, sizeof(*connect));
    if (!(connect->us = ngx_array_push(uscf->servers))) return "!ngx_array_push";
    ngx_memzero(connect->us, sizeof(*connect->us));
    connect->us->fail_timeout = 10;
    connect->us->max_fails = 1;
    connect->us->weight = 1;
    char *rv;
    if (!(connect->cl = ngx_alloc_chain_link(cf->pool))) return "!ngx_alloc_chain_link";
    if ((rv = ngx_pg_parse_url(cf, cmd, connect)) != NGX_CONF_OK) return rv;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "url = %V", &connect->url.url);
    if (ngx_parse_url(cf->pool, &connect->url) != NGX_OK) return connect->url.err ? connect->url.err : "ngx_parse_url != NGX_OK";
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "naddrs = %i", connect->url.naddrs);
    connect->us->addrs = connect->url.addrs;
    connect->us->naddrs = connect->url.naddrs;
    connect->us->name = connect->url.url;
    return NGX_CONF_OK;
}

static char *ngx_pg_upstream_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->upstream.upstream) return "duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pg_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_str_t *elts = cf->args->elts;
    plcf->connect.url.no_resolve = 1;
    plcf->connect.url.url = elts[1];
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "url = %V", &plcf->connect.url.url);
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &plcf->connect.url, 0))) return NGX_CONF_ERROR;
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "naddrs = %i", plcf->connect.url.naddrs);
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
  { .name = ngx_string("pg_pass_request_body"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_pg_loc_conf_t, upstream.pass_request_body),
    .post = NULL },
  { .name = ngx_string("pg_query"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_pg_query_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
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
