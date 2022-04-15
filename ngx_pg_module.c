#include <ngx_http.h>
#include "pg_fsm.h"

extern ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool) __attribute__((weak));
extern ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool) __attribute__((weak));

ngx_module_t ngx_pg_module;

typedef enum {
    ngx_pg_output_type_csv = 1,
    ngx_pg_output_type_plain,
} ngx_pg_output_type_t;

typedef struct {
    ngx_http_complex_value_t argument;
    ngx_http_complex_value_t type;
} ngx_pg_argument_t;

typedef struct {
    ngx_str_t argument;
    ngx_uint_t type;
} ngx_pg_value_t;

typedef struct {
    ngx_array_t *arguments;
    ngx_array_t *options;
    ngx_http_complex_value_t complex;
    ngx_http_complex_value_t function;
    ngx_http_upstream_conf_t upstream;
    ngx_str_t query;
#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t cache_key;
#endif
    struct {
        ngx_flag_t header;
        ngx_flag_t string;
        ngx_pg_output_type_t type;
        ngx_str_t null;
        u_char delimiter;
        u_char escape;
        u_char quote;
    } out;
} ngx_pg_loc_conf_t;

typedef struct {
    ngx_array_t caches;
} ngx_pg_main_conf_t;

typedef struct {
    ngx_array_t *options;
    ngx_http_upstream_peer_t peer;
    ngx_log_t *log;
} ngx_pg_srv_conf_t;

typedef struct {
    ngx_str_t key;
    ngx_str_t val;
} ngx_pg_error_t;

typedef struct {
    ngx_str_t key;
    ngx_str_t val;
} ngx_pg_option_t;

typedef struct ngx_pg_data_t ngx_pg_data_t;

typedef struct {
    ngx_array_t *options;
    ngx_buf_t buffer;
    ngx_connection_t *connection;
    ngx_pg_data_t *data;
    ngx_uint_t rc;
    pg_command_state_t command;
    pg_fsm_t *fsm;
    pg_ready_for_query_state_t state;
    uint32_t key;
    uint32_t pid;
    struct {
        ngx_event_handler_pt read_handler;
        ngx_event_handler_pt write_handler;
        void *data;
    } keep;
    struct {
        ngx_str_t extra;
        ngx_str_t relname;
        uint32_t pid;
    } notification;
} ngx_pg_save_t;

typedef struct ngx_pg_data_t {
    ngx_array_t *errors;
    ngx_buf_t *shadow;
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_pg_save_t *save;
    ngx_pg_srv_conf_t *conf;
    ngx_str_t error;
    ngx_uint_t busy;
    ngx_uint_t col;
    ngx_uint_t filter;
    ngx_uint_t row;
} ngx_pg_data_t;

static ngx_int_t ngx_pg_output_handler(ngx_http_request_t *r, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%*s", (int)len, data);
    ngx_chain_t *cl;
    ngx_http_upstream_t *u = r->upstream;
    ngx_event_pipe_t *p = u->pipe;
    ngx_pg_data_t *d = u->peer.data;
    if (u->buffering) {
        if (!p->pool) p->pool = r->pool;
        if (!(cl = ngx_chain_get_free_buf(p->pool, &p->free))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
        if (p->in) *p->last_in = cl; else p->in = cl;
        p->last_in = &cl->next;
    } else {
        ngx_chain_t **ll;
        for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
        if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
        *ll = cl;
    }
    ngx_buf_t *b = cl->buf;
    b->flush = 1;
    b->last = data + len;
    b->memory = 1;
    b->pos = data;
    b->tag = p->tag;
    b->temporary = 1;
    if (u->buffering && d->shadow && !d->shadow->shadow) {
        b->last_shadow = 1;
        b->recycled = 1;
        b->shadow = d->shadow;
        d->shadow->shadow = b;
    }
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = u->out_bufs; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%d:%d:%c", i++, *p, *p);
    return NGX_OK;
}

inline static ngx_chain_t *ngx_pg_alloc_size(ngx_pool_t *p, uint32_t *size) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(*size)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (size) *size += sizeof(*size);
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_byte(ngx_pool_t *p, uint32_t *size, size_t len, const uint8_t *data) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, len))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (len) cl->buf->last = ngx_copy(cl->buf->last, data, len);
    if (size) *size += len;
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_int1(ngx_pool_t *p, uint32_t *size, uint8_t c) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(c)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    *cl->buf->last++ = c;
    if (size) *size += sizeof(c);
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_int2(ngx_pool_t *p, uint32_t *size, uint16_t n) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(n)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    for (uint8_t m = sizeof(uint16_t); m; *cl->buf->last++ = n >> (2 << 2) * --m);
    if (size) *size += sizeof(n);
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_int4(ngx_pool_t *p, uint32_t *size, uint32_t n) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(n)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    for (uint8_t m = sizeof(uint32_t); m; *cl->buf->last++ = n >> (2 << 2) * --m);
    if (size) *size += sizeof(n);
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_opt(ngx_pool_t *p, uint32_t *size, size_t len, const uint8_t *data) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, len + sizeof(uint8_t)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    for (ngx_uint_t i = 0; i < len; i++) *cl->buf->last++ = data[i] == '=' ? 0 : data[i];
    *cl->buf->last++ = 0;
    if (size) *size += len + sizeof(uint8_t);
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_size(ngx_chain_t *cl, uint32_t size) {
    for (uint8_t m = sizeof(uint32_t); m; *cl->buf->last++ = size >> (2 << 2) * --m);
    return NULL;
}

inline static ngx_chain_t *ngx_pg_write_str(ngx_pool_t *p, uint32_t *size, size_t len, const uint8_t *data) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, len + sizeof(uint8_t)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (len) cl->buf->last = ngx_copy(cl->buf->last, data, len);
    *cl->buf->last++ = 0;
    if (size) *size += len + sizeof(uint8_t);
    return cl;
}

static int ngx_pg_fsm_all(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d:%c", *data, *data);
    return s->rc;
}

static int ngx_pg_fsm_authentication_ok(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_authentication_ok;
    return s->rc;
}

static int ngx_pg_fsm_backend_key_data(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_authentication_ok;
    return s->rc;
}

static int ngx_pg_fsm_backend_key_data_key(ngx_pg_save_t *s, uint32_t key) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", key);
    s->key = key;
    return s->rc;
}

static int ngx_pg_fsm_backend_key_data_pid(ngx_pg_save_t *s, uint32_t pid) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", pid);
    s->pid = pid;
    return s->rc;
}

static int ngx_pg_fsm_bind_complete(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_bind_complete;
    return s->rc;
}

static int ngx_pg_fsm_close_complete(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_close_complete;
    return s->rc;
}

static int ngx_pg_fsm_command_complete(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_command_complete;
    return s->rc;
}

static int ngx_pg_fsm_command_complete_val(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (plcf->out.type || d->row) return s->rc;
    if ((s->rc = ngx_pg_output_handler(r, len, data)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_copy_data(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_copy_data;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->row++;
    if (!d->filter++) s->rc = NGX_DONE;
    return s->rc;
}

static int ngx_pg_fsm_copy_done(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_copy_done;
    return s->rc;
}

static int ngx_pg_fsm_copy_out_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_copy_out_response;
    return s->rc;
}

static int ngx_pg_fsm_data_row(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_data_row;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->col = 0;
    d->row++;
    ngx_http_request_t *r = d->request;
    if (!d->filter++) s->rc = NGX_DONE;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->out.type) return s->rc;
    if (d->row > 1 || plcf->out.header) if (ngx_pg_output_handler(r, sizeof("\n") - 1, (uint8_t *)"\n") == NGX_ERROR) { s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_data_row_count(ngx_pg_save_t *s, uint16_t count) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", count);
    return s->rc;
}

static int ngx_pg_fsm_empty_query_response(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_empty_query_response;
    return s->rc;
}

static int ngx_pg_fsm_error(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_buf_t *b = &s->buffer;
    ngx_pg_data_t *d = s->data;
    if (d) {
        ngx_http_request_t *r = d->request;
        ngx_http_upstream_t *u = r->upstream;
        b = &u->buffer;
    }
    ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%d:%d:%c", i++, *p, *p);
    s->rc = d->filter ? NGX_ERROR : NGX_HTTP_UPSTREAM_INVALID_HEADER;
    return s->rc;
}

static int ngx_pg_fsm_error_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_error_response;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_error_t *error;
    ngx_http_request_t *r = d->request;
    if (!(d->errors = ngx_array_create(r->pool, 1, sizeof(*error)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_create"); s->rc = NGX_ERROR; return s->rc; }
    ngx_http_upstream_t *u = r->upstream;
    u->headers_in.status_n = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (!(d->error.data = ngx_pnalloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_error_response_key(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_error_t *error;
    if (!d->errors) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!errors"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    if (!(error = ngx_array_push(d->errors))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(error, sizeof(*error));
    error->key.data = data;
    error->key.len = len;
    return s->rc;
}

static int ngx_pg_fsm_error_response_val(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    if (!d->errors->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_pg_error_t *error = d->errors->elts;
    error = &error[d->errors->nelts - 1];
    if (!error->val.data) error->val.data = d->error.data + d->error.len;
    ngx_memcpy(error->val.data + error->val.len, data, len);
    error->val.len += len;
    d->error.len += len;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    if (u->headers_in.status_n == NGX_HTTP_INTERNAL_SERVER_ERROR) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%V = %V", &error->key, &error->val); }
    else { ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0, "%V = %V", &error->key, &error->val); }
    return s->rc;
}

static int ngx_pg_fsm_function_call_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_function_call_response;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->row++;
    if (!d->filter++) s->rc = NGX_DONE;
    return s->rc;
}

static int ngx_pg_fsm_no_data(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_no_data;
    return s->rc;
}

static int ngx_pg_fsm_notice_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_notice_response;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_error_t *error;
    ngx_http_request_t *r = d->request;
    if (!(d->errors = ngx_array_create(r->pool, 1, sizeof(*error)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_create"); s->rc = NGX_ERROR; return s->rc; }
    if (!(d->error.data = ngx_pnalloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_notification_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_notification_response;
    ngx_connection_t *c = s->connection;
    if (!(s->notification.relname.data = ngx_pnalloc(c->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_notification_response_done(ngx_pg_save_t *s) {
    s->notification.extra.data[s->notification.extra.len] = '\0';
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "extra = %V", &s->notification.extra);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "pid = %d", s->notification.pid);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "relname = %V", &s->notification.relname);
    ngx_connection_t *c = s->connection;
    if (!ngx_http_push_stream_add_msg_to_channel_my) goto free;
    ngx_pool_t *p;
    if (!(p = ngx_create_pool(4096 + s->notification.relname.len + s->notification.extra.len, s->connection->log))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_create_pool"); s->rc = NGX_ERROR; goto free; }
    switch ((s->rc = ngx_http_push_stream_add_msg_to_channel_my(s->connection->log, &s->notification.relname, &s->notification.extra, NULL, NULL, 1, p))) {
        case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); break;
        case NGX_DECLINED: ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED"); {
            ngx_chain_t *cl, *cl_size, *out, *last;
            uint32_t size = 0;
            if (!(cl = out = ngx_pg_write_int1(p, NULL, 'Q'))) { s->rc = NGX_ERROR; goto destroy; }
            if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) { s->rc = NGX_ERROR; goto destroy; }
            if (!(cl = cl->next = ngx_pg_write_byte(p, &size, sizeof("UNLISTEN ") - 1, (uint8_t *)"UNLISTEN "))) { s->rc = NGX_ERROR; goto destroy; }
            if (!(cl = cl->next = ngx_pg_write_str(p, &size, s->notification.relname.len, s->notification.relname.data))) { s->rc = NGX_ERROR; goto destroy; }
            cl->next = ngx_pg_write_size(cl_size, size);
            ngx_chain_writer_ctx_t ctx = { .out = out, .last = &last, .connection = c, .pool = p, .limit = 0 };
            ngx_chain_writer(&ctx, NULL);
        } break;
        case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DONE"); break;
        case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_OK"); break;
        default: ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == %i", s->rc); break;
    }
    s->rc = NGX_OK;
destroy:
    ngx_destroy_pool(p);
free:
    ngx_pfree(c->pool, s->notification.relname.data);
    ngx_str_null(&s->notification.extra);
    ngx_str_null(&s->notification.relname);
    return s->rc;
}

static int ngx_pg_fsm_notification_response_extra(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    if (!s->notification.extra.data) {
        s->notification.extra.data = s->notification.relname.data + s->notification.relname.len + 1;
        s->notification.relname.data[s->notification.relname.len] = '\0';
    }
    ngx_memcpy(s->notification.extra.data + s->notification.extra.len, data, len);
    s->notification.extra.len += len;
    return s->rc;
}

static int ngx_pg_fsm_notification_response_pid(ngx_pg_save_t *s, uint32_t pid) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", pid);
    s->notification.pid = pid;
    return s->rc;
}

static int ngx_pg_fsm_notification_response_relname(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_memcpy(s->notification.relname.data + s->notification.relname.len, data, len);
    s->notification.relname.len += len;
    return s->rc;
}

static int ngx_pg_fsm_parameter_status(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_parameter_status;
    ngx_pg_option_t *option;
    if (!(option = ngx_array_push(s->options))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(option, sizeof(*option));
    ngx_connection_t *c = s->connection;
    if (!(option->key.data = ngx_pnalloc(c->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_parameter_status_key(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    if (!s->options->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_pg_option_t *option = s->options->elts;
    option = &option[s->options->nelts - 1];
    ngx_memcpy(option->key.data + option->key.len, data, len);
    option->key.len += len;
    return s->rc;
}

static int ngx_pg_fsm_parameter_status_val(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    if (!s->options->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_pg_option_t *option = s->options->elts;
    option = &option[s->options->nelts - 1];
    if (!option->val.data) option->val.data = option->key.data + option->key.len;
    ngx_memcpy(option->val.data + option->val.len, data, len);
    option->val.len += len;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%V = %V", &option->key, &option->val);
    return s->rc;
}

static int ngx_pg_fsm_parse_complete(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_parse_complete;
    return s->rc;
}

static int ngx_pg_fsm_ready_for_query(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->command = pg_command_state_ready_for_query;
    return s->rc;
}

static int ngx_pg_fsm_ready_for_query_state(ngx_pg_save_t *s, uint16_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", state);
    s->state = state;
    ngx_pg_data_t *d = s->data;
    if (d && d->busy) d->busy--;
    return s->rc;
}

static int ngx_pg_fsm_result_done(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->out.type) return s->rc;
    if (plcf->out.string && plcf->out.quote) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.quote), &plcf->out.quote)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_result_len(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->col++;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d:%d", d->col, d->row);
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->out.type) return s->rc;
    if (d->col > 1) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.delimiter), &plcf->out.delimiter)) != NGX_OK) return s->rc;
    if (len == (uint32_t)-1) {
        if (plcf->out.null.len) if ((s->rc = ngx_pg_output_handler(r, plcf->out.null.len, plcf->out.null.data)) != NGX_OK) return s->rc;
    } else {
        if (plcf->out.string && plcf->out.quote) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.quote), &plcf->out.quote)) != NGX_OK) return s->rc;
    }
    return s->rc;
}

static int ngx_pg_fsm_result_val(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d:%d", d->col, d->row);
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (plcf->out.type && plcf->out.string && plcf->out.quote && plcf->out.escape) for (ngx_uint_t k = 0; k < len; k++) {
        if (data[k] == plcf->out.quote) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.escape), &plcf->out.escape)) != NGX_OK) return s->rc;
        if ((s->rc = ngx_pg_output_handler(r, sizeof(data[k]), &data[k])) != NGX_OK) return s->rc;
    } else if ((s->rc = ngx_pg_output_handler(r, len, data)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_row_description(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", len);
    s->command = pg_command_state_row_description;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->col = 0;
    d->row = 0;
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->out.type || !plcf->out.header) return s->rc;
    if (!d->filter++) s->rc = NGX_DONE;
    return s->rc;
}

static int ngx_pg_fsm_row_description_beg(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->col++;
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->out.type || !plcf->out.header) return s->rc;
    if (d->col > 1) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.delimiter), &plcf->out.delimiter)) != NGX_OK) return s->rc;
    if (plcf->out.string && plcf->out.quote) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.quote), &plcf->out.quote)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_row_description_column(ngx_pg_save_t *s, uint16_t column) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", column);
    return s->rc;
}

static int ngx_pg_fsm_row_description_count(ngx_pg_save_t *s, uint16_t count) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", count);
    return s->rc;
}

static int ngx_pg_fsm_row_description_format(ngx_pg_save_t *s, uint16_t format) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", format);
    return s->rc;
}

static int ngx_pg_fsm_row_description_length(ngx_pg_save_t *s, uint16_t length) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", length == (uint16_t)-1 ? -1 : length);
    return s->rc;
}

static int ngx_pg_fsm_row_description_mod(ngx_pg_save_t *s, uint32_t mod) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", mod);
    return s->rc;
}

static int ngx_pg_fsm_row_description_name(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", d->col);
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->out.type || !plcf->out.header) return s->rc;
    if (plcf->out.string && plcf->out.quote && plcf->out.escape) for (ngx_uint_t k = 0; k < len; k++) {
        if (data[k] == plcf->out.quote) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.escape), &plcf->out.escape)) != NGX_OK) return s->rc;
        if ((s->rc = ngx_pg_output_handler(r, sizeof(data[k]), &data[k])) != NGX_OK) return s->rc;
    } else if ((s->rc = ngx_pg_output_handler(r, len, data)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_row_description_oid(ngx_pg_save_t *s, uint32_t oid) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", oid);
    return s->rc;
}

static int ngx_pg_fsm_row_description_table(ngx_pg_save_t *s, uint32_t table) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", table);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (!plcf->out.type) return s->rc;
    if (plcf->out.string && plcf->out.quote) if ((s->rc = ngx_pg_output_handler(r, sizeof(plcf->out.quote), &plcf->out.quote)) != NGX_OK) return s->rc;
    return s->rc;
}

static const pg_fsm_cb_t ngx_pg_fsm_cb = {
    .all = (pg_fsm_str_cb)ngx_pg_fsm_all,
    .authentication_ok = (pg_fsm_cb)ngx_pg_fsm_authentication_ok,
    .backend_key_data_key = (pg_fsm_int4_cb)ngx_pg_fsm_backend_key_data_key,
    .backend_key_data = (pg_fsm_cb)ngx_pg_fsm_backend_key_data,
    .backend_key_data_pid = (pg_fsm_int4_cb)ngx_pg_fsm_backend_key_data_pid,
    .bind_complete = (pg_fsm_cb)ngx_pg_fsm_bind_complete,
    .close_complete = (pg_fsm_cb)ngx_pg_fsm_close_complete,
    .command_complete = (pg_fsm_int4_cb)ngx_pg_fsm_command_complete,
    .command_complete_val = (pg_fsm_str_cb)ngx_pg_fsm_command_complete_val,
    .copy_data = (pg_fsm_int4_cb)ngx_pg_fsm_copy_data,
    .copy_done = (pg_fsm_cb)ngx_pg_fsm_copy_done,
    .copy_out_response = (pg_fsm_int4_cb)ngx_pg_fsm_copy_out_response,
    .data_row_count = (pg_fsm_int2_cb)ngx_pg_fsm_data_row_count,
    .data_row = (pg_fsm_int4_cb)ngx_pg_fsm_data_row,
    .empty_query_response = (pg_fsm_cb)ngx_pg_fsm_empty_query_response,
    .error = (pg_fsm_cb)ngx_pg_fsm_error,
    .error_response_key = (pg_fsm_str_cb)ngx_pg_fsm_error_response_key,
    .error_response = (pg_fsm_int4_cb)ngx_pg_fsm_error_response,
    .error_response_val = (pg_fsm_str_cb)ngx_pg_fsm_error_response_val,
    .function_call_response = (pg_fsm_int4_cb)ngx_pg_fsm_function_call_response,
    .no_data = (pg_fsm_cb)ngx_pg_fsm_no_data,
    .notice_response = (pg_fsm_int4_cb)ngx_pg_fsm_notice_response,
    .notification_response_done = (pg_fsm_cb)ngx_pg_fsm_notification_response_done,
    .notification_response_extra = (pg_fsm_str_cb)ngx_pg_fsm_notification_response_extra,
    .notification_response = (pg_fsm_int4_cb)ngx_pg_fsm_notification_response,
    .notification_response_pid = (pg_fsm_int4_cb)ngx_pg_fsm_notification_response_pid,
    .notification_response_relname = (pg_fsm_str_cb)ngx_pg_fsm_notification_response_relname,
    .parameter_status_key = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_key,
    .parameter_status = (pg_fsm_int4_cb)ngx_pg_fsm_parameter_status,
    .parameter_status_val = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_val,
    .parse_complete = (pg_fsm_cb)ngx_pg_fsm_parse_complete,
    .ready_for_query = (pg_fsm_cb)ngx_pg_fsm_ready_for_query,
    .ready_for_query_state = (pg_fsm_int2_cb)ngx_pg_fsm_ready_for_query_state,
    .result_done = (pg_fsm_cb)ngx_pg_fsm_result_done,
    .result_len = (pg_fsm_int4_cb)ngx_pg_fsm_result_len,
    .result_val = (pg_fsm_str_cb)ngx_pg_fsm_result_val,
    .row_description_beg = (pg_fsm_cb)ngx_pg_fsm_row_description_beg,
    .row_description_column = (pg_fsm_int2_cb)ngx_pg_fsm_row_description_column,
    .row_description_count = (pg_fsm_int2_cb)ngx_pg_fsm_row_description_count,
    .row_description_format = (pg_fsm_int2_cb)ngx_pg_fsm_row_description_format,
    .row_description_length = (pg_fsm_int2_cb)ngx_pg_fsm_row_description_length,
    .row_description_mod = (pg_fsm_int4_cb)ngx_pg_fsm_row_description_mod,
    .row_description_name = (pg_fsm_str_cb)ngx_pg_fsm_row_description_name,
    .row_description_oid = (pg_fsm_int4_cb)ngx_pg_fsm_row_description_oid,
    .row_description = (pg_fsm_int4_cb)ngx_pg_fsm_row_description,
    .row_description_table = (pg_fsm_int4_cb)ngx_pg_fsm_row_description_table,
};

inline static ngx_chain_t *ngx_pg_bind(ngx_pool_t *p, ngx_array_t *arguments) {
    ngx_chain_t *cl, *cl_size, *bind;
    uint32_t size = 0;
    if (!(cl = bind = ngx_pg_write_int1(p, NULL, 'B'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (uint8_t *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (uint8_t *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, arguments->nelts))) return NULL;
    ngx_pg_value_t *value = arguments->elts;
    for (ngx_uint_t i = 0; i < arguments->nelts; i++) {
        if (value[i].argument.data) {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, value[i].argument.len))) return NULL;
            if (!(cl = cl->next = ngx_pg_write_byte(p, &size, value[i].argument.len, value[i].argument.data))) return NULL;
        } else {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, -1))) return NULL;
        }
    }
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = bind; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return bind;
}

inline static ngx_chain_t *ngx_pg_cancel_request(ngx_pool_t *p, uint32_t pid, uint32_t key) {
    ngx_chain_t *cl, *cl_size, *cancel;
    uint32_t size = 0;
    if (!(cl = cl_size = cancel = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, 80877102))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, pid))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, key))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = cancel; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return cancel;
}

inline static ngx_chain_t *ngx_pg_close(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *close;
    uint32_t size = 0;
    if (!(cl = close = ngx_pg_write_int1(p, NULL, 'C'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (uint8_t *)""))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = close; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return close;
}

inline static ngx_chain_t *ngx_pg_startup_message(ngx_pool_t *p, ngx_array_t *options) {
    ngx_chain_t *cl, *cl_size, *connect;
    uint32_t size = 0;
    if (!(cl = cl_size = connect = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, 0x00030000))) return NULL;
    if (options) {
        ngx_str_t *str = options->elts;
        for (ngx_uint_t i = 0; i < options->nelts; i++) if (!(cl = cl->next = ngx_pg_write_opt(p, &size, str[i].len, str[i].data))) return NULL;
    }
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = *connect; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%d:%d:%c", i++, *p, *p);
    return connect;
}

inline static ngx_chain_t *ngx_pg_describe(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *describe;
    uint32_t size = 0;
    if (!(cl = describe = ngx_pg_write_int1(p, NULL, 'D'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (uint8_t *)""))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = describe; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return describe;
}

inline static ngx_chain_t *ngx_pg_execute(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *execute;
    uint32_t size = 0;
    if (!(cl = execute = ngx_pg_write_int1(p, NULL, 'E'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (uint8_t *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = execute; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return execute;
}

inline static ngx_chain_t *ngx_pg_terminate(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *exit;
    uint32_t size = 0;
    if (!(cl = exit = ngx_pg_write_int1(p, NULL, 'X'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = exit; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return exit;
}

inline static ngx_chain_t *ngx_pg_flush(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *flush;
    uint32_t size = 0;
    if (!(cl = flush = ngx_pg_write_int1(p, NULL, 'H'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = flush; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return flush;
}

inline static ngx_chain_t *ngx_pg_function_call(ngx_pool_t *p, uint32_t oid, ngx_array_t *arguments) {
    ngx_chain_t *cl, *cl_size, *function;
    uint32_t size = 0;
    if (!(cl = function = ngx_pg_write_int1(p, NULL, 'F'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, oid))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 1))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, arguments->nelts))) return NULL;
    ngx_pg_value_t *value = arguments->elts;
    for (ngx_uint_t i = 0; i < arguments->nelts; i++) {
        if (value[i].argument.data) {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, value[i].argument.len))) return NULL;
            if (!(cl = cl->next = ngx_pg_write_byte(p, &size, value[i].argument.len, value[i].argument.data))) return NULL;
        } else {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, -1))) return NULL;
        }
    }
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = function; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return function;
}

inline static ngx_chain_t *ngx_pg_parse(ngx_pool_t *p, size_t len, const uint8_t *data, ngx_array_t *arguments) {
    ngx_chain_t *cl, *cl_size, *parse;
    uint32_t size = 0;
    if (!(cl = parse = ngx_pg_write_int1(p, NULL, 'P'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (uint8_t *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, data))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, arguments->nelts))) return NULL;
    ngx_pg_value_t *value = arguments->elts;
    for (ngx_uint_t i = 0; i < arguments->nelts; i++) if (!(cl = cl->next = ngx_pg_write_int4(p, &size, value[i].type))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = parse; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return parse;
}

inline static ngx_chain_t *ngx_pg_query(ngx_pool_t *p, size_t len, const uint8_t *data) {
    ngx_chain_t *cl, *cl_size, *query;
    uint32_t size = 0;
    if (!(cl = query = ngx_pg_write_int1(p, NULL, 'Q'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, data))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = query; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return query;
}

inline static ngx_chain_t *ngx_pg_sync(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *sync;
    uint32_t size = 0;
    if (!(cl = sync = ngx_pg_write_int1(p, NULL, 'S'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = sync; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%d:%d:%c", i++, *c, *c);
    return sync;
}

static void ngx_pg_save_cln_handler(ngx_pg_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_chain_t *out, *last;
    if (!(out = ngx_pg_terminate(c->pool))) return;
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
        default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %d", rc); return rc;
    }
    ngx_pg_save_t *s;
    if (pc->connection) s = d->save = (ngx_pg_save_t *)((char *)pc->connection->pool + sizeof(*pc->connection->pool)); else {
        pc->get = ngx_event_get_peer;
        switch ((rc = ngx_event_connect_peer(pc))) {
            case NGX_AGAIN: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_AGAIN"); break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_DONE"); break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_OK"); break;
            default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %d", rc); return rc;
        }
        pc->get = ngx_pg_peer_get;
        ngx_connection_t *c = pc->connection;
        if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!c"); return NGX_ERROR; }
        if (c->pool) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "c->pool"); return NGX_ERROR; }
        if (!(c->pool = ngx_create_pool(sizeof(*c->pool) + sizeof(*s), pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); return NGX_ERROR; }
        if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        if ((char *)s != (char *)c->pool + sizeof(*c->pool)) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "wrong pool"); return NGX_ERROR; }
        ngx_pool_cleanup_t *cln;
        if (!(cln = ngx_pool_cleanup_add(c->pool, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
        cln->data = s;
        cln->handler = (ngx_pool_cleanup_pt)ngx_pg_save_cln_handler;
        if (!(s->options = ngx_array_create(c->pool, 1, sizeof(ngx_pg_option_t)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_array_create"); return NGX_ERROR; }
        if (!(s->fsm = ngx_pcalloc(c->pool, pg_fsm_size()))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        pg_fsm_init(s->fsm);
        s->connection = c;
        ngx_chain_t *cl, *connect;
        ngx_http_request_t *r = d->request;
        ngx_http_upstream_t *u = r->upstream;
        ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
        ngx_pg_srv_conf_t *pscf = d->conf;
        if (!(cl = connect = ngx_pg_startup_message(r->pool, pscf ? pscf->options : plcf->options))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
//        if (!(cl->next = ngx_pg_flush(r->pool))) return NGX_ERROR;
//        while (cl->next) cl = cl->next;
        cl->next = u->request_bufs;
        u->request_bufs = connect;
        d->busy++;
    }
    d->busy++;
    s->data = d;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = u->request_bufs; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%d:%d:%c", i++, *p, *p);
    return NGX_DONE;
}

static ngx_int_t ngx_pg_process(ngx_pg_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_buf_t *b = &s->buffer;
    ssize_t n;
    for ( ;; ) {
        switch ((n = c->recv(c, b->last, b->end - b->last))) {
            case 0: ngx_log_error(NGX_LOG_ERR, c->log, 0, "upstream prematurely closed connection"); return NGX_ERROR;
            case NGX_AGAIN: if (ngx_handle_read_event(c->read, 0) != NGX_OK) return NGX_ERROR; return NGX_OK;
            case NGX_ERROR: return NGX_ERROR;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "n = %d", n);
        b->last += n;
//        ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "%d:%d:%c", i++, *p, *p);
        s->rc = NGX_OK;
        while (b->pos < b->last && s->rc == NGX_OK) b->pos += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->pos, b->last, b->end);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "s->rc = %d", s->rc);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "b->pos == b->last = %s", b->pos == b->last ? "true" : "false");
        if ((ngx_int_t)s->rc == NGX_AGAIN) {
            if (b->last == b->end) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "upstream sent too big header"); return NGX_ERROR; }
            continue;
        }
        break;
    }
    return s->rc;
}

static void ngx_pg_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_pg_save_t *s = c->data;
    if (!ev->timedout && ngx_pg_process(s) == NGX_OK) return;
    c->data = s->keep.data;
    s->keep.read_handler(ev);
    if (c->data == s->keep.data) c->data = s;
}

static void ngx_pg_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_pg_save_t *s = c->data;
    c->data = s->keep.data;
    s->keep.write_handler(ev);
    if (c->data == s->keep.data) c->data = s;
}

static void ngx_pg_cancel_request_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
/*    ngx_connection_t *c = ev->data;
    if (c->close || c->read->timedout) goto close;
    char buf[1];
    int n = recv(c->fd, buf, 1, MSG_PEEK);
    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) goto close;
        return;
    }
close:
    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);*/
}

static void ngx_pg_cancel_request_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_chain_t *out, *last;
    ngx_connection_t *c = ev->data;
    ngx_pg_save_t *s = c->data;
    if (!(out = ngx_pg_cancel_request(c->pool, s->pid, s->key))) return;
    ngx_chain_writer_ctx_t ctx = { .out = out, .last = &last, .connection = c, .pool = c->pool, .limit = 0 };
    ngx_chain_writer(&ctx, NULL);
    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}

static void ngx_pg_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %d", state);
    ngx_pg_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    ngx_pg_save_t *s = d->save;
    d->save = NULL;
    s->data = NULL;
    if (d->busy) {
        ngx_int_t rc;
        ngx_peer_connection_t *pc_;
        if (!(pc_ = ngx_pcalloc(s->connection->pool, sizeof(*pc_)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return; }
        pc_->get = ngx_event_get_peer;
        pc_->log = pc->log;
        pc_->name = pc->name;
        pc_->sockaddr = pc->sockaddr;
        pc_->socklen = pc->socklen;
        switch ((rc = ngx_event_connect_peer(pc_))) {
            case NGX_AGAIN: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_AGAIN"); break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_DONE"); break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_OK"); break;
            default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %d", rc); return;
        }
        ngx_connection_t *c = pc_->connection;
        if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!c"); return; }
        if (c->pool) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "c->pool"); return; }
        if (!(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); return; }
        c->data = s;
        c->read->handler = ngx_pg_cancel_request_read_handler;
        c->write->handler = ngx_pg_cancel_request_write_handler;
        if (rc == NGX_AGAIN) {
            ngx_http_request_t *r = d->request;
            ngx_http_upstream_t *u = r->upstream;
            ngx_add_timer(c->write, u->conf->connect_timeout);
        }
        if (rc == NGX_OK) ngx_pg_cancel_request_write_handler(c->write);
    }
    if (pc->connection) return;
    ngx_pg_srv_conf_t *pscf = d->conf;
    if (!pscf) return;
    s->command = pg_command_state_unknown;
    if (!s->buffer.start) {
        ngx_connection_t *c = s->connection;
        ngx_http_request_t *r = d->request;
        ngx_http_upstream_t *u = r->upstream;
        if (!(s->buffer.start = ngx_palloc(c->pool, u->conf->buffer_size))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_palloc"); return; }
        s->buffer.end = s->buffer.start + u->conf->buffer_size;
        s->buffer.tag = u->output.tag;
        s->buffer.temporary = 1;
    }
    s->buffer.last = s->buffer.start;
    s->buffer.pos = s->buffer.start;
    ngx_connection_t *c = s->connection;
    s->keep.data = c->data;
    s->keep.read_handler = c->read->handler;
    s->keep.write_handler = c->write->handler;
    c->data = s;
    c->read->handler = ngx_pg_read_handler;
    c->write->handler = ngx_pg_write_handler;
    if (!pscf->log) return;
    c->log = pscf->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;
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
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (plcf->complex.value.data) {
        ngx_str_t host;
        if (ngx_http_complex_value(r, &plcf->complex, &host) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
        if (!host.len) { ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty \"pg_pass\" (was: \"%V\") in location \"%V\"", &plcf->complex.value, &clcf->name); return NGX_ERROR; }
        if (!(u->resolved = ngx_pcalloc(r->pool, sizeof(*u->resolved)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        u->resolved->host = host;
        u->resolved->no_port = 1;
    }
    u->headers_in.status_n = NGX_HTTP_OK;
    u->keepalive = !u->headers_in.connection_close;
    switch (plcf->out.type) {
        case ngx_pg_output_type_csv: ngx_str_set(&r->headers_out.content_type, "text/csv"); break;
        case ngx_pg_output_type_plain: ngx_str_set(&r->headers_out.content_type, "text/plain"); break;
    }
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    ngx_chain_t *cl;
    ngx_array_t arguments = {0};
    if (plcf->arguments) {
        ngx_pg_value_t *value;
        if (ngx_array_init(&arguments, r->pool, plcf->arguments->nelts, sizeof(*value)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        ngx_pg_argument_t *argument = plcf->arguments->elts;
        for (ngx_uint_t i = 0; i < plcf->arguments->nelts; i++) {
            if (!(value = ngx_array_push(&arguments))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
            ngx_memzero(value, sizeof(*value));
            if (argument[i].type.value.data) {
                ngx_str_t str;
                if (ngx_http_complex_value(r, &argument[i].type, &str) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
                value->type = n;
            }
            if (argument[i].argument.value.data) if (ngx_http_complex_value(r, &argument[i].argument, &value->argument) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
        }
    }
    if (plcf->function.value.data) {
        ngx_str_t value;
        if (ngx_http_complex_value(r, &plcf->function, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
        ngx_int_t oid = ngx_atoi(value.data, value.len);
        if (oid == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
        if (!(cl = u->request_bufs = ngx_pg_function_call(r->pool, oid, &arguments))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
    } else if (plcf->query.data) {
        if (!(cl = u->request_bufs = ngx_pg_parse(r->pool, plcf->query.len, plcf->query.data, &arguments))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
        if (!(cl->next = ngx_pg_bind(r->pool, &arguments))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
        if (!(cl->next = ngx_pg_describe(r->pool))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
        if (!(cl->next = ngx_pg_execute(r->pool))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
        if (!(cl->next = ngx_pg_close(r->pool))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
        if (!(cl->next = ngx_pg_sync(r->pool))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
    } else { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!pg_function && !pg_query"); return NGX_ERROR; }
//    if (!(cl->next = ngx_pg_flush(r->pool))) return NGX_ERROR;
//    while (cl->next) cl = cl->next;
    return NGX_OK;
}

static void ngx_pg_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %d", rc);
}

static ngx_int_t ngx_pg_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_buf_t *b = &u->buffer;
//    ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%d:%d:%c", i++, *p, *p);
    if (r->cached) {
        u->headers_in.status_n = NGX_HTTP_OK;
        u->keepalive = !u->headers_in.connection_close;
        return NGX_OK;
    }
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!s) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!s"); return NGX_ERROR; }
    s->rc = NGX_OK;
    while (b->pos < b->last && s->rc == NGX_OK) b->pos += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->pos, b->last, b->end);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %d", s->rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos == b->last = %s", b->pos == b->last ? "true" : "false");
    if (s->rc == NGX_OK) {
        char buf[1];
        ngx_connection_t *c = s->connection;
        s->rc = d->busy || s->state == pg_ready_for_query_state_unknown || recv(c->fd, buf, 1, MSG_PEEK) > 0 ? NGX_AGAIN : NGX_OK;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %d", s->rc);
    if (s->rc == NGX_OK && u->headers_in.status_n == NGX_HTTP_INTERNAL_SERVER_ERROR && d->errors && d->errors->nelts) s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
    return s->rc;
}

static ngx_int_t ngx_pg_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    r->state = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_pipe_input_filter(ngx_event_pipe_t *p, ngx_buf_t *b) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, p->log, 0, "%s", __func__);
    ngx_http_request_t *r = p->input_ctx;
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    s->rc = NGX_OK;
    d->shadow = b;
    while (b->pos < b->last && s->rc == NGX_OK) b->pos += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->pos, b->last, b->end);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, p->log, 0, "s->rc = %d", s->rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos == b->last = %s", b->pos == b->last ? "true" : "false");
    if (!d->busy && s->state != pg_ready_for_query_state_unknown) p->length = 0;
    return s->rc;
}

static ngx_int_t ngx_pg_input_filter_init(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_event_pipe_t *p = u->pipe;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!d->busy && s->state != pg_ready_for_query_state_unknown) {
        u->length = 0;
        p->length = 0;
    } else p->length = 1;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = u->out_bufs; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%d:%d:%c", i++, *p, *p);
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter(ngx_http_request_t *r, ssize_t bytes) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bytes = %d", bytes);
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    ngx_buf_t *b = &u->buffer;
    u_char *last = b->last + bytes;
    s->rc = NGX_OK;
    while (b->last < last && s->rc == NGX_OK) b->last += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->last, last, b->end);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %d", s->rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos == b->last = %s", b->pos == b->last ? "true" : "false");
    if (!d->busy && s->state != pg_ready_for_query_state_unknown) u->length = 0;
    return s->rc;
}

#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_pg_create_key(ngx_http_request_t *r) {
    ngx_str_t *key;
    if (!(key = ngx_array_push(&r->cache->keys))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    if (ngx_http_complex_value(r, &plcf->cache_key, key) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    return NGX_OK;
}
#endif

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
#if (NGX_HTTP_CACHE)
    ngx_pg_main_conf_t *pmcf = ngx_http_get_module_main_conf(r, ngx_pg_module);
    u->caches = &pmcf->caches;
    u->create_key = ngx_pg_create_key;
#endif
    u->abort_request = ngx_pg_abort_request;
    u->create_request = ngx_pg_create_request;
    u->finalize_request = ngx_pg_finalize_request;
    u->process_header = ngx_pg_process_header;
    u->reinit_request = ngx_pg_reinit_request;
    r->state = 0;
    u->buffering = u->conf->buffering;
    if (!(u->pipe = ngx_pcalloc(r->pool, sizeof(*u->pipe)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u->pipe->input_ctx = r;
    u->pipe->input_filter = ngx_pg_pipe_input_filter;
    u->input_filter_init = (ngx_int_t (*)(void *data))ngx_pg_input_filter_init;
    u->input_filter = (ngx_int_t (*)(void *data, ssize_t bytes))ngx_pg_input_filter;
    u->input_filter_ctx = r;
    if (!u->conf->request_buffering && u->conf->pass_request_body && !r->headers_in.chunked) r->request_body_no_buffering = 1;
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
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    ngx_str_set(&conf->upstream.module, "pg");
#if (NGX_HTTP_CACHE)
    conf->upstream.cache_background_update = NGX_CONF_UNSET;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_lock = NGX_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache = NGX_CONF_UNSET;
    conf->upstream.cache_revalidate = NGX_CONF_UNSET;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
#endif
    return conf;
}

static ngx_path_init_t ngx_pg_temp_path = {
    ngx_string("/var/tmp/nginx/pg_temp"), { 1, 2, 0 }
};

static char *ngx_pg_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_pg_loc_conf_t *prev = parent;
    ngx_pg_loc_conf_t *conf = child;
#if (NGX_HTTP_CACHE)
    if (conf->upstream.store > 0) conf->upstream.cache = 0;
    if (conf->upstream.cache > 0) conf->upstream.store = 0;
#endif
    if (!conf->upstream.upstream) conf->upstream = prev->upstream;
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_ERROR|NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs, 8, ngx_pagesize);
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);
    ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t)ngx_pagesize);
    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf, prev->upstream.busy_buffers_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering, 1);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);
    ngx_conf_merge_value(conf->upstream.request_buffering, prev->upstream.request_buffering, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body, prev->upstream.pass_request_body, 0);
    ngx_conf_merge_value(conf->upstream.socket_keepalive, prev->upstream.socket_keepalive, 0);
    if (conf->upstream.bufs.num < 2) return "there must be at least 2 \"pg_buffers\"";
    size_t size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) size = conf->upstream.bufs.size;
    conf->upstream.busy_buffers_size = conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE ? 2 * size : conf->upstream.busy_buffers_size_conf;
    if (conf->upstream.busy_buffers_size < size) return "\"pg_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
    if (conf->upstream.busy_buffers_size > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) return "\"pg_busy_buffers_size\" must be less than the size of all \"pg_buffers\" minus one buffer";
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path, prev->upstream.temp_path, &ngx_pg_temp_path) != NGX_OK) return NGX_CONF_ERROR;
#if (NGX_HTTP_CACHE)
    if (conf->upstream.cache == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.cache, prev->upstream.cache, 0);
        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }
    if (conf->upstream.cache_zone && !conf->upstream.cache_zone->data) { ngx_shm_zone_t *shm_zone = conf->upstream.cache_zone; ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"pg_cache\" zone \"%V\" is unknown", &shm_zone->shm.name); return NGX_CONF_ERROR; }
    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses, prev->upstream.cache_min_uses, 1);
    ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset, prev->upstream.cache_max_range_offset, NGX_MAX_OFF_T_VALUE);
    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale, prev->upstream.cache_use_stale, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF);
    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
    if (!conf->upstream.cache_methods) conf->upstream.cache_methods = prev->upstream.cache_methods;
    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;
    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass, prev->upstream.cache_bypass, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.no_cache, prev->upstream.no_cache, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.cache_valid, prev->upstream.cache_valid, NULL);
    if (!conf->cache_key.value.data) conf->cache_key = prev->cache_key;
    if (conf->upstream.cache && !conf->cache_key.value.data) return "no \"pg_cache_key\" for \"pg_cache\"";
    ngx_conf_merge_value(conf->upstream.cache_lock, prev->upstream.cache_lock, 0);
    ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout, prev->upstream.cache_lock_timeout, 5000);
    ngx_conf_merge_msec_value(conf->upstream.cache_lock_age, prev->upstream.cache_lock_age, 5000);
    ngx_conf_merge_value(conf->upstream.cache_revalidate, prev->upstream.cache_revalidate, 0);
    ngx_conf_merge_value(conf->upstream.cache_background_update, prev->upstream.cache_background_update, 0);
#endif
    return NGX_CONF_OK;
}

static ngx_int_t ngx_pg_error_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) return NGX_OK;
    ngx_pg_data_t *d = u->peer.data;
    if (!d->errors) return NGX_OK;
    ngx_pg_error_t *error = d->errors->elts;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_uint_t i;
    for (i = 0; i < d->errors->nelts; i++) if (name->len - sizeof("pg_error_") + 1 == error[i].key.len && !ngx_strncasecmp(name->data + sizeof("pg_error_") - 1, error[i].key.data, error[i].key.len)) break;
    if (i == d->errors->nelts) return NGX_OK;
    v->data = error[i].val.data;
    v->len = error[i].val.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_option_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) return NGX_OK;
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!s) return NGX_OK;
    if (!s->options) return NGX_OK;
    ngx_pg_option_t *option = s->options->elts;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_uint_t i;
    for (i = 0; i < s->options->nelts; i++) if (name->len - sizeof("pg_option_") + 1 == option[i].key.len && !ngx_strncasecmp(name->data + sizeof("pg_option_") - 1, option[i].key.data, option[i].key.len)) break;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", i == s->options->nelts ? "true" : "false");
    if (i == s->options->nelts) return NGX_OK;
    v->data = option[i].val.data;
    v->len = option[i].val.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_pid_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) return NGX_OK;
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!s) return NGX_OK;
    v->len = snprintf(NULL, 0, "%d", s->pid);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%d", s->pid) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static const ngx_http_variable_t ngx_pg_variables[] = {
  { ngx_string("pg_error_"), NULL, ngx_pg_error_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_option_"), NULL, ngx_pg_option_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_pid"), NULL, ngx_pg_pid_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },
    ngx_http_null_variable
};

static ngx_int_t ngx_pg_preconfiguration(ngx_conf_t *cf) {
    ngx_http_variable_t *var;
    for (ngx_http_variable_t *v = ngx_pg_variables; v->name.len; v++) {
        if (!(var = ngx_http_add_variable(cf, &v->name, v->flags))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_http_add_variable"); return NGX_ERROR; }
        *var = *v;
    }
    return NGX_OK;
}

static void *ngx_pg_create_main_conf(ngx_conf_t *cf) {
    ngx_pg_main_conf_t *conf;
    if (!(conf = ngx_pcalloc(cf->pool, sizeof(*conf)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
#if (NGX_HTTP_CACHE)
    if (ngx_array_init(&conf->caches, cf->pool, 1, sizeof(ngx_http_file_cache_t *)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_array_init != NGX_OK"); return NULL; }
#endif
    return conf;
}

static ngx_http_module_t ngx_pg_ctx = {
    .preconfiguration = ngx_pg_preconfiguration,
    .postconfiguration = NULL,
    .create_main_conf = ngx_pg_create_main_conf,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_pg_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_pg_create_loc_conf,
    .merge_loc_conf = ngx_pg_merge_loc_conf
};

static ngx_int_t ngx_pg_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
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

static char *ngx_pg_argument_output_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    ngx_str_t *str = cf->args->elts;
    plcf->out.header = 1;
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (str[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            if (!(str[i].len - (sizeof("delimiter=") - 1))) return "empty \"delimiter\" value";
            if (str[i].len - (sizeof("delimiter=") - 1) > 1) return "\"delimiter\" value must be one character";
            plcf->out.delimiter = str[i].data[sizeof("delimiter=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            if (!(str[i].len - (sizeof("escape=") - 1))) { plcf->out.escape = '\0'; continue; }
            else if (str[i].len > 1) return "\"escape\" value must be one character";
            plcf->out.escape = str[i].data[sizeof("escape=") - 1];
            continue;
        }
        if (str[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("header=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("header=") - 1], str[i].len - (sizeof("header=") - 1))) break;
            if (!e[j].name.len) return "\"header\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            plcf->out.header = e[j].value;
            continue;
        }
        if (str[i].len > sizeof("output=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"output=", sizeof("output=") - 1)) {
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("csv"), ngx_pg_output_type_csv }, { ngx_string("plain"), ngx_pg_output_type_plain }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("output=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("output=") - 1], str[i].len - (sizeof("output=") - 1))) break;
            if (!e[j].name.len) return "\"output\" value must be \"csv\" or \"plain\"";
            switch ((plcf->out.type = e[j].value)) {
                case ngx_pg_output_type_csv: {
                    ngx_str_set(&plcf->out.null, "");
                    plcf->out.delimiter = ',';
                    plcf->out.escape = '"';
                    plcf->out.quote = '"';
                } break;
                case ngx_pg_output_type_plain: {
                    ngx_str_set(&plcf->out.null, "\\N");
                    plcf->out.delimiter = '\t';
                } break;
            }
            continue;
        }
        if (str[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            if (!(plcf->out.null.len = str[i].len - (sizeof("null=") - 1))) return "empty \"null\" value";
            plcf->out.null.data = &str[i].data[sizeof("null=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            if (!(str[i].len - (sizeof("quote=") - 1))) { plcf->out.quote = '\0'; continue; }
            else if (str[i].len - (sizeof("quote=") - 1) > 1) return "\"quote\" value must be one character";
            plcf->out.quote = str[i].data[sizeof("quote=") - 1];
            continue;
        }
        if (str[i].len > sizeof("string=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("string=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("string=") - 1], str[i].len - (sizeof("string=") - 1))) break;
            if (!e[j].name.len) return "\"string\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            plcf->out.string = e[j].value;
            continue;
        }
        ngx_pg_argument_t *argument;
        if (!plcf->arguments && !(plcf->arguments = ngx_array_create(cf->pool, 1, sizeof(*argument)))) return "!ngx_array_create";
        if (!(argument = ngx_array_push(plcf->arguments))) return "!ngx_array_push";
        ngx_memzero(argument, sizeof(*argument));
        u_char *colon;
        ngx_str_t name = str[i];
        ngx_str_t type = ngx_null_string;
        if ((colon = ngx_strstrn(name.data, "::", sizeof("::") - 1 - 1))) {
            name.len = colon - name.data;
            type.data = colon + sizeof("::") - 1;
            type.len = str[i].len - name.len - sizeof("::") + 1;
        }
        if (name.len != sizeof("NULL") - 1 || ngx_strncasecmp(name.data, "NULL", sizeof("NULL") - 1)) {
            ngx_http_compile_complex_value_t ccv = {cf, &name, &argument->argument, 0, 0, 0};
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
        }
        if (!type.data) continue;
        ngx_http_compile_complex_value_t ccv = {cf, &type, &argument->type, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_function_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->function.value.data) return "duplicate";
    if (plcf->query.data) return "conflicts with \"pg_query\" directive";
    ngx_str_t *str = cf->args->elts;
    ngx_http_compile_complex_value_t ccv = {cf, &str[1], &plcf->function, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    return ngx_pg_argument_output_loc_conf(cf, cmd, conf);
}

static char *ngx_pg_log_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_log_set_log(cf, &pscf->log);
}

static char *ngx_pg_option_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->options) return "duplicate";
    ngx_str_t *option;
    if (!(plcf->options = ngx_array_create(cf->pool, 1, sizeof(*option)))) return "!ngx_array_create";
    ngx_str_t *str = cf->args->elts;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (!(option = ngx_array_push(plcf->options))) return "!ngx_array_push";
        *option = str[i];
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_option_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    if (pscf->options) return "duplicate";
    ngx_str_t *option;
    if (!(pscf->options = ngx_array_create(cf->pool, 1, sizeof(*option)))) return "!ngx_array_create";
    ngx_str_t *str = cf->args->elts;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (!(option = ngx_array_push(pscf->options))) return "!ngx_array_push";
        *option = str[i];
    }
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (uscf->peer.init_upstream != ngx_pg_peer_init_upstream) {
        pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
        uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_pass_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->upstream.upstream || plcf->complex.value.data) return "duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pg_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_str_t *str = cf->args->elts;
    if (ngx_http_script_variables_count(&str[1])) {
        ngx_http_compile_complex_value_t ccv = {cf, &str[1], &plcf->complex, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
        return NGX_CONF_OK;
    }
    ngx_url_t url = {0};
    if (!plcf->options) url.no_resolve = 1;
    url.url = str[1];
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) return NGX_CONF_ERROR;
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    return NGX_CONF_OK;
}

static char *ngx_pg_query_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->query.data) return "duplicate";
    if (plcf->function.value.data) return "conflicts with \"pg_function\" directive";
    ngx_str_t *str = cf->args->elts;
    plcf->query = str[1];
    return ngx_pg_argument_output_loc_conf(cf, cmd, conf);
}

#if (NGX_HTTP_CACHE)
static char *ngx_pg_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->upstream.cache != NGX_CONF_UNSET) return "is duplicate";
    ngx_str_t *str = cf->args->elts;
    if (ngx_strcmp(str[1].data, "off") == 0) { plcf->upstream.cache = 0; return NGX_CONF_OK; }
    if (plcf->upstream.store > 0) return "is incompatible with \"pg_store\"";
    plcf->upstream.cache = 1;
    ngx_http_compile_complex_value_t ccv = {0};
    ngx_http_complex_value_t cv = {0};
    ccv.cf = cf;
    ccv.value = &str[1];
    ccv.complex_value = &cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    if (cv.lengths) {
        if (!(plcf->upstream.cache_value = ngx_palloc(cf->pool, sizeof(*plcf->upstream.cache_value)))) return "!ngx_palloc";
        *plcf->upstream.cache_value = cv;
        return NGX_CONF_OK;
    }
    if (!(plcf->upstream.cache_zone = ngx_shared_memory_add(cf, &str[1], 0, &ngx_pg_module))) return "!ngx_shared_memory_add";
    return NGX_CONF_OK;
}

static char *ngx_pg_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->cache_key.value.data) return "is duplicate";
    ngx_str_t *str = cf->args->elts;
    ngx_http_compile_complex_value_t ccv = {0};
    ccv.cf = cf;
    ccv.value = &str[1];
    ccv.complex_value = &plcf->cache_key;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    return NGX_CONF_OK;
}
#endif

static ngx_conf_bitmask_t ngx_pg_next_upstream_masks[] = {
  { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
  { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
  { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
  { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
  { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
  { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
  { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
  { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
  { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
  { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
  { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
  { ngx_null_string, 0 }
};

static ngx_command_t ngx_pg_commands[] = {
  { ngx_string("pg_function"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_function_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, function), NULL },
  { ngx_string("pg_log"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_log_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_option"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_option_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, options), NULL },
  { ngx_string("pg_option"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_option_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, offsetof(ngx_pg_srv_conf_t, options), NULL },
  { ngx_string("pg_pass"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1, ngx_pg_pass_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_query"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_query_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, query), NULL },
  { ngx_string("pg_buffering"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.buffering), NULL },
  { ngx_string("pg_buffer_size"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.buffer_size), NULL },
  { ngx_string("pg_buffers"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2, ngx_conf_set_bufs_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.bufs), NULL },
  { ngx_string("pg_busy_buffers_size"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.busy_buffers_size_conf), NULL },
  { ngx_string("pg_connect_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.connect_timeout), NULL },
  { ngx_string("pg_ignore_client_abort"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.ignore_client_abort), NULL },
  { ngx_string("pg_intercept_errors"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.intercept_errors), NULL },
  { ngx_string("pg_next_upstream"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.next_upstream), &ngx_pg_next_upstream_masks },
  { ngx_string("pg_next_upstream_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.next_upstream_timeout), NULL },
  { ngx_string("pg_next_upstream_tries"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.next_upstream_tries), NULL },
  { ngx_string("pg_pass_request_body"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.pass_request_body), NULL },
  { ngx_string("pg_read_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.read_timeout), NULL },
  { ngx_string("pg_request_buffering"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.request_buffering), NULL },
  { ngx_string("pg_send_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.send_timeout), NULL },
  { ngx_string("pg_socket_keepalive"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.socket_keepalive), NULL },
#if (NGX_HTTP_CACHE)
  { ngx_string("pg_cache_background_update"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_background_update), NULL },
  { ngx_string("pg_cache_bypass"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_http_set_predicate_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_bypass), NULL },
  { ngx_string("pg_cache_key"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_pg_cache_key, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_cache_lock_age"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_lock_age), NULL },
  { ngx_string("pg_cache_lock"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_lock), NULL },
  { ngx_string("pg_cache_lock_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_lock_timeout), NULL },
  { ngx_string("pg_cache_max_range_offset"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_off_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_max_range_offset), NULL },
  { ngx_string("pg_cache_methods"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_methods), &ngx_http_upstream_cache_method_mask },
  { ngx_string("pg_cache_min_uses"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_min_uses), NULL },
  { ngx_string("pg_cache"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_pg_cache, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_cache_path"), NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE, ngx_http_file_cache_set_slot, NGX_HTTP_MAIN_CONF_OFFSET, offsetof(ngx_pg_main_conf_t, caches), &ngx_pg_module },
  { ngx_string("pg_cache_revalidate"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_revalidate), NULL },
  { ngx_string("pg_cache_use_stale"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_use_stale), &ngx_pg_next_upstream_masks },
  { ngx_string("pg_cache_valid"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_http_file_cache_valid_set_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.cache_valid), NULL },
  { ngx_string("pg_no_cache"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_http_set_predicate_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.no_cache), NULL },
#endif
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
