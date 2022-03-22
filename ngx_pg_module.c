#include <ngx_http.h>
#include "pg_parser.h"

ngx_module_t ngx_pg_module;

typedef enum {
    ngx_pg_state_unknown = 0,
    ngx_pg_state_idle,
    ngx_pg_state_inerror,
    ngx_pg_state_intrans,
} ngx_pg_state_t;

typedef struct {
    ngx_chain_t *bind;
    ngx_chain_t *close;
    ngx_chain_t *connect;
    ngx_chain_t *describe;
    ngx_chain_t *execute;
    ngx_chain_t *parse;
    ngx_chain_t *sync;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t upstream;
} ngx_pg_loc_conf_t;

typedef struct {
    ngx_chain_t *connect;
    ngx_http_upstream_peer_t peer;
    ngx_log_t *log;
} ngx_pg_srv_conf_t;

typedef struct {
    ngx_str_t key;
    ngx_str_t val;
} ngx_pg_key_val_t;

typedef struct {
    ngx_array_t option;
    ngx_buf_t buffer;
    ngx_connection_t *connection;
    ngx_http_request_t *request;
    ngx_pg_state_t state;
    pg_parser_t *parser;
    struct {
        ngx_event_handler_pt read_handler;
        ngx_event_handler_pt write_handler;
        void *data;
    } keep;
} ngx_pg_save_t;

typedef struct {
    ngx_array_t error;
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_pg_save_t *save;
    ngx_pg_srv_conf_t *conf;
} ngx_pg_data_t;

static ngx_int_t ngx_pg_add_response(ngx_http_request_t *r, size_t len, const u_char *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_chain_t *cl, **ll;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
    if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
    *ll = cl;
    ngx_buf_t *b = cl->buf;
    b->flush = 1;
    b->last = data + len;
    b->memory = 1;
    b->pos = data;
    b->tag = u->output.tag;
    b->temporary = 1;
    for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%c", *p, *p);
    return NGX_OK;
}

static ngx_int_t ngx_pg_parser_all(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i:%c", *(const u_char *)ptr, *(const u_char *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_atttypmod(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint32_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_auth(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_bind(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_byte(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    ngx_http_request_t *r = s->request;
    if (r && ngx_pg_add_response(r, len, str) == NGX_ERROR) return NGX_ERROR;
    return NGX_OK;
}
static ngx_int_t ngx_pg_parser_close(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_columnid(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint16_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_column(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_command(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_complete(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_constraint(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_context(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_datatype(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_detail(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_error(ngx_pg_save_t *s, const void *ptr) {
    ngx_http_request_t *r = s->request;
    if (r) {
        ngx_http_upstream_t *u = r->upstream;
        u->headers_in.status_n = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    uint32_t len;
    if (!(len = *(uint32_t *)ptr)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); return NGX_ERROR; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", len);
    return NGX_OK;
}
static ngx_int_t ngx_pg_parser_fatal(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_HTTP_UPSTREAM_INVALID_HEADER; }
static ngx_int_t ngx_pg_parser_field(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_file(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_format(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint16_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_function(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_hint(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_idle(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); s->state = ngx_pg_state_idle; return NGX_OK; }
static ngx_int_t ngx_pg_parser_inerror(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); s->state = ngx_pg_state_inerror; return NGX_OK; }
static ngx_int_t ngx_pg_parser_internal(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_intrans(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); s->state = ngx_pg_state_intrans; return NGX_OK; }
static ngx_int_t ngx_pg_parser_key(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint32_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_line(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_method(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint32_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_name(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_nbytes(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint32_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_nfields(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint16_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_nonlocalized(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_ntups(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint16_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_option(ngx_pg_save_t *s, size_t len, const u_char *str) {
    if (!len) return NGX_OK;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    if (!s->option.nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); return NGX_ERROR; }
    ngx_pg_key_val_t *option = s->option.elts;
    option = &option[s->option.nelts - 1];
    (void)strncat((char *)option->key.data, (char *)str, len);
    return NGX_OK;
}
static ngx_int_t ngx_pg_parser_parse(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_pid(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint32_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_primary(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_query(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_ready(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_schema(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_secret(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_OK; }
static ngx_int_t ngx_pg_parser_severity(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_sqlstate(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_statement(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_status(ngx_pg_save_t *s, const void *ptr) {
    uint32_t len;
    if (!(len = *(uint32_t *)ptr)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); return NGX_ERROR; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", len);
    ngx_pg_key_val_t *option;
    if (!(option = ngx_array_push(&s->option))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
    ngx_memzero(option, sizeof(*option));
    if (!(option->key.data = ngx_pcalloc(s->connection->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    return NGX_OK;
}
static ngx_int_t ngx_pg_parser_tableid(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint32_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_table(ngx_pg_save_t *s, size_t len, const u_char *str) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str); return NGX_OK; }
static ngx_int_t ngx_pg_parser_tup(ngx_pg_save_t *s) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); return NGX_DONE; }
static ngx_int_t ngx_pg_parser_typid(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint32_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_typlen(ngx_pg_save_t *s, const void *ptr) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(uint16_t *)ptr); return NGX_OK; }
static ngx_int_t ngx_pg_parser_unknown(ngx_pg_save_t *s, size_t len, const u_char *str) { for (u_char *p = str; p < str + len; p++) ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%i:%c", *p, *p); return NGX_HTTP_UPSTREAM_INVALID_HEADER; }
static ngx_int_t ngx_pg_parser_value(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    if (!len) return NGX_OK;
    if (!s->option.nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); return NGX_ERROR; }
    ngx_pg_key_val_t *option = s->option.elts;
    option = &option[s->option.nelts - 1];
    if (!option->val.data) option->val.data = option->key.data + (option->key.len = ngx_strlen(option->key.data)) + 1;
    (void)strncat((char *)option->val.data, (char *)str, len);
    option->val.len = ngx_strlen(option->val.data);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%V = %V", &option->key, &option->val);
    return NGX_OK;
}

static const pg_parser_settings_t ngx_pg_parser_settings = {
    .all = (pg_parser_ptr_cb)ngx_pg_parser_all,
    .atttypmod = (pg_parser_ptr_cb)ngx_pg_parser_atttypmod,
    .auth = (pg_parser_cb)ngx_pg_parser_auth,
    .bind = (pg_parser_cb)ngx_pg_parser_bind,
    .byte = (pg_parser_str_cb)ngx_pg_parser_byte,
    .close = (pg_parser_cb)ngx_pg_parser_close,
    .columnid = (pg_parser_ptr_cb)ngx_pg_parser_columnid,
    .column = (pg_parser_str_cb)ngx_pg_parser_column,
    .command = (pg_parser_str_cb)ngx_pg_parser_command,
    .complete = (pg_parser_cb)ngx_pg_parser_complete,
    .constraint = (pg_parser_str_cb)ngx_pg_parser_constraint,
    .context = (pg_parser_str_cb)ngx_pg_parser_context,
    .datatype = (pg_parser_str_cb)ngx_pg_parser_datatype,
    .detail = (pg_parser_str_cb)ngx_pg_parser_detail,
    .error = (pg_parser_ptr_cb)ngx_pg_parser_error,
    .fatal = (pg_parser_cb)ngx_pg_parser_fatal,
    .field = (pg_parser_cb)ngx_pg_parser_field,
    .file = (pg_parser_str_cb)ngx_pg_parser_file,
    .format = (pg_parser_ptr_cb)ngx_pg_parser_format,
    .function = (pg_parser_str_cb)ngx_pg_parser_function,
    .hint = (pg_parser_str_cb)ngx_pg_parser_hint,
    .idle = (pg_parser_cb)ngx_pg_parser_idle,
    .inerror = (pg_parser_cb)ngx_pg_parser_inerror,
    .internal = (pg_parser_str_cb)ngx_pg_parser_internal,
    .intrans = (pg_parser_cb)ngx_pg_parser_intrans,
    .key = (pg_parser_ptr_cb)ngx_pg_parser_key,
    .line = (pg_parser_str_cb)ngx_pg_parser_line,
    .method = (pg_parser_ptr_cb)ngx_pg_parser_method,
    .name = (pg_parser_str_cb)ngx_pg_parser_name,
    .nbytes = (pg_parser_ptr_cb)ngx_pg_parser_nbytes,
    .nfields = (pg_parser_ptr_cb)ngx_pg_parser_nfields,
    .nonlocalized = (pg_parser_str_cb)ngx_pg_parser_nonlocalized,
    .ntups = (pg_parser_ptr_cb)ngx_pg_parser_ntups,
    .option = (pg_parser_str_cb)ngx_pg_parser_option,
    .parse = (pg_parser_cb)ngx_pg_parser_parse,
    .pid = (pg_parser_ptr_cb)ngx_pg_parser_pid,
    .primary = (pg_parser_str_cb)ngx_pg_parser_primary,
    .query = (pg_parser_str_cb)ngx_pg_parser_query,
    .ready = (pg_parser_cb)ngx_pg_parser_ready,
    .schema = (pg_parser_str_cb)ngx_pg_parser_schema,
    .secret = (pg_parser_cb)ngx_pg_parser_secret,
    .severity = (pg_parser_str_cb)ngx_pg_parser_severity,
    .sqlstate = (pg_parser_str_cb)ngx_pg_parser_sqlstate,
    .statement = (pg_parser_str_cb)ngx_pg_parser_statement,
    .status = (pg_parser_ptr_cb)ngx_pg_parser_status,
    .tableid = (pg_parser_ptr_cb)ngx_pg_parser_tableid,
    .table = (pg_parser_str_cb)ngx_pg_parser_table,
    .tup = (pg_parser_cb)ngx_pg_parser_tup,
    .typid = (pg_parser_ptr_cb)ngx_pg_parser_typid,
    .typlen = (pg_parser_ptr_cb)ngx_pg_parser_typlen,
    .unknown = (pg_parser_str_cb)ngx_pg_parser_unknown,
    .value = (pg_parser_str_cb)ngx_pg_parser_value,
};

inline static ngx_chain_t *ngx_pg_write_uint8(ngx_pool_t *p, uint32_t *len, uint8_t uint8) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(uint8)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    cl->buf->last = pg_write_uint8(cl->buf->last, uint8);
    if (len) *len += sizeof(uint8);
    return cl;
}

inline static ngx_chain_t *ngx_pg_alloc_len(ngx_pool_t *p, uint32_t *len) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(*len)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (len) *len += sizeof(*len);
    return cl;
}

inline static ngx_chain_t *ngx_pg_exit(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_len, *sync;
    uint32_t len = 0;
    if (!(cl = sync = ngx_pg_write_uint8(p, NULL, 'X'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return sync;
}

static void ngx_pg_save_cln_handler(ngx_pg_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_http_request_t *r = s->request;
    if (r) {
        ngx_http_upstream_t *u = r->upstream;
        ngx_pg_data_t *d = u->peer.data;
        d->save = NULL;
        s->request = NULL;
    }
    ngx_chain_t *out, *last;
    if (!(out = ngx_pg_exit(c->pool))) return;
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
    ngx_chain_t *cl;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    ngx_pg_srv_conf_t *pscf = d->conf;
    if (!(cl = u->request_bufs = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    ngx_pg_save_t *s;
    if (pc->connection) s = d->save = (ngx_pg_save_t *)((char *)pc->connection->pool + sizeof(*pc->connection->pool)); else {
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
        if (!(c->pool = ngx_create_pool(128 + sizeof(*s), pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); return NGX_ERROR; }
        if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        if ((char *)s != (char *)c->pool + sizeof(*c->pool)) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "wrong pool"); return NGX_ERROR; }
        ngx_pool_cleanup_t *cln;
        if (!(cln = ngx_pool_cleanup_add(c->pool, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
        cln->data = s;
        cln->handler = (ngx_pool_cleanup_pt)ngx_pg_save_cln_handler;
        if (ngx_array_init(&s->option, c->pool, 1, sizeof(ngx_pg_key_val_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        if (!(s->parser = ngx_pcalloc(c->pool, pg_parser_size()))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        pg_parser_init(s->parser, &ngx_pg_parser_settings, s);
        s->connection = c;
        ngx_chain_t *connect = pscf ? pscf->connect : plcf->connect;
        for (ngx_chain_t *cmd = connect; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
    }
    s->request = r;
    for (ngx_chain_t *cmd = plcf->parse; cmd; cmd = cmd->next) {
        cl->buf = cmd->buf;
        ngx_buf_t *b = cl->buf;
        b->pos = b->start;
        if (cmd->next && !(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    }
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = u->request_bufs; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i:%i:%c", i++, *p, *p);
    return NGX_DONE;
}

static void ngx_pg_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_pg_save_t *s = c->data;
//    if (ngx_pg_parse(s) == NGX_OK) return;
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
    s->request = NULL;
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
    if (ngx_array_init(&d->error, r->pool, 1, sizeof(ngx_pg_key_val_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
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
    return NGX_OK;
}

static void ngx_pg_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
}

static ngx_int_t ngx_pg_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    u->headers_in.status_n = NGX_HTTP_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    ngx_buf_t *b = &u->buffer;
//    ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    ngx_int_t rc = NGX_OK;
    while (b->pos < b->last && (rc = pg_parser_execute(s->parser, b->last - b->pos, &b->pos)) == NGX_OK);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos = %p", b->pos);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->last = %p", b->last);
    if (rc == NGX_OK) {
        char buf[1];
        ngx_connection_t *c = s->connection;
        rc = s->state == ngx_pg_state_unknown || recv(c->fd, buf, 1, MSG_PEEK) > 0 ? NGX_AGAIN : NGX_OK;
    }
    if (b->pos == b->last) b->pos = b->last = b->start;
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
//    u->length = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter(void *data, ssize_t bytes) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bytes = %i", bytes);
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    ngx_buf_t *b = &u->buffer;
    ngx_int_t rc = NGX_OK;
    u_char *last = b->last + bytes;
    while (b->last < last && (rc = pg_parser_execute(s->parser, bytes, &b->last)) == NGX_OK);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    u->length = last - b->last;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "length = %i", u->length);
//    if (!(u->length -= bytes)) u->keepalive = !u->headers_in.connection_close;
    return rc;
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
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    ngx_str_set(&conf->upstream.module, "pg");
    return conf;
}

static char *ngx_pg_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_pg_loc_conf_t *prev = parent;
    ngx_pg_loc_conf_t *conf = child;
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
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);
    ngx_conf_merge_value(conf->upstream.pass_request_body, prev->upstream.pass_request_body, 0);
    ngx_conf_merge_value(conf->upstream.socket_keepalive, prev->upstream.socket_keepalive, 0);
    if (conf->upstream.bufs.num < 2) return "there must be at least 2 \"pg_buffers\"";
    size_t size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) size = conf->upstream.bufs.size;
    conf->upstream.busy_buffers_size = conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE ? 2 * size : conf->upstream.busy_buffers_size_conf;
    if (conf->upstream.busy_buffers_size < size) return "\"pg_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"pg_buffer_size\" and one of the \"pg_buffers\"";
    if (conf->upstream.busy_buffers_size > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) return "\"pg_busy_buffers_size\" must be less than the size of all \"pg_buffers\" minus one buffer";
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    return NGX_CONF_OK;
}

static ngx_int_t pg_error_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_key_val_t *elts = d->error.elts;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_uint_t i;
    for (i = 0; i < d->error.nelts; i++) if (name->len - sizeof("pg_error_") + 1 == elts[i].key.len && !ngx_strncasecmp(name->data + sizeof("pg_error_") - 1, elts[i].key.data, elts[i].key.len)) break;
    if (i == d->error.nelts) return NGX_OK;
    v->data = elts[i].val.data;
    v->len = elts[i].val.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t pg_option_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!s) return NGX_OK;
    ngx_pg_key_val_t *elts = s->option.elts;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_uint_t i;
    for (i = 0; i < s->option.nelts; i++) if (name->len - sizeof("pg_option_") + 1 == elts[i].key.len && !ngx_strncasecmp(name->data + sizeof("pg_option_") - 1, elts[i].key.data, elts[i].key.len)) break;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", i == s->option.nelts ? "true" : "false");
    if (i == s->option.nelts) return NGX_OK;
    v->data = elts[i].val.data;
    v->len = elts[i].val.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static const ngx_http_variable_t ngx_pg_variables[] = {
  { .name = ngx_string("pg_error_"),
    .set_handler = NULL,
    .get_handler = pg_error_get_handler,
    .data = 0,
    .flags = NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX,
    .index = 0 },
  { .name = ngx_string("pg_option_"),
    .set_handler = NULL,
    .get_handler = pg_option_get_handler,
    .data = 0,
    .flags = NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX,
    .index = 0 },
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

static ngx_http_module_t ngx_pg_ctx = {
    .preconfiguration = ngx_pg_preconfiguration,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_pg_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_pg_create_loc_conf,
    .merge_loc_conf = ngx_pg_merge_loc_conf
};

static ngx_int_t ngx_pg_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
//    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
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

inline static ngx_chain_t *ngx_pg_write_uint16(ngx_pool_t *p, uint32_t *len, uint16_t uint16) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(uint16)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    cl->buf->last = pg_write_uint16(cl->buf->last, uint16);
    if (len) *len += sizeof(uint16);
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_uint32(ngx_pool_t *p, uint32_t *len, uint32_t uint32) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(uint32)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    cl->buf->last = pg_write_uint32(cl->buf->last, uint32);
    if (len) *len += sizeof(uint32);
    return cl;
}

inline static ngx_chain_t *ngx_pg_write_opt(ngx_pool_t *p, uint32_t *len, ngx_str_t str) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, str.len + sizeof(uint8_t)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    for (ngx_uint_t i = 0; i < str.len; i++) cl->buf->last = pg_write_uint8(cl->buf->last, str.data[i] == '=' ? 0 : str.data[i]);
    cl->buf->last = pg_write_uint8(cl->buf->last, 0);
    if (len) *len += str.len + sizeof(uint8_t);
    return cl;
}

static char *ngx_pg_connect(ngx_conf_t *cf, ngx_command_t *cmd, ngx_chain_t **connect) {
    ngx_chain_t *cl, *cl_len;
    uint32_t len = 0;
    if (!(cl = cl_len = *connect = ngx_pg_alloc_len(cf->pool, &len))) return NGX_CONF_ERROR;
    if (!(cl = cl->next = ngx_pg_write_uint32(cf->pool, &len, 0x00030000))) return NGX_CONF_ERROR;
    ngx_str_t *elts = cf->args->elts;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) if (!(cl = cl->next = ngx_pg_write_opt(cf->pool, &len, elts[i]))) return NGX_CONF_ERROR;
    if (!(cl = cl->next = ngx_pg_write_uint8(cf->pool, &len, 0))) return NGX_CONF_ERROR;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = *connect; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%i:%i:%c", i++, *p, *p);
    return NGX_CONF_OK;
}

static char *ngx_pg_connect_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->connect) return "duplicate";
    return ngx_pg_connect(cf, cmd, &plcf->connect);
}

static char *ngx_pg_connect_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    if (pscf->connect) return "duplicate";
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    return ngx_pg_connect(cf, cmd, &pscf->connect);
}

static char *ngx_pg_log_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_log_set_log(cf, &pscf->log);
}

static char *ngx_pg_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->upstream.upstream || plcf->complex.value.data) return "duplicate";
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_pg_handler;
    if (clcf->name.data[clcf->name.len - 1] == '/') clcf->auto_redirect = 1;
    ngx_str_t *elts = cf->args->elts;
    if (ngx_http_script_variables_count(&elts[1])) {
        ngx_http_compile_complex_value_t ccv = {cf, &elts[1], &plcf->complex, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
        return NGX_CONF_OK;
    }
    ngx_url_t url = {0};
    if (!plcf->connect) url.no_resolve = 1;
    url.url = elts[1];
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) return NGX_CONF_ERROR;
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    return NGX_CONF_OK;
}

inline static ngx_chain_t *ngx_pg_write_str(ngx_pool_t *p, uint32_t *len, ngx_str_t str) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, str.len + sizeof(uint8_t)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (str.len) cl->buf->last = ngx_copy(cl->buf->last, str.data, str.len);
    cl->buf->last = pg_write_uint8(cl->buf->last, 0);
    if (len) *len += str.len + sizeof(uint8_t);
    return cl;
}

inline static ngx_chain_t *ngx_pg_query(ngx_pool_t *p, ngx_str_t str) {
    ngx_chain_t *cl, *cl_len, *query;
    uint32_t len = 0;
    if (!(cl = query = ngx_pg_write_uint8(p, NULL, 'Q'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, str))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return query;
}

inline static ngx_chain_t *ngx_pg_parse(ngx_pool_t *p, ngx_str_t str) {
    ngx_chain_t *cl, *cl_len, *parse;
    uint32_t len = 0;
    if (!(cl = parse = ngx_pg_write_uint8(p, NULL, 'P'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, (ngx_str_t)ngx_string("")))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, str))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint16(p, &len, 0))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return parse;
}

inline static ngx_chain_t *ngx_pg_bind(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_len, *bind;
    uint32_t len = 0;
    if (!(cl = bind = ngx_pg_write_uint8(p, NULL, 'B'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, (ngx_str_t)ngx_string("")))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, (ngx_str_t)ngx_string("")))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint16(p, &len, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint16(p, &len, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint16(p, &len, 0))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return bind;
}

inline static ngx_chain_t *ngx_pg_describe(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_len, *describe;
    uint32_t len = 0;
    if (!(cl = describe = ngx_pg_write_uint8(p, NULL, 'D'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint8(p, &len, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, (ngx_str_t)ngx_string("")))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return describe;
}

inline static ngx_chain_t *ngx_pg_execute(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_len, *execute;
    uint32_t len = 0;
    if (!(cl = execute = ngx_pg_write_uint8(p, NULL, 'E'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, (ngx_str_t)ngx_string("")))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint32(p, &len, 0))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return execute;
}

inline static ngx_chain_t *ngx_pg_close(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_len, *close;
    uint32_t len = 0;
    if (!(cl = close = ngx_pg_write_uint8(p, NULL, 'C'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint8(p, &len, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &len, (ngx_str_t)ngx_string("")))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return close;
}

inline static ngx_chain_t *ngx_pg_sync(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_len, *sync;
    uint32_t len = 0;
    if (!(cl = sync = ngx_pg_write_uint8(p, NULL, 'S'))) return NULL;
    if (!(cl = cl->next = cl_len = ngx_pg_alloc_len(p, &len))) return NULL;
    cl_len->buf->last = pg_write_uint32(cl_len->buf->last, len);
    cl->next = NULL;
    return sync;
}

static char *ngx_pg_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->parse) return "duplicate";
    ngx_chain_t *cl;
    ngx_str_t *elts = cf->args->elts;
//    if (!(cl = plcf->parse = ngx_pg_query(cf->pool, elts[1]))) return NGX_CONF_ERROR;
    if (!(cl = plcf->parse = ngx_pg_parse(cf->pool, elts[1]))) return NGX_CONF_ERROR;
    while (cl->next) cl = cl->next;
    if (!(cl = cl->next = plcf->bind = ngx_pg_bind(cf->pool))) return NGX_CONF_ERROR;
    while (cl->next) cl = cl->next;
    if (!(cl = cl->next = plcf->describe = ngx_pg_describe(cf->pool))) return NGX_CONF_ERROR;
    while (cl->next) cl = cl->next;
    if (!(cl = cl->next = plcf->execute = ngx_pg_execute(cf->pool))) return NGX_CONF_ERROR;
//    while (cl->next) cl = cl->next;
//    if (!(cl = cl->next = plcf->close = ngx_pg_close(cf->pool))) return NGX_CONF_ERROR;
    while (cl->next) cl = cl->next;
    if (!(cl = cl->next = plcf->sync = ngx_pg_sync(cf->pool))) return NGX_CONF_ERROR;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = plcf->parse; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%i:%i:%c", i++, *p, *p);
    return NGX_CONF_OK;
}

static ngx_command_t ngx_pg_commands[] = {
  { .name = ngx_string("pg_connect"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_connect_loc_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("pg_connect"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_pg_connect_ups_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
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
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
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
