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
    ngx_http_complex_value_t complex;
    ngx_uint_t type;
} ngx_pg_arg_t;

typedef struct {
    ngx_array_t *arg;
    ngx_chain_t *close;
    ngx_chain_t *connect;
    ngx_chain_t *describe;
    ngx_chain_t *execute;
    ngx_chain_t *flush;
    ngx_chain_t *parse;
    ngx_chain_t *query;
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

typedef struct ngx_pg_data_t ngx_pg_data_t;

typedef struct {
    ngx_array_t *option;
    ngx_buf_t buffer;
    ngx_connection_t *connection;
    ngx_pg_data_t *data;
    ngx_pg_state_t state;
    ngx_uint_t rc;
    pg_parser_t *parser;
    int32_t pid;
    struct {
        ngx_event_handler_pt read_handler;
        ngx_event_handler_pt write_handler;
        void *data;
    } keep;
} ngx_pg_save_t;

typedef struct {
    ngx_str_t name;
    int16_t columnid;
    int16_t format;
    int16_t oidlen;
    int32_t mod;
    int32_t oid;
    int32_t tableid;
} ngx_pg_col_t;

typedef struct {
    ngx_array_t *str;
} ngx_pg_row_t;

typedef struct ngx_pg_data_t {
    ngx_array_t *col;
    ngx_array_t *error;
    ngx_array_t *row;
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_pg_save_t *save;
    ngx_pg_srv_conf_t *conf;
    ngx_str_t cols;
    ngx_str_t command;
    ngx_uint_t ready;
    int16_t ncols;
    int16_t nrows;
} ngx_pg_data_t;

inline static u_char *pg_write_int(u_char *p, int m, int n) { for (; m; *p++ = n >> (2 << 2) * --m); return p; }

static ngx_int_t ngx_pg_add_error(ngx_pg_data_t *d, ngx_str_t key, size_t len, const u_char *str) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!d->error->nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!nelts"); return NGX_ERROR; }
    ngx_pg_key_val_t *elts = d->error->elts;
    ngx_pg_key_val_t *error = &elts[d->error->nelts - 1];
    if (error->key.len != key.len || ngx_strncasecmp(error->key.data, key.data, key.len)) {
        if (!(error = ngx_array_push(d->error))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
        ngx_memzero(error, sizeof(*error));
        error->val.data = elts[d->error->nelts - 2].val.data + elts[d->error->nelts - 2].val.len + 1;
    }
    error->key = key;
    (void)ngx_copy(error->val.data + error->val.len, str, len);
    error->val.len += len;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%V = %V", &error->key, &error->val);
    return NGX_OK;
}

static ngx_int_t ngx_pg_parser_all(ngx_pg_save_t *s, const void *ptr) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i:%c", *(const u_char *)ptr, *(const u_char *)ptr);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_mod(ngx_pg_save_t *s, const void *ptr) {
    int32_t mod = *(int32_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", mod);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_col_t *elts = d->col->elts;
    elts[d->col->nelts - 2].mod = mod;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_auth(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_bind(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_byte(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    if (!d->row->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_ERROR; return s->rc; }
    ngx_pg_row_t *elts = d->row->elts;
    ngx_pg_row_t *row = &elts[d->row->nelts - 1];
    if (!row->str->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_ERROR; return s->rc; }
    ngx_str_t *rowelts = row->str->elts;
    ngx_str_t *strstr = &rowelts[row->str->nelts - 1];
    (void)ngx_copy(strstr->data + strstr->len, str, len);
    strstr->len += len;
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i,%i:%V", d->row->nelts - 1, row->str->nelts - 1, strstr);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_close(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_columnid(ngx_pg_save_t *s, const void *ptr) {
    int16_t columnid = *(int16_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", columnid);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_col_t *elts = d->col->elts;
    elts[d->col->nelts - 2].columnid = columnid;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_column(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("column"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_command(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    (void)ngx_copy(d->command.data + d->command.len, str, len);
    d->command.len += len;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_complete(ngx_pg_save_t *s, const void *ptr) {
    int32_t len;
    if (!(len = *(int32_t *)ptr)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", len);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    if (!(d->command.data = ngx_pnalloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static ngx_int_t ngx_pg_parser_constraint(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("constraint"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_context(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("context"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_datatype(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("datatype"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_detail(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("detail"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_error(ngx_pg_save_t *s, const void *ptr) {
    int32_t len;
    if (!(len = *(int32_t *)ptr)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", len);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    u->headers_in.status_n = NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_pg_key_val_t *error;
    if (!(d->error = ngx_array_create(r->pool, 1, sizeof(*error)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_create"); s->rc = NGX_ERROR; return s->rc; }
    if (!(error = ngx_array_push(d->error))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(error, sizeof(*error));
    if (!(error->val.data = ngx_pnalloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static ngx_int_t ngx_pg_parser_fatal(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_col(ngx_pg_save_t *s, const void *ptr) {
    int32_t len;
    if (!(len = *(int32_t *)ptr)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", len);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    if (!(d->cols.data = ngx_pnalloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static ngx_int_t ngx_pg_parser_file(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("file"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_format(ngx_pg_save_t *s, const void *ptr) {
    int16_t format = *(int16_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", format);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_col_t *elts = d->col->elts;
    elts[d->col->nelts - 2].format = format;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_function(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("function"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_hint(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("hint"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_idle(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); s->state = ngx_pg_state_idle;
    s->state = ngx_pg_state_idle;
    ngx_pg_data_t *d = s->data;
    if (d && d->ready) d->ready--;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_inerror(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__); s->state = ngx_pg_state_inerror;
    s->state = ngx_pg_state_inerror;
    ngx_pg_data_t *d = s->data;
    if (d && d->ready) d->ready--;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_internal(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("internal"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_intrans(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    s->state = ngx_pg_state_intrans;
    ngx_pg_data_t *d = s->data;
    if (d && d->ready) d->ready--;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_key(ngx_pg_save_t *s, const void *ptr) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(int32_t *)ptr);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_line(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("line"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_method(ngx_pg_save_t *s, const void *ptr) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", *(int32_t *)ptr);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_name(ngx_pg_save_t *s, size_t len, const u_char *str) {
    if (!len) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    if (!d->col->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_pg_col_t *elts = d->col->elts;
    ngx_pg_col_t *col = &elts[d->col->nelts - 1];
    (void)ngx_copy(col->name.data + col->name.len, str, len);
    col->name.len += len;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_nbytes(ngx_pg_save_t *s, const void *ptr) {
    int32_t nbytes = *(int32_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", nbytes);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    if (!d->row->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_ERROR; return s->rc; }
    ngx_http_request_t *r = d->request;
    ngx_pg_row_t *elts = d->row->elts;
    ngx_pg_row_t *row = &elts[d->row->nelts - 1];
    ngx_str_t *str;
    if (!(str = ngx_array_push(row->str))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(str, sizeof(*str));
    if (nbytes == (int32_t)-1) return s->rc;
    if (!(str->data = ngx_pnalloc(r->pool, nbytes))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static ngx_int_t ngx_pg_parser_ncols(ngx_pg_save_t *s, const void *ptr) {
    int16_t ncols = *(int16_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", ncols);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->ncols = ncols;
    if (!ncols) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_pg_col_t *col;
    if (!(d->col = ngx_array_create(r->pool, ncols, sizeof(*col)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_create"); s->rc = NGX_ERROR; return s->rc; }
    if (!(col = ngx_array_push(d->col))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(col, sizeof(*col));
    col->name.data = d->cols.data;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_nonlocalized(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("nonlocalized"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_nrows(ngx_pg_save_t *s, const void *ptr) {
    int16_t nrows = *(int16_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", nrows);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    d->nrows = nrows;
    if (!nrows) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_pg_row_t *row;
    if (!(row = ngx_array_push(d->row))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(row, sizeof(*row));
    ngx_str_t *str;
    if (!(row->str = ngx_array_create(r->pool, nrows, sizeof(*str)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_create"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static ngx_int_t ngx_pg_parser_option(ngx_pg_save_t *s, size_t len, const u_char *str) {
    if (!len) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    if (!s->option->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_pg_key_val_t *elts = s->option->elts;
    ngx_pg_key_val_t *option = &elts[s->option->nelts - 1];
    (void)ngx_copy(option->key.data + option->key.len, str, len);
    option->key.len += len;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_parse(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_pid(ngx_pg_save_t *s, const void *ptr) {
    int32_t pid = *(int32_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", pid);
    s->pid = pid;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_primary(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("primary"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_query(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("query"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_ready(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_schema(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("schema"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_secret(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_severity(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("severity"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_sqlstate(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("sqlstate"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_statement(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("statement"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_status(ngx_pg_save_t *s, const void *ptr) {
    int32_t len;
    if (!(len = *(int32_t *)ptr)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", len);
    ngx_pg_key_val_t *option;
    if (!(option = ngx_array_push(s->option))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(option, sizeof(*option));
    ngx_connection_t *c = s->connection;
    if (!(option->key.data = ngx_pnalloc(c->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static ngx_int_t ngx_pg_parser_tableid(ngx_pg_save_t *s, const void *ptr) {
    int32_t tableid = *(int32_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", tableid);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_col_t *col;
    ngx_pg_col_t *elts = d->col->elts;
    if (!(col = ngx_array_push(d->col))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
    ngx_memzero(col, sizeof(*col));
    col->name.data = elts[d->col->nelts - 2].name.data + elts[d->col->nelts - 2].name.len + 1;
    col->tableid = tableid;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_table(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%*s", (int)len, str);
    ngx_pg_data_t *d = s->data;
    if (d) s->rc = ngx_pg_add_error(d, (ngx_str_t)ngx_string("table"), len, str);
    return s->rc;
}

static ngx_int_t ngx_pg_parser_row(ngx_pg_save_t *s, const void *ptr) {
    int32_t len;
    if (!(len = *(int32_t *)ptr)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", len);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_pg_row_t *row;
    if (!d->row && !(d->row = ngx_array_create(r->pool, 1, sizeof(*row)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_create"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static ngx_int_t ngx_pg_parser_oid(ngx_pg_save_t *s, const void *ptr) {
    int32_t oid = *(int32_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", oid);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_col_t *elts = d->col->elts;
    elts[d->col->nelts - 2].oid = oid;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_oidlen(ngx_pg_save_t *s, const void *ptr) {
    int16_t oidlen = *(int16_t *)ptr;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i", oidlen);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_col_t *elts = d->col->elts;
    elts[d->col->nelts - 2].oidlen = oidlen;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_unknown(ngx_pg_save_t *s, size_t len, const u_char *str) {
    ngx_uint_t i = 0; for (u_char *p = str; p < str + len; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
    return s->rc;
}

static ngx_int_t ngx_pg_parser_value(ngx_pg_save_t *s, size_t len, const u_char *str) {
    if (!len) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!len"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, str);
    if (!s->option->nelts) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!nelts"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_pg_key_val_t *option = s->option->elts;
    option = &option[s->option->nelts - 1];
    if (!option->val.data) option->val.data = option->key.data + option->key.len + 1;
    (void)ngx_copy(option->val.data + option->val.len, str, len);
    option->val.len += len;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%V = %V", &option->key, &option->val);
    return s->rc;
}

static const pg_parser_settings_t ngx_pg_parser_settings = {
    .all = (pg_parser_ptr_cb)ngx_pg_parser_all,
    .auth = (pg_parser_cb)ngx_pg_parser_auth,
    .bind = (pg_parser_cb)ngx_pg_parser_bind,
    .byte = (pg_parser_len_str_cb)ngx_pg_parser_byte,
    .close = (pg_parser_cb)ngx_pg_parser_close,
    .col = (pg_parser_ptr_cb)ngx_pg_parser_col,
    .columnid = (pg_parser_ptr_cb)ngx_pg_parser_columnid,
    .column = (pg_parser_len_str_cb)ngx_pg_parser_column,
    .command = (pg_parser_len_str_cb)ngx_pg_parser_command,
    .complete = (pg_parser_ptr_cb)ngx_pg_parser_complete,
    .constraint = (pg_parser_len_str_cb)ngx_pg_parser_constraint,
    .context = (pg_parser_len_str_cb)ngx_pg_parser_context,
    .datatype = (pg_parser_len_str_cb)ngx_pg_parser_datatype,
    .detail = (pg_parser_len_str_cb)ngx_pg_parser_detail,
    .error = (pg_parser_ptr_cb)ngx_pg_parser_error,
    .fatal = (pg_parser_cb)ngx_pg_parser_fatal,
    .file = (pg_parser_len_str_cb)ngx_pg_parser_file,
    .format = (pg_parser_ptr_cb)ngx_pg_parser_format,
    .function = (pg_parser_len_str_cb)ngx_pg_parser_function,
    .hint = (pg_parser_len_str_cb)ngx_pg_parser_hint,
    .idle = (pg_parser_cb)ngx_pg_parser_idle,
    .inerror = (pg_parser_cb)ngx_pg_parser_inerror,
    .internal = (pg_parser_len_str_cb)ngx_pg_parser_internal,
    .intrans = (pg_parser_cb)ngx_pg_parser_intrans,
    .key = (pg_parser_ptr_cb)ngx_pg_parser_key,
    .line = (pg_parser_len_str_cb)ngx_pg_parser_line,
    .method = (pg_parser_ptr_cb)ngx_pg_parser_method,
    .mod = (pg_parser_ptr_cb)ngx_pg_parser_mod,
    .name = (pg_parser_len_str_cb)ngx_pg_parser_name,
    .nbytes = (pg_parser_ptr_cb)ngx_pg_parser_nbytes,
    .ncols = (pg_parser_ptr_cb)ngx_pg_parser_ncols,
    .nonlocalized = (pg_parser_len_str_cb)ngx_pg_parser_nonlocalized,
    .nrows = (pg_parser_ptr_cb)ngx_pg_parser_nrows,
    .oidlen = (pg_parser_ptr_cb)ngx_pg_parser_oidlen,
    .oid = (pg_parser_ptr_cb)ngx_pg_parser_oid,
    .option = (pg_parser_len_str_cb)ngx_pg_parser_option,
    .parse = (pg_parser_cb)ngx_pg_parser_parse,
    .pid = (pg_parser_ptr_cb)ngx_pg_parser_pid,
    .primary = (pg_parser_len_str_cb)ngx_pg_parser_primary,
    .query = (pg_parser_len_str_cb)ngx_pg_parser_query,
    .ready = (pg_parser_cb)ngx_pg_parser_ready,
    .row = (pg_parser_ptr_cb)ngx_pg_parser_row,
    .schema = (pg_parser_len_str_cb)ngx_pg_parser_schema,
    .secret = (pg_parser_cb)ngx_pg_parser_secret,
    .severity = (pg_parser_len_str_cb)ngx_pg_parser_severity,
    .sqlstate = (pg_parser_len_str_cb)ngx_pg_parser_sqlstate,
    .statement = (pg_parser_len_str_cb)ngx_pg_parser_statement,
    .status = (pg_parser_ptr_cb)ngx_pg_parser_status,
    .tableid = (pg_parser_ptr_cb)ngx_pg_parser_tableid,
    .table = (pg_parser_len_str_cb)ngx_pg_parser_table,
    .unknown = (pg_parser_len_str_cb)ngx_pg_parser_unknown,
    .value = (pg_parser_len_str_cb)ngx_pg_parser_value,
};

static ngx_chain_t *ngx_pg_write_uint8(ngx_pool_t *p, int32_t *len, uint8_t uint8) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(uint8)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    *cl->buf->last++ = uint8;
    if (len) *len += sizeof(uint8);
    return cl;
}

static ngx_chain_t *ngx_pg_alloc_size(ngx_pool_t *p, int32_t *size) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(*size)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (size) *size += sizeof(*size);
    return cl;
}

static ngx_chain_t *ngx_pg_exit(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *exit;
    int32_t size = 0;
    if (!(cl = exit = ngx_pg_write_uint8(p, NULL, 'X'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = exit; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return exit;
}

static void ngx_pg_save_cln_handler(ngx_pg_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_chain_t *out, *last;
    if (!(out = ngx_pg_exit(c->pool))) return;
    ngx_chain_writer_ctx_t ctx = { .out = out, .last = &last, .connection = c, .pool = c->pool, .limit = 0 };
    ngx_chain_writer(&ctx, NULL);
}

static ngx_chain_t *ngx_pg_write_str(ngx_pool_t *p, int32_t *size, size_t len, const u_char *str) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, len + sizeof(uint8_t)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (len) cl->buf->last = ngx_copy(cl->buf->last, str, len);
    *cl->buf->last++ = 0;
    if (size) *size += len + sizeof(uint8_t);
    return cl;
}

static ngx_chain_t *ngx_pg_write_byte(ngx_pool_t *p, int32_t *size, size_t len, const u_char *str) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, len))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (len) cl->buf->last = ngx_copy(cl->buf->last, str, len);
    if (size) *size += len;
    return cl;
}

static ngx_chain_t *ngx_pg_write_int16(ngx_pool_t *p, int32_t *size, int16_t int16) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(int16)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    cl->buf->last = pg_write_int(cl->buf->last, 2, int16);
    if (size) *size += sizeof(int16);
    return cl;
}

static ngx_chain_t *ngx_pg_write_int32(ngx_pool_t *p, int32_t *size, int32_t int32) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(int32)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    cl->buf->last = pg_write_int(cl->buf->last, 4, int32);
    if (size) *size += sizeof(int32);
    return cl;
}

static ngx_chain_t *ngx_pg_bind(ngx_http_request_t *r) {
    ngx_chain_t *cl, *cl_size, *bind;
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    ngx_pool_t *p = r->pool;
    int32_t size = 0;
    ngx_pg_arg_t *elts = plcf->arg->elts;
    if (!(cl = bind = ngx_pg_write_uint8(p, NULL, 'B'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (u_char *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (u_char *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int16(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int16(p, &size, plcf->arg->nelts))) return NULL;
    for (ngx_uint_t i = 0; i < plcf->arg->nelts; i++) {
        if (elts[i].complex.value.data) {
            ngx_str_t value;
            if (ngx_http_complex_value(r, &elts[i].complex, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "ngx_http_complex_value != NGX_OK"); return NULL; }
            if (!(cl = cl->next = ngx_pg_write_int32(p, &size, value.len))) return NULL;
            if (!(cl = cl->next = ngx_pg_write_byte(p, &size, value.len, value.data))) return NULL;
        } else {
            if (!(cl = cl->next = ngx_pg_write_int32(p, &size, -1))) return NULL;
        }
    }
    if (!(cl = cl->next = ngx_pg_write_int16(p, &size, 0))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = bind; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return bind;
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
        if (!(s->option = ngx_array_create(c->pool, 1, sizeof(ngx_pg_key_val_t)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_array_create"); return NGX_ERROR; }
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
        for (ngx_chain_t *cmd = plcf->flush; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
        d->ready++;
    }
    d->ready++;
    s->data = d;
    if (plcf->query) {
        for (ngx_chain_t *cmd = plcf->query; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
    } else if (plcf->parse) {
        for (ngx_chain_t *cmd = plcf->parse; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (cmd->next && !(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
        if (!(cl = cl->next = ngx_pg_bind(r))) return NGX_ERROR;
        while (cl->next) cl = cl->next;
        if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        for (ngx_chain_t *cmd = plcf->describe; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
        for (ngx_chain_t *cmd = plcf->execute; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
        for (ngx_chain_t *cmd = plcf->close; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
        for (ngx_chain_t *cmd = plcf->sync; cmd; cmd = cmd->next) {
            cl->buf = cmd->buf;
            ngx_buf_t *b = cl->buf;
            b->pos = b->start;
            if (!(cl = cl->next = ngx_alloc_chain_link(r->pool))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
        }
    } else { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!query && !parse"); return NGX_ERROR; }
    for (ngx_chain_t *cmd = plcf->flush; cmd; cmd = cmd->next) {
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

static void ngx_pg_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %i", state);
    ngx_pg_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    if (pc->connection) return;
    ngx_pg_srv_conf_t *pscf = d->conf;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "pscf = %p", pscf);
    if (!pscf) return;
    ngx_pg_save_t *s = d->save;
    s->data = NULL;
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
        if (!host.len) { ngx_http_core_loc_conf_t *clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module); ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty \"pg_pas\" (was: \"%V\") in location \"%V\"", &plcf->complex.value, &clcf->name); return NGX_ERROR; }
        if (!(u->resolved = ngx_pcalloc(r->pool, sizeof(*u->resolved)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        u->resolved->host = host;
        u->resolved->no_port = 1;
    }
    return NGX_OK;
}

static void ngx_pg_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
}

static ngx_int_t ngx_pg_add_response(ngx_http_request_t *r, size_t len, const u_char *str) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_event_pipe_t *p = u->pipe;
    ngx_chain_t *cl, **ll;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
    if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_chain_get_free_buf"); return NGX_ERROR; }
    *ll = cl;
    if (p->in) *p->last_in = cl; else p->in = cl;
    p->last_in = &cl->next;
    ngx_buf_t *b = cl->buf;
    b->flush = 1;
    b->last = str + len;
    b->memory = 1;
    b->pos = str;
    b->tag = u->output.tag;
    b->temporary = 1;
    u->headers_in.content_length_n += len;
    return NGX_OK;
}

static ngx_int_t ngx_pg_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    ngx_buf_t *b = &u->buffer;
//    ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i:%i:%c", i++, *p, *p);
    s->rc = NGX_OK;
    while (b->pos < b->last && s->rc == NGX_OK) b->pos += pg_parser_execute(s->parser, (const char *)b->pos, (const char *)b->last);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %i", s->rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos == b->last = %s", b->pos == b->last ? "true" : "false");
    if (s->rc == NGX_OK) {
        char buf[1];
        ngx_connection_t *c = s->connection;
        s->rc = d->ready || s->state == ngx_pg_state_unknown || recv(c->fd, buf, 1, MSG_PEEK) > 0 ? NGX_AGAIN : NGX_OK;
    }
    if (b->pos == b->last) b->pos = b->last = b->start;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %i", s->rc);
    if (s->rc == NGX_OK && d->error && d->error->nelts) s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
    if (s->rc == NGX_OK) {
        u->headers_in.content_length_n = 0;
        u->headers_in.status_n = NGX_HTTP_OK;
        if (d->row) {
            ngx_pg_row_t *elts = d->row->elts;
            for (ngx_uint_t i = 0; i < d->row->nelts; i++) {
                if (i && ngx_pg_add_response(r, sizeof("\n") - 1, (u_char *)"\n") != NGX_OK) return NGX_ERROR;
                ngx_str_t *str = elts[i].str->elts;
                for (ngx_uint_t j = 0; j < elts[i].str->nelts; j++) {
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%i,%i:%V", i, j, &str[j]);
                    if (j && ngx_pg_add_response(r, sizeof("\t") - 1, (u_char *)"\t") != NGX_OK) return NGX_ERROR;
                    if (!str[j].data) {
                        if (ngx_pg_add_response(r, sizeof("\\N") - 1, (u_char *)"\\N") != NGX_OK) return NGX_ERROR;
                    } else {
                        if (ngx_pg_add_response(r, str[j].len, str[j].data) != NGX_OK) return NGX_ERROR;
                    }
                }
            }
        }
        u->keepalive = !u->headers_in.connection_close;
    }
    return s->rc;
}

static ngx_int_t ngx_pg_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return NGX_OK;
}

static ngx_int_t ngx_pg_pipe_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, p->log, 0, "%s", __func__);
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter_init(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    u->length = 0;
    u->pipe->length = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter(ngx_http_request_t *r, ssize_t bytes) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bytes = %i", bytes);
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
    return NGX_CONF_OK;
}

static ngx_int_t ngx_pg_pid_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    v->len = snprintf(NULL, 0, "%i", s->pid);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", s->pid) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_err_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    if (!d->error) return NGX_OK;
    ngx_pg_key_val_t *elts = d->error->elts;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_uint_t i;
    for (i = 0; i < d->error->nelts; i++) if (name->len - sizeof("pg_err_") + 1 == elts[i].key.len && !ngx_strncasecmp(name->data + sizeof("pg_err_") - 1, elts[i].key.data, elts[i].key.len)) break;
    if (i == d->error->nelts) return NGX_OK;
    v->data = elts[i].val.data;
    v->len = elts[i].val.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_opt_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!s->option) return NGX_OK;
    ngx_pg_key_val_t *elts = s->option->elts;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_uint_t i;
    for (i = 0; i < s->option->nelts; i++) if (name->len - sizeof("pg_opt_") + 1 == elts[i].key.len && !ngx_strncasecmp(name->data + sizeof("pg_opt_") - 1, elts[i].key.data, elts[i].key.len)) break;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", i == s->option->nelts ? "true" : "false");
    if (i == s->option->nelts) return NGX_OK;
    v->data = elts[i].val.data;
    v->len = elts[i].val.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_mod_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_mod_") - 1, name->len - sizeof("pg_mod_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->col || i >= d->col->nelts) return NGX_OK;
    ngx_pg_col_t *elts = d->col->elts;
    v->len = snprintf(NULL, 0, "%i", elts[i].mod);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", elts[i].mod) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_columnid_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_columnid_") - 1, name->len - sizeof("pg_columnid_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->col || i >= d->col->nelts) return NGX_OK;
    ngx_pg_col_t *elts = d->col->elts;
    v->len = snprintf(NULL, 0, "%i", elts[i].columnid);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", elts[i].columnid) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_cmd_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    v->data = d->command.data;
    v->len = d->command.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_format_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_format_") - 1, name->len - sizeof("pg_format_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->col || i >= d->col->nelts) return NGX_OK;
    ngx_pg_col_t *elts = d->col->elts;
    v->len = snprintf(NULL, 0, "%i", elts[i].format);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", elts[i].format) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_ncols_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    v->len = snprintf(NULL, 0, "%i", d->ncols);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", d->ncols) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_name_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_name_") - 1, name->len - sizeof("pg_name_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->col || i >= d->col->nelts) return NGX_OK;
    ngx_pg_col_t *elts = d->col->elts;
    v->data = elts[i].name.data;
    v->len = elts[i].name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_tableid_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_tableid_") - 1, name->len - sizeof("pg_tableid_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->col || i >= d->col->nelts) return NGX_OK;
    ngx_pg_col_t *elts = d->col->elts;
    v->len = snprintf(NULL, 0, "%i", elts[i].tableid);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", elts[i].tableid) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_oid_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_oid_") - 1, name->len - sizeof("pg_oid_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->col || i >= d->col->nelts) return NGX_OK;
    ngx_pg_col_t *elts = d->col->elts;
    v->len = snprintf(NULL, 0, "%i", elts[i].oid);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", elts[i].oid) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_oidlen_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_oidlen_") - 1, name->len - sizeof("pg_oidlen_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->col || i >= d->col->nelts) return NGX_OK;
    ngx_pg_col_t *elts = d->col->elts;
    v->len = snprintf(NULL, 0, "%i", elts[i].oidlen);
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_snprintf(v->data, v->len, "%i", elts[i].oidlen) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_pg_row_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_str_t *name = (ngx_str_t *)data;
    u_char *c = ngx_strlchr(name->data + sizeof("pg_row_") - 1, name->data + name->len, '_');
    if (!c) return NGX_OK;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%*s", c - name->data - sizeof("pg_row_") + 1, name->data + sizeof("pg_row_") - 1);
    ngx_int_t n = ngx_atoi(name->data + sizeof("pg_row_") - 1, c - name->data - sizeof("pg_row_") + 1);
    if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t i = n;
    if (!d->row || i >= d->row->nelts) return NGX_OK;
    ngx_pg_row_t *elts = d->row->elts;
    ngx_pg_row_t *row = &elts[i];
    ngx_int_t m = ngx_atoi(c + 1, name->data + name->len - c - 1);
    if (m == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NGX_ERROR; }
    ngx_uint_t j = m;
    if (!row->str || j >= row->str->nelts) return NGX_OK;
    ngx_str_t *str = row->str->elts;
    v->len = str[j].len;
    v->data = str[j].data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static const ngx_http_variable_t ngx_pg_variables[] = {
  { ngx_string("pg_cmd"), NULL, ngx_pg_cmd_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_columnid_"), NULL, ngx_pg_columnid_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_err_"), NULL, ngx_pg_err_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_format_"), NULL, ngx_pg_format_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_mod_"), NULL, ngx_pg_mod_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_name_"), NULL, ngx_pg_name_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_ncols"), NULL, ngx_pg_ncols_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_oidlen_"), NULL, ngx_pg_oidlen_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_oid_"), NULL, ngx_pg_oid_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_opt_"), NULL, ngx_pg_opt_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_pid"), NULL, ngx_pg_pid_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_row_"), NULL, ngx_pg_row_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
  { ngx_string("pg_tableid_"), NULL, ngx_pg_tableid_get_handler, 0, NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_PREFIX, 0 },
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

static ngx_chain_t *ngx_pg_write_opt(ngx_pool_t *p, int32_t *size, size_t len, const u_char *str) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, len + sizeof(uint8_t)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    for (ngx_uint_t i = 0; i < len; i++) *cl->buf->last++ = str[i] == '=' ? 0 : str[i];
    *cl->buf->last++ = 0;
    if (size) *size += len + sizeof(uint8_t);
    return cl;
}

static char *ngx_pg_connect(ngx_conf_t *cf, ngx_command_t *cmd, ngx_chain_t **connect) {
    ngx_chain_t *cl, *cl_size;
    int32_t size = 0;
    if (!(cl = cl_size = *connect = ngx_pg_alloc_size(cf->pool, &size))) return NGX_CONF_ERROR;
    if (!(cl = cl->next = ngx_pg_write_int32(cf->pool, &size, 0x00030000))) return NGX_CONF_ERROR;
    ngx_str_t *elts = cf->args->elts;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) if (!(cl = cl->next = ngx_pg_write_opt(cf->pool, &size, elts[i].len, elts[i].data))) return NGX_CONF_ERROR;
    if (!(cl = cl->next = ngx_pg_write_uint8(cf->pool, &size, 0))) return NGX_CONF_ERROR;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = *connect; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%i:%i:%c", i++, *p, *p);
    return NGX_CONF_OK;
}

static char *ngx_pg_con_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->connect) return "duplicate";
    return ngx_pg_connect(cf, cmd, &plcf->connect);
}

static char *ngx_pg_con_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    if (pscf->connect) return "duplicate";
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    return ngx_pg_connect(cf, cmd, &pscf->connect);
}

static char *ngx_pg_log_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_log_set_log(cf, &pscf->log);
}

static char *ngx_pg_pas_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
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

static ngx_chain_t *ngx_pg_query(ngx_pool_t *p, size_t len, const u_char *str) {
    ngx_chain_t *cl, *cl_size, *query;
    int32_t size = 0;
    if (!(cl = query = ngx_pg_write_uint8(p, NULL, 'Q'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, str))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = query; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return query;
}

static ngx_chain_t *ngx_pg_parse(ngx_pool_t *p, size_t len, const u_char *str, ngx_array_t *arg) {
    ngx_chain_t *cl, *cl_size, *parse;
    int32_t size = 0;
    if (!(cl = parse = ngx_pg_write_uint8(p, NULL, 'P'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (u_char *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, str))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int16(p, &size, arg->nelts))) return NULL;
    ngx_pg_arg_t *elts = arg->elts;
    for (ngx_uint_t i = 0; i < arg->nelts; i++) if (!(cl = cl->next = ngx_pg_write_int32(p, &size, elts[i].type))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = parse; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return parse;
}

static ngx_chain_t *ngx_pg_describe(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *describe;
    int32_t size = 0;
    if (!(cl = describe = ngx_pg_write_uint8(p, NULL, 'D'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint8(p, &size, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (u_char *)""))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = describe; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return describe;
}

static ngx_chain_t *ngx_pg_execute(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *execute;
    int32_t size = 0;
    if (!(cl = execute = ngx_pg_write_uint8(p, NULL, 'E'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (u_char *)""))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int32(p, &size, 0))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = execute; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return execute;
}

static ngx_chain_t *ngx_pg_flush(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *flush;
    int32_t size = 0;
    if (!(cl = flush = ngx_pg_write_uint8(p, NULL, 'H'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = flush; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return flush;
}

static ngx_chain_t *ngx_pg_close(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *close;
    int32_t size = 0;
    if (!(cl = close = ngx_pg_write_uint8(p, NULL, 'C'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_uint8(p, &size, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("") - 1, (u_char *)""))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = close; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return close;
}

static ngx_chain_t *ngx_pg_sync(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *sync;
    int32_t size = 0;
    if (!(cl = sync = ngx_pg_write_uint8(p, NULL, 'S'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl_size->buf->last = pg_write_int(cl_size->buf->last, 4, size);
    cl->next = NULL;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = sync; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_error(NGX_LOG_ERR, p->log, 0, "%i:%i:%c", i++, *c, *c);
    return sync;
}

static char *ngx_pg_sql_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->query || plcf->parse) return "duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (!(plcf->flush = ngx_pg_flush(cf->pool))) return NGX_CONF_ERROR;
    if (plcf->arg) {
        if (!(plcf->close = ngx_pg_close(cf->pool))) return NGX_CONF_ERROR;
        if (!(plcf->describe = ngx_pg_describe(cf->pool))) return NGX_CONF_ERROR;
        if (!(plcf->execute = ngx_pg_execute(cf->pool))) return NGX_CONF_ERROR;
        if (!(plcf->parse = ngx_pg_parse(cf->pool, elts[1].len, elts[1].data, plcf->arg))) return NGX_CONF_ERROR;
        if (!(plcf->sync = ngx_pg_sync(cf->pool))) return NGX_CONF_ERROR;
    } else {
        if (!(plcf->query = ngx_pg_query(cf->pool, elts[1].len, elts[1].data))) return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_arg_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    ngx_pg_arg_t *arg;
    if (!plcf->arg && !(plcf->arg = ngx_array_create(cf->pool, 1, sizeof(*arg)))) return "!ngx_array_create";
    if (!(arg = ngx_array_push(plcf->arg))) return "!ngx_array_push";
    ngx_memzero(arg, sizeof(*arg));
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].len != sizeof("NULL") - 1 || ngx_strncasecmp(elts[1].data, "NULL", sizeof("NULL") - 1)) {
        ngx_http_compile_complex_value_t ccv = {cf, &elts[1], &arg->complex, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    }
    if (cf->args->nelts <= 2) return NGX_CONF_OK;
    ngx_int_t n = ngx_atoi(elts[2].data, elts[2].len);
    if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
    arg->type = n;
    return NGX_CONF_OK;
}

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
  { ngx_string("pg_arg"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_arg_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_con"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_con_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_con"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_con_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_log"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_log_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_pas"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1, ngx_pg_pas_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_sql"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1, ngx_pg_sql_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_upstream_connect_timeout"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_msec_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.connect_timeout), NULL },
  { ngx_string("pg_upstream_next_upstream"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.next_upstream), &ngx_pg_next_upstream_masks },
  { ngx_string("pg_upstream_pass_request_body"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.pass_request_body), NULL },
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
