#include <ngx_http.h>
#include <ngx_md5.h>
#include "pg_fsm.h"

#define CANCEL_REQUEST_CODE PG_PROTOCOL(1234,5678)
#define NEGOTIATE_GSS_CODE PG_PROTOCOL(1234,5680)
#define NEGOTIATE_SSL_CODE PG_PROTOCOL(1234,5679)
#define PG_PROTOCOL_EARLIEST PG_PROTOCOL(3,0)
#define PG_PROTOCOL_LATEST PG_PROTOCOL(3,0)
#define PG_PROTOCOL_MAJOR(v) ((v) >> 16)
#define PG_PROTOCOL_MINOR(v) ((v) & 0x0000ffff)
#define PG_PROTOCOL(m,n) (((m) << 16) | (n))

extern ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool) __attribute__((weak));
extern ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool) __attribute__((weak));

ngx_module_t ngx_pg_module;

enum {
    ngx_pg_type_execute = 1 << 0,
    ngx_pg_type_function = 1 << 1,
    ngx_pg_type_location = 1 << 2,
    ngx_pg_type_output = 1 << 3,
    ngx_pg_type_parse = 1 << 4,
    ngx_pg_type_query = 1 << 5,
    ngx_pg_type_upstream = 1 << 6,
};

typedef enum {
    ngx_pg_output_type_csv = 2,
    ngx_pg_output_type_none = 0,
    ngx_pg_output_type_plain = 3,
    ngx_pg_output_type_value = 1,
} ngx_pg_output_type_t;

#if (NGX_HTTP_SSL)
typedef enum {
    ngx_pg_ssl_disable = 0,
    ngx_pg_ssl_prefer,
    ngx_pg_ssl_require,
} ngx_pg_ssl_t;
#endif

typedef struct {
    struct {
        ngx_int_t index;
        uint32_t value;
    } oid;
    struct {
        ngx_int_t index;
        ngx_str_t str;
    } value;
} ngx_pg_argument_t;

typedef struct {
    ngx_int_t index;
    ngx_str_t str;
} ngx_pg_command_t;

typedef struct {
    ngx_flag_t header;
    ngx_flag_t string;
    ngx_int_t index;
    ngx_pg_output_type_t type;
    ngx_str_t null;
    u_char delimiter;
    u_char escape;
    u_char quote;
} ngx_pg_output_t;

typedef struct {
    ngx_array_t arguments;
    ngx_array_t commands;
    ngx_pg_output_t output;
    ngx_uint_t type;
    struct {
        ngx_int_t index;
        uint32_t oid;
    } function;
    struct {
        ngx_int_t index;
        ngx_str_t str;
    } name;
} ngx_pg_query_t;

typedef struct {
    ngx_array_t options;
#if (NGX_HTTP_SSL)
    ngx_pg_ssl_t sslmode;
#endif
    ngx_str_t password;
    ngx_str_t username;
} ngx_pg_connect_t;

typedef struct {
    ngx_array_t queries;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t upstream;
#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t cache_key;
#endif
#if (NGX_HTTP_SSL)
    ngx_array_t *ssl_conf_commands;
    ngx_str_t ssl_ciphers;
    ngx_str_t ssl_crl;
    ngx_str_t ssl_trusted_certificate;
    ngx_uint_t ssl_protocols;
    ngx_uint_t ssl_verify_depth;
#endif
    ngx_pg_connect_t connect;
} ngx_pg_loc_conf_t;

typedef struct {
    ngx_array_t caches;
} ngx_pg_main_conf_t;

typedef struct {
    ngx_array_t queries;
    ngx_http_upstream_peer_t peer;
    ngx_log_t *log;
    ngx_pg_connect_t connect;
} ngx_pg_srv_conf_t;

typedef struct {
    ngx_str_t all;
    ngx_str_t column;
    ngx_str_t constraint;
    ngx_str_t context;
    ngx_str_t datatype;
    ngx_str_t detail;
    ngx_str_t file;
    ngx_str_t function;
    ngx_str_t hint;
    ngx_str_t internal;
    ngx_str_t line;
    ngx_str_t nonlocalized;
    ngx_str_t primary;
    ngx_str_t query;
    ngx_str_t schema;
    ngx_str_t severity;
    ngx_str_t sqlstate;
    ngx_str_t statement;
    ngx_str_t table;
} ngx_pg_error_t;

typedef struct {
    ngx_str_t application_name;
    ngx_str_t client_encoding;
    ngx_str_t datestyle;
    ngx_str_t default_transaction_read_only;
    ngx_str_t in_hot_standby;
    ngx_str_t integer_datetimes;
    ngx_str_t intervalstyle;
    ngx_str_t is_superuser;
    ngx_str_t server_encoding;
    ngx_str_t server_version;
    ngx_str_t session_authorization;
    ngx_str_t standard_conforming_strings;
    ngx_str_t timezone;
} ngx_pg_option_t;

typedef struct ngx_pg_data_t ngx_pg_data_t;

typedef struct {
    ngx_int_t index;
    ngx_str_t value;
} ngx_pg_variable_t;

typedef struct {
    ngx_array_t channels;
    ngx_array_t variables;
    ngx_buf_t buffer;
    ngx_connection_t *connection;
    ngx_msec_t timeout;
    ngx_pg_data_t *data;
    ngx_pg_error_t error;
    ngx_pg_option_t option;
    ngx_uint_t rc;
    pg_fsm_t *fsm;
    uint32_t key;
    uint32_t len;
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

typedef struct {
    ngx_pg_query_t *query;
    ngx_queue_t queue;
} ngx_pg_query_queue_t;

typedef struct ngx_pg_data_t {
    ngx_buf_t *shadow;
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_pg_error_t error;
    ngx_pg_loc_conf_t *plcf;
    ngx_pg_option_t option;
    ngx_pg_query_t *query;
    ngx_pg_save_t *save;
    ngx_pg_srv_conf_t *pscf;
    ngx_queue_t queue;
    ngx_uint_t col;
    ngx_uint_t filter;
    ngx_uint_t row;
} ngx_pg_data_t;

static ngx_int_t ngx_pg_output_handler(ngx_pg_data_t *d, size_t len, const uint8_t *data) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%*s", (int)len, data);
    ngx_chain_t *cl;
    ngx_http_upstream_t *u = r->upstream;
    ngx_event_pipe_t *p = u->pipe;
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
    b->tag = u->output.tag;
    b->temporary = 1;
    if (u->buffering && d->shadow && !d->shadow->shadow) {
        b->last_shadow = 1;
        b->recycled = 1;
        b->shadow = d->shadow;
        d->shadow->shadow = b;
    }
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = u->out_bufs; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%ui:%d:%c", i++, *p, *p);
    return NGX_OK;
}

static ngx_chain_t *ngx_pg_alloc_size(ngx_pool_t *p, uint32_t *size) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(*size)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (size) *size += sizeof(*size);
    return cl;
}

static ngx_chain_t *ngx_pg_write_int1(ngx_pool_t *p, uint32_t *size, uint8_t c) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(c)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    *cl->buf->last++ = c;
    if (size) *size += sizeof(c);
    return cl;
}

static ngx_chain_t *ngx_pg_write_int2(ngx_pool_t *p, uint32_t *size, uint16_t n) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(n)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    for (uint8_t m = sizeof(uint16_t); m; *cl->buf->last++ = n >> (2 << 2) * --m);
    if (size) *size += sizeof(n);
    return cl;
}

static ngx_chain_t *ngx_pg_write_int4(ngx_pool_t *p, uint32_t *size, uint32_t n) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, sizeof(n)))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    for (uint8_t m = sizeof(uint32_t); m; *cl->buf->last++ = n >> (2 << 2) * --m);
    if (size) *size += sizeof(n);
    return cl;
}

static ngx_chain_t *ngx_pg_write_size(ngx_chain_t *cl, uint32_t size) {
    for (uint8_t m = sizeof(uint32_t); m; *cl->buf->last++ = size >> (2 << 2) * --m);
    return NULL;
}

static ngx_chain_t *ngx_pg_write_str(ngx_pool_t *p, uint32_t *size, size_t len, const uint8_t *data) {
    ngx_chain_t *cl;
    if (!(cl = ngx_alloc_chain_link(p))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_alloc_chain_link"); return NULL; }
    if (!(cl->buf = ngx_create_temp_buf(p, len))) { ngx_log_error(NGX_LOG_ERR, p->log, 0, "!ngx_create_temp_buf"); return NULL; }
    if (len) cl->buf->last = ngx_copy(cl->buf->last, data, len);
    if (size) *size += len;
    return cl;
}

static ngx_chain_t *ngx_pg_bind(ngx_pool_t *p, size_t len, const uint8_t *data, ngx_array_t *arguments) {
    ngx_chain_t *cl, *cl_size, *bind;
    uint32_t size = 0;
    if (!(cl = bind = ngx_pg_write_int1(p, NULL, 'B'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    if (len) if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, data))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, arguments->nelts))) return NULL;
    ngx_pg_argument_t *argument = arguments->elts;
    for (ngx_uint_t i = 0; i < arguments->nelts; i++) {
        if (argument[i].value.str.data) {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, argument[i].value.str.len))) return NULL;
            if (!(cl = cl->next = ngx_pg_write_str(p, &size, argument[i].value.str.len, argument[i].value.str.data))) return NULL;
        } else {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, -1))) return NULL;
        }
    }
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = bind; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return bind;
}

static ngx_chain_t *ngx_pg_cancel_request(ngx_pool_t *p, uint32_t pid, uint32_t key) {
    ngx_chain_t *cl, *cl_size, *cancel;
    uint32_t size = 0;
    if (!(cl = cl_size = cancel = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, CANCEL_REQUEST_CODE))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, pid))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, key))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = cancel; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return cancel;
}

static ngx_chain_t *ngx_pg_close(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *close;
    uint32_t size = 0;
    if (!(cl = close = ngx_pg_write_int1(p, NULL, 'C'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = close; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return close;
}

static ngx_chain_t *ngx_pg_describe(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *describe;
    uint32_t size = 0;
    if (!(cl = describe = ngx_pg_write_int1(p, NULL, 'D'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 'P'))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = describe; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return describe;
}

static ngx_chain_t *ngx_pg_execute(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *execute;
    uint32_t size = 0;
    if (!(cl = execute = ngx_pg_write_int1(p, NULL, 'E'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = execute; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return execute;
}

/*static ngx_chain_t *ngx_pg_terminate(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *exit;
    uint32_t size = 0;
    if (!(cl = exit = ngx_pg_write_int1(p, NULL, 'X'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = exit; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return exit;
}*/

static ngx_chain_t *ngx_pg_flush(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *flush;
    uint32_t size = 0;
    if (!(cl = flush = ngx_pg_write_int1(p, NULL, 'H'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = flush; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return flush;
}

static ngx_chain_t *ngx_pg_function_call(ngx_pool_t *p, uint32_t oid, ngx_array_t *arguments) {
    ngx_chain_t *cl, *cl_size, *function;
    uint32_t size = 0;
    if (!(cl = function = ngx_pg_write_int1(p, NULL, 'F'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, oid))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 1))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, arguments->nelts))) return NULL;
    ngx_pg_argument_t *argument = arguments->elts;
    for (ngx_uint_t i = 0; i < arguments->nelts; i++) {
        if (argument[i].value.str.data) {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, argument[i].value.str.len))) return NULL;
            if (!(cl = cl->next = ngx_pg_write_str(p, &size, argument[i].value.str.len, argument[i].value.str.data))) return NULL;
        } else {
            if (!(cl = cl->next = ngx_pg_write_int4(p, &size, -1))) return NULL;
        }
    }
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = function; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return function;
}

static ngx_chain_t *ngx_pg_command(ngx_pool_t *p, uint32_t *size, ngx_chain_t *cl, ngx_array_t *commands) {
    ngx_pg_command_t *command = commands->elts;
    for (ngx_uint_t i = 0; i < commands->nelts; i++) {
        if (command[i].index) {
            if (!(cl = cl->next = ngx_pg_write_int1(p, size, '"'))) return NULL;
            ngx_uint_t num_quotes = 0;
            u_char *b = command[i].str.data;
            u_char *e = command[i].str.data + command[i].str.len;
            for (u_char *s = b; s < e; s++) if (*s == '"') num_quotes++;
            if (!num_quotes) {
                if (!(cl = cl->next = ngx_pg_write_str(p, size, command[i].str.len, command[i].str.data))) return NULL;
            } else for (u_char *s = b; s < e; s++) {
                if (*s == '"') if (!(cl = cl->next = ngx_pg_write_int1(p, size, *s))) return NULL;
                if (!(cl = cl->next = ngx_pg_write_int1(p, size, *s))) return NULL;
            }
            if (!(cl = cl->next = ngx_pg_write_int1(p, size, '"'))) return NULL;
        } else {
            if (!(cl = cl->next = ngx_pg_write_str(p, size, command[i].str.len, command[i].str.data))) return NULL;
        }
    }
    if (!(cl = cl->next = ngx_pg_write_int1(p, size, 0))) return NULL;
    return cl;
}

static ngx_chain_t *ngx_pg_parse(ngx_pool_t *p, size_t len, const uint8_t *data, ngx_array_t *commands, ngx_array_t *arguments) {
    ngx_chain_t *cl, *cl_size, *parse;
    uint32_t size = 0;
    if (!(cl = parse = ngx_pg_write_int1(p, NULL, 'P'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (len) if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, data))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    if (!(cl = ngx_pg_command(p, &size, cl, commands))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int2(p, &size, arguments->nelts))) return NULL;
    ngx_pg_argument_t *argument = arguments->elts;
    for (ngx_uint_t i = 0; i < arguments->nelts; i++) if (!(cl = cl->next = ngx_pg_write_int4(p, &size, argument[i].oid.value))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = parse; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return parse;
}

static ngx_chain_t *ngx_pg_password_message(ngx_pool_t *p, size_t len, const uint8_t *data) {
    ngx_chain_t *cl, *cl_size, *password;
    uint32_t size = 0;
    if (!(cl = password = ngx_pg_write_int1(p, NULL, 'p'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, data))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = password; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return password;
}

static ngx_chain_t *ngx_pg_query(ngx_pool_t *p, ngx_array_t *commands) {
    ngx_chain_t *cl, *cl_size, *query;
    uint32_t size = 0;
    if (!(cl = query = ngx_pg_write_int1(p, NULL, 'Q'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = ngx_pg_command(p, &size, cl, commands))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = query; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return query;
}

/*static ngx_chain_t *ngx_pg_sasl_initial_response_scram_sha_256(ngx_pool_t *p, uint32_t len, const uint8_t *data) {
    ngx_chain_t *cl, *cl_size, *sasl;
    uint32_t size = 0;
    if (!(cl = sasl = ngx_pg_write_int1(p, NULL, 'p'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_str(p, &size, sizeof("SCRAM-SHA-256") - 1, (uint8_t *)"SCRAM-SHA-256"))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, len))) return NULL;
    if (len != (uint32_t)-1) if (!(cl = cl->next = ngx_pg_write_str(p, &size, len, data))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = sasl; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return sasl;
}*/

#if (NGX_HTTP_SSL)
static ngx_chain_t *ngx_pg_ssl_request(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *ssl;
    uint32_t size = 0;
    if (!(cl = cl_size = ssl = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, NEGOTIATE_SSL_CODE))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = ssl; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return ssl;
}
#endif

static ngx_chain_t *ngx_pg_startup_message(ngx_pool_t *p, ngx_array_t *options) {
    ngx_chain_t *cl, *cl_size, *connect;
    uint32_t size = 0;
    if (!(cl = cl_size = connect = ngx_pg_alloc_size(p, &size))) return NULL;
    if (!(cl = cl->next = ngx_pg_write_int4(p, &size, PG_PROTOCOL_LATEST))) return NULL;
    if (options) {
        ngx_str_t *str = options->elts;
        for (ngx_uint_t i = 0; i < options->nelts; i++) {
            if (!(cl = cl->next = ngx_pg_write_str(p, &size, str[i].len, str[i].data))) return NULL;
            if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
        }
    }
    if (!(cl = cl->next = ngx_pg_write_int1(p, &size, 0))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = *connect; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return connect;
}

static ngx_chain_t *ngx_pg_sync(ngx_pool_t *p) {
    ngx_chain_t *cl, *cl_size, *sync;
    uint32_t size = 0;
    if (!(cl = sync = ngx_pg_write_int1(p, NULL, 'S'))) return NULL;
    if (!(cl = cl->next = cl_size = ngx_pg_alloc_size(p, &size))) return NULL;
    cl->next = ngx_pg_write_size(cl_size, size);
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = sync; cl; cl = cl->next) for (u_char *c = cl->buf->pos; c < cl->buf->last; c++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, p->log, 0, "%ui:%d:%c", i++, *c, *c);
    return sync;
}

static ngx_chain_t *ngx_pg_queries(ngx_pg_data_t *d, ngx_array_t *queries) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_chain_t *cl = NULL, *cl_query = NULL;
    ngx_pg_query_t *query = queries->elts;
    for (ngx_uint_t i = 0; i < queries->nelts; i++) {
        ngx_pg_argument_t *argument = query[i].arguments.elts;
        for (ngx_uint_t j = 0; j < query[i].arguments.nelts; j++) {
            if (argument[j].oid.index) {
                ngx_http_variable_value_t *value;
                if (!(value = ngx_http_get_indexed_variable(r, argument[j].oid.index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NULL; }
                ngx_int_t n = ngx_atoi(value->data, value->len);
                if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NULL; }
                argument[j].oid.value = n;
            }
            if (argument[j].value.index) {
                ngx_http_variable_value_t *value;
                if (!(value = ngx_http_get_indexed_variable(r, argument[j].value.index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NULL; }
                argument[j].value.str.data = value->data;
                argument[j].value.str.len = value->len;
            }
        }
        ngx_pg_command_t *command = query[i].commands.elts;
        for (ngx_uint_t j = 0; j < query[i].commands.nelts; j++) if (command[j].index) {
            ngx_http_variable_value_t *value;
            if (!(value = ngx_http_get_indexed_variable(r, command[j].index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NULL; }
            command[j].str.data = value->data;
            command[j].str.len = value->len;
        }
        if (query[i].type & ngx_pg_type_function) {
            if (query[i].function.index) {
                ngx_http_variable_value_t *value;
                if (!(value = ngx_http_get_indexed_variable(r, query[i].function.index))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_get_indexed_variable"); return NULL; }
                ngx_int_t n = ngx_atoi(value->data, value->len);
                if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_atoi == NGX_ERROR"); return NULL; }
                query[i].function.oid = n;
            }
            if (cl) {
                if (!(cl->next = ngx_pg_function_call(r->pool, query[i].function.oid, &query[i].arguments))) return NULL;
            } else {
                if (!(cl = cl_query = ngx_pg_function_call(r->pool, query[i].function.oid, &query[i].arguments))) return NULL;
            }
            while (cl->next) cl = cl->next;
            ngx_pg_query_queue_t *qq;
            if (!(qq = ngx_pcalloc(r->pool, sizeof(*qq)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NULL; }
            ngx_queue_insert_tail(&d->queue, &qq->queue);
            qq->query = &query[i];
        } else {
            if (query[i].type & ngx_pg_type_query || query[i].type & ngx_pg_type_parse) {
                if (cl) {
                    if (!(cl->next = ngx_pg_parse(r->pool, query[i].name.str.len, query[i].name.str.data, &query[i].commands, &query[i].arguments))) return NULL;
                } else {
                    if (!(cl = cl_query = ngx_pg_parse(r->pool, query[i].name.str.len, query[i].name.str.data, &query[i].commands, &query[i].arguments))) return NULL;
                }
                while (cl->next) cl = cl->next;
                ngx_pg_query_queue_t *qq;
                if (!(qq = ngx_pcalloc(r->pool, sizeof(*qq)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NULL; }
                ngx_queue_insert_tail(&d->queue, &qq->queue);
                qq->query = &query[i];
            }
            if (query[i].type & ngx_pg_type_query || query[i].type & ngx_pg_type_execute) {
                if (cl) {
                    if (!(cl->next = ngx_pg_bind(r->pool, query[i].name.str.len, query[i].name.str.data, &query[i].arguments))) return NULL;
                } else {
                    if (!(cl = cl_query = ngx_pg_bind(r->pool, query[i].name.str.len, query[i].name.str.data, &query[i].arguments))) return NULL;
                }
                while (cl->next) cl = cl->next;
                if (!(cl->next = ngx_pg_describe(r->pool))) return NULL;
                while (cl->next) cl = cl->next;
                if (!(cl->next = ngx_pg_execute(r->pool))) return NULL;
                while (cl->next) cl = cl->next;
                ngx_pg_query_queue_t *qq;
                if (!(qq = ngx_pcalloc(r->pool, sizeof(*qq)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NULL; }
                ngx_queue_insert_tail(&d->queue, &qq->queue);
                qq->query = &query[i];
            }
        }
    }
    if (!(cl->next = ngx_pg_close(r->pool))) return NULL;
    while (cl->next) cl = cl->next;
    if (!(cl->next = ngx_pg_sync(r->pool))) return NULL;
    while (cl->next) cl = cl->next;
    if (!(cl->next = ngx_pg_flush(r->pool))) return NULL;
    return cl_query;
}

static int ngx_pg_fsm_all(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d:%c", *data, *data);
    return s->rc;
}

static int ngx_pg_fsm_authentication_cleartext_password(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_loc_conf_t *plcf = d->plcf;
    ngx_pg_srv_conf_t *pscf = d->pscf;
    ngx_str_t password = pscf ? pscf->connect.password : plcf->connect.password;
    if (!password.data) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!password"); s->rc = NGX_ERROR; return s->rc; }
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    if (!(u->request_bufs = ngx_pg_password_message(r->pool, password.len, password.data))) { s->rc = NGX_ERROR; return s->rc; }
    u->request_sent = 0;
    u->write_event_handler(r, u);
    ngx_connection_t *c = r->connection;
    ngx_http_run_posted_requests(c);
    return s->rc;
}

#define MD5_DIGEST_LENGTH 16
#define MD5_HEX_LENGTH 32

static int ngx_pg_fsm_authentication_md5_password(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    for (u_char *p = data; p < data + len; p++) ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d:%c", *p, *p);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_loc_conf_t *plcf = d->plcf;
    ngx_pg_srv_conf_t *pscf = d->pscf;
    ngx_str_t password = pscf ? pscf->connect.password : plcf->connect.password;
    if (!password.data) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!password"); s->rc = NGX_ERROR; return s->rc; }
    ngx_str_t username = pscf ? pscf->connect.username : plcf->connect.username;
    ngx_md5_t md5;
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, password.data, password.len);
    ngx_md5_update(&md5, username.data, username.len);
    u_char digest[MD5_DIGEST_LENGTH];
    ngx_md5_final(digest, &md5);
    u_char hex[3 + MD5_HEX_LENGTH];
    hex[0] = 'm'; hex[1] = 'd'; hex[2] = '5';
    (void)ngx_hex_dump(hex + 3, digest, MD5_DIGEST_LENGTH);
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, hex + 3, MD5_HEX_LENGTH);
    ngx_md5_update(&md5, data, len);
    ngx_md5_final(digest, &md5);
    (void)ngx_hex_dump(hex + 3, digest, MD5_DIGEST_LENGTH);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", 3 + MD5_HEX_LENGTH, hex);
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    if (!(u->request_bufs = ngx_pg_password_message(r->pool, 3 + MD5_HEX_LENGTH, hex))) { s->rc = NGX_ERROR; return s->rc; }
    u->request_sent = 0;
    u->write_event_handler(r, u);
    ngx_connection_t *c = r->connection;
    ngx_http_run_posted_requests(c);
    return s->rc;
}

static int ngx_pg_fsm_authentication_ok(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_pg_loc_conf_t *plcf = d->plcf;
    ngx_pg_srv_conf_t *pscf = d->pscf;
    if (!(u->request_bufs = ngx_pg_queries(d, pscf && pscf->queries.elts ? &pscf->queries : &plcf->queries))) { s->rc = NGX_ERROR; return s->rc; }
    u->request_sent = 0;
    u->write_event_handler(r, u);
    ngx_connection_t *c = r->connection;
    ngx_http_run_posted_requests(c);
    return s->rc;
}

static int ngx_pg_fsm_backend_key_data(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static int ngx_pg_fsm_backend_key_data_key(ngx_pg_save_t *s, uint32_t key) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", key);
    s->key = key;
    return s->rc;
}

static int ngx_pg_fsm_backend_key_data_pid(ngx_pg_save_t *s, uint32_t pid) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", pid);
    s->pid = pid;
    return s->rc;
}

static int ngx_pg_fsm_bind_complete(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); s->rc = NGX_ERROR; return s->rc; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pg_query_queue_t *qq = ngx_queue_data(q, ngx_pg_query_queue_t, queue);
    ngx_pg_query_t *query = d->query = qq->query;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_close_complete(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static int ngx_pg_fsm_command_complete(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    return s->rc;
}

static int ngx_pg_fsm_command_complete_val(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (ngx_http_push_stream_delete_channel_my && query->commands.nelts == 2 && len == sizeof("LISTEN") - 1 && !ngx_strncasecmp(data, (u_char *)"LISTEN", sizeof("LISTEN") - 1)) {
        ngx_pg_command_t *command = query->commands.elts;
        command = &command[1];
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%V", &command->str);
        ngx_str_t *channel;
        ngx_connection_t *c = s->connection;
        if (!s->channels.elts && ngx_array_init(&s->channels, c->pool, 1, sizeof(*channel)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_array_init != NGX_OK"); s->rc = NGX_ERROR; return s->rc; }
        if (!(channel = ngx_array_push(&s->channels))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
        ngx_memzero(channel, sizeof(*channel));
        if (!(channel->data = ngx_pstrdup(c->pool, &command->str))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pstrdup"); s->rc = NGX_ERROR; return s->rc; }
        channel->len = command->str.len;
    }
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    if (query->output.type > ngx_pg_output_type_value || d->row) return s->rc;
    if ((s->rc = ngx_pg_output_handler(d, len, data)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_copy_data(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (!d->filter++) s->rc = NGX_DONE;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    d->row++;
    return s->rc;
}

static int ngx_pg_fsm_copy_done(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static int ngx_pg_fsm_copy_out_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    return s->rc;
}

static int ngx_pg_fsm_data_row(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (!d->filter++) s->rc = NGX_DONE;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    d->col = 0;
    d->row++;
    if (d->row > 1 || query->output.header) if (ngx_pg_output_handler(d, sizeof("\n") - 1, (uint8_t *)"\n") == NGX_ERROR) { s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_data_row_count(ngx_pg_save_t *s, uint16_t count) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", count);
    return s->rc;
}

static int ngx_pg_fsm_empty_query_response(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static int ngx_pg_fsm_error(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    ngx_uint_t i = 0; for (u_char *p = data; p < data + len; p++) ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%ui:%d:%c", i++, *p, *p);
    s->rc = d && d->filter ? NGX_ERROR : NGX_HTTP_UPSTREAM_INVALID_HEADER;
    return s->rc;
}

static int ngx_pg_fsm_error_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    ngx_memzero(&s->error, sizeof(s->error));
    ngx_connection_t *c = s->connection;
    if (s->error.all.data) ngx_pfree(c->pool, s->error.all.data);
    if (!(s->error.all.data = ngx_pnalloc(c->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    u->headers_in.status_n = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); s->rc = NGX_ERROR; return s->rc; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pg_query_queue_t *qq = ngx_queue_data(q, ngx_pg_query_queue_t, queue);
    ngx_pg_query_t *query = d->query = qq->query;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_error_response_value(ngx_pg_save_t *s, size_t len, const uint8_t *data, const char *key, ngx_str_t *value) {
    if (!value->data) value->data = s->error.all.data + s->error.all.len;
    ngx_memcpy(value->data + value->len, data, len);
    value->len += len;
    s->error.all.len += len;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    if (u->headers_in.status_n == NGX_HTTP_INTERNAL_SERVER_ERROR) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s = %V", key, value); }
    else { ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0, "%s = %V", key, value); }
    return s->rc;
}

static int ngx_pg_fsm_error_response_column(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "column", &s->error.column);
}

static int ngx_pg_fsm_error_response_constraint(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "constraint", &s->error.constraint);
}

static int ngx_pg_fsm_error_response_context(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "context", &s->error.context);
}

static int ngx_pg_fsm_error_response_datatype(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "datatype", &s->error.datatype);
}

static int ngx_pg_fsm_error_response_detail(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "detail", &s->error.detail);
}

static int ngx_pg_fsm_error_response_file(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "file", &s->error.file);
}

static int ngx_pg_fsm_error_response_function(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "function", &s->error.function);
}

static int ngx_pg_fsm_error_response_hint(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "hint", &s->error.hint);
}

static int ngx_pg_fsm_error_response_internal(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "internal", &s->error.internal);
}

static int ngx_pg_fsm_error_response_line(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "line", &s->error.line);
}

static int ngx_pg_fsm_error_response_nonlocalized(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "nonlocalized", &s->error.nonlocalized);
}

static int ngx_pg_fsm_error_response_primary(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "primary", &s->error.primary);
}

static int ngx_pg_fsm_error_response_query(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "query", &s->error.query);
}

static int ngx_pg_fsm_error_response_schema(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "schema", &s->error.schema);
}

static int ngx_pg_fsm_error_response_severity(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "severity", &s->error.severity);
}

static int ngx_pg_fsm_error_response_sqlstate(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "sqlstate", &s->error.sqlstate);
}

static int ngx_pg_fsm_error_response_statement(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "statement", &s->error.statement);
}

static int ngx_pg_fsm_error_response_table(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_error_response_value(s, len, data, "table", &s->error.table);
}

static int ngx_pg_fsm_function_call_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); s->rc = NGX_ERROR; return s->rc; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pg_query_queue_t *qq = ngx_queue_data(q, ngx_pg_query_queue_t, queue);
    ngx_pg_query_t *query = d->query = qq->query;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (!d->filter++) s->rc = NGX_DONE;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    d->row++;
    return s->rc;
}

static int ngx_pg_fsm_no_data(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static int ngx_pg_fsm_notice_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    ngx_memzero(&s->error, sizeof(s->error));
    ngx_connection_t *c = s->connection;
    if (s->error.all.data) ngx_pfree(c->pool, s->error.all.data);
    if (!(s->error.all.data = ngx_pnalloc(c->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_notification_response(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    ngx_connection_t *c = s->connection;
    if (!(s->notification.relname.data = ngx_pnalloc(c->pool, len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_notification_response_done(ngx_pg_save_t *s) {
    s->notification.extra.data[s->notification.extra.len] = '\0';
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "extra = %V", &s->notification.extra);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "pid = %uD", s->notification.pid);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "relname = %V", &s->notification.relname);
    ngx_connection_t *c = s->connection;
    if (!ngx_http_push_stream_add_msg_to_channel_my) goto free;
    ngx_pool_t *p;
    if (!(p = ngx_create_pool(4096 + s->notification.relname.len + s->notification.extra.len, s->connection->log))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_create_pool"); s->rc = NGX_ERROR; goto free; }
    switch ((s->rc = ngx_http_push_stream_add_msg_to_channel_my(s->connection->log, &s->notification.relname, &s->notification.extra, NULL, NULL, 1, p))) {
        case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); break;
        case NGX_DECLINED: ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED"); {
            ngx_array_t commands;
            ngx_pg_command_t *command;
            if (ngx_array_init(&commands, p, 2, sizeof(*command)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_array_init != NGX_OK"); goto destroy; }
            if (!(command = ngx_array_push(&commands))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); goto destroy; }
            ngx_memzero(command, sizeof(*command));
            ngx_str_set(&command->str, "UNLISTEN ");
            if (!(command = ngx_array_push(&commands))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); goto destroy; }
            ngx_memzero(command, sizeof(*command));
            command->index = NGX_ERROR;
            command->str = s->notification.relname;
            ngx_chain_t *out, *last;
            if (!(out = ngx_pg_query(p, &commands))) goto destroy;
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
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", pid);
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
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    return s->rc;
}

static int ngx_pg_fsm_parameter_status_value(ngx_pg_save_t *s, size_t len, const uint8_t *data, ngx_str_t *value) {
    ngx_connection_t *c = s->connection;
    if (!value->data && !(value->data = ngx_pnalloc(c->pool, s->len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER; return s->rc; }
    ngx_memcpy(value->data + value->len, data, len);
    value->len += len;
    return s->rc;
}

static int ngx_pg_fsm_parameter_status_application_name(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.application_name);
}

static int ngx_pg_fsm_parameter_status_client_encoding(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.client_encoding);
}

static int ngx_pg_fsm_parameter_status_datestyle(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.datestyle);
}

static int ngx_pg_fsm_parameter_status_default_transaction_read_only(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.default_transaction_read_only);
}

static int ngx_pg_fsm_parameter_status_in_hot_standby(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.in_hot_standby);
}

static int ngx_pg_fsm_parameter_status_integer_datetimes(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.integer_datetimes);
}

static int ngx_pg_fsm_parameter_status_intervalstyle(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.intervalstyle);
}

static int ngx_pg_fsm_parameter_status_is_superuser(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.is_superuser);
}

static int ngx_pg_fsm_parameter_status_server_encoding(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.server_encoding);
}

static int ngx_pg_fsm_parameter_status_server_version(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.server_version);
}

static int ngx_pg_fsm_parameter_status_session_authorization(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.session_authorization);
}

static int ngx_pg_fsm_parameter_status_standard_conforming_strings(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.standard_conforming_strings);
}

static int ngx_pg_fsm_parameter_status_timezone(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    return ngx_pg_fsm_parameter_status_value(s, len, data, &s->option.timezone);
}

static int ngx_pg_fsm_parse_complete(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    if (ngx_queue_empty(&d->queue)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_queue_empty"); s->rc = NGX_ERROR; return s->rc; }
    ngx_queue_t *q = ngx_queue_head(&d->queue);
    ngx_queue_remove(q);
    ngx_pg_query_queue_t *qq = ngx_queue_data(q, ngx_pg_query_queue_t, queue);
    ngx_pg_query_t *query = d->query = qq->query;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_ready_for_query(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return s->rc;
}

static int ngx_pg_fsm_ready_for_query_state(ngx_pg_save_t *s, uint16_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%d", state);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_upstream)) return s->rc;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_pg_loc_conf_t *plcf = d->plcf;
    if (!(u->request_bufs = ngx_pg_queries(d, &plcf->queries))) { s->rc = NGX_ERROR; return s->rc; }
    u->request_sent = 0;
    u->write_event_handler(r, u);
    ngx_connection_t *c = r->connection;
    ngx_http_run_posted_requests(c);
    return s->rc;
}

static int ngx_pg_fsm_result_done(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    if (query->output.string && query->output.quote) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.quote), &query->output.quote)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_result_len(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    d->col++;
    if (d->col > 1) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.delimiter), &query->output.delimiter)) != NGX_OK) return s->rc;
    if (len == (uint32_t)-1) {
        if (query->output.null.len) if ((s->rc = ngx_pg_output_handler(d, query->output.null.len, query->output.null.data)) != NGX_OK) return s->rc;
    } else {
        if (query->output.string && query->output.quote) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.quote), &query->output.quote)) != NGX_OK) return s->rc;
    }
    return s->rc;
}

static int ngx_pg_fsm_result_val(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (query->type & ngx_pg_type_upstream) {
        if (query->output.index) {
            ngx_pg_variable_t *variable;
            ngx_connection_t *c = s->connection;
            if (!s->variables.elts && ngx_array_init(&s->variables, c->pool, 1, sizeof(*variable)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_array_init != NGX_OK"); s->rc = NGX_ERROR; return s->rc; }
            if (!(variable = ngx_array_push(&s->variables))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); s->rc = NGX_ERROR; return s->rc; }
            ngx_memzero(variable, sizeof(*variable));
            if (!(variable->value.data = ngx_pnalloc(c->pool, variable->value.len = len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); s->rc = NGX_ERROR; return s->rc; }
            (void)ngx_copy(variable->value.data, data, len);
            variable->index = query->output.index;
        }
        return s->rc;
    }
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    if (query->output.type > ngx_pg_output_type_value && query->output.string && query->output.quote && query->output.escape) for (ngx_uint_t k = 0; k < len; k++) {
        if (data[k] == query->output.quote) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.escape), &query->output.escape)) != NGX_OK) return s->rc;
        if ((s->rc = ngx_pg_output_handler(d, sizeof(data[k]), &data[k])) != NGX_OK) return s->rc;
    } else if (query->output.type > ngx_pg_output_type_none) {
        if ((s->rc = ngx_pg_output_handler(d, len, data)) != NGX_OK) return s->rc;
    }
    return s->rc;
}

static int ngx_pg_fsm_row_description(ngx_pg_save_t *s, uint32_t len) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", len);
    s->len = len;
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (!d->filter++) s->rc = NGX_DONE;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    d->col = 0;
    if (!query->output.header) return s->rc;
    if (d->row > 1) if (ngx_pg_output_handler(d, sizeof("\n") - 1, (uint8_t *)"\n") == NGX_ERROR) { s->rc = NGX_ERROR; return s->rc; }
    return s->rc;
}

static int ngx_pg_fsm_row_description_beg(ngx_pg_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    d->col++;
    if (!query->output.header) return s->rc;
    if (d->col > 1) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.delimiter), &query->output.delimiter)) != NGX_OK) return s->rc;
    if (query->output.string && query->output.quote) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.quote), &query->output.quote)) != NGX_OK) return s->rc;
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
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", mod);
    return s->rc;
}

static int ngx_pg_fsm_row_description_name(ngx_pg_save_t *s, size_t len, const uint8_t *data) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%*s", (int)len, data);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%ui", d->col);
    if (!query->output.header) return s->rc;
    if (query->output.string && query->output.quote && query->output.escape) for (ngx_uint_t k = 0; k < len; k++) {
        if (data[k] == query->output.quote) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.escape), &query->output.escape)) != NGX_OK) return s->rc;
        if ((s->rc = ngx_pg_output_handler(d, sizeof(data[k]), &data[k])) != NGX_OK) return s->rc;
    } else if ((s->rc = ngx_pg_output_handler(d, len, data)) != NGX_OK) return s->rc;
    return s->rc;
}

static int ngx_pg_fsm_row_description_oid(ngx_pg_save_t *s, uint32_t oid) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", oid);
    return s->rc;
}

static int ngx_pg_fsm_row_description_table(ngx_pg_save_t *s, uint32_t table) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%uD", table);
    ngx_pg_data_t *d = s->data;
    if (!d) return s->rc;
    ngx_pg_query_t *query = d->query;
    if (!query) return s->rc;
    if (!(query->type & ngx_pg_type_location)) return s->rc;
    if (query->output.type == ngx_pg_output_type_none) return s->rc;
    if (query->output.string && query->output.quote) if ((s->rc = ngx_pg_output_handler(d, sizeof(query->output.quote), &query->output.quote)) != NGX_OK) return s->rc;
    return s->rc;
}

static const pg_fsm_cb_t ngx_pg_fsm_cb = {
    .all = (pg_fsm_str_cb)ngx_pg_fsm_all,
    .authentication_cleartext_password = (pg_fsm_cb)ngx_pg_fsm_authentication_cleartext_password,
    .authentication_md5_password = (pg_fsm_str_cb)ngx_pg_fsm_authentication_md5_password,
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
    .error = (pg_fsm_str_cb)ngx_pg_fsm_error,
    .error_response_column = (pg_fsm_str_cb)ngx_pg_fsm_error_response_column,
    .error_response_constraint = (pg_fsm_str_cb)ngx_pg_fsm_error_response_constraint,
    .error_response_context = (pg_fsm_str_cb)ngx_pg_fsm_error_response_context,
    .error_response_datatype = (pg_fsm_str_cb)ngx_pg_fsm_error_response_datatype,
    .error_response_detail = (pg_fsm_str_cb)ngx_pg_fsm_error_response_detail,
    .error_response_file = (pg_fsm_str_cb)ngx_pg_fsm_error_response_file,
    .error_response_function = (pg_fsm_str_cb)ngx_pg_fsm_error_response_function,
    .error_response_hint = (pg_fsm_str_cb)ngx_pg_fsm_error_response_hint,
    .error_response_internal = (pg_fsm_str_cb)ngx_pg_fsm_error_response_internal,
    .error_response_line = (pg_fsm_str_cb)ngx_pg_fsm_error_response_line,
    .error_response_nonlocalized = (pg_fsm_str_cb)ngx_pg_fsm_error_response_nonlocalized,
    .error_response = (pg_fsm_int4_cb)ngx_pg_fsm_error_response,
    .error_response_primary = (pg_fsm_str_cb)ngx_pg_fsm_error_response_primary,
    .error_response_query = (pg_fsm_str_cb)ngx_pg_fsm_error_response_query,
    .error_response_schema = (pg_fsm_str_cb)ngx_pg_fsm_error_response_schema,
    .error_response_severity = (pg_fsm_str_cb)ngx_pg_fsm_error_response_severity,
    .error_response_sqlstate = (pg_fsm_str_cb)ngx_pg_fsm_error_response_sqlstate,
    .error_response_statement = (pg_fsm_str_cb)ngx_pg_fsm_error_response_statement,
    .error_response_table = (pg_fsm_str_cb)ngx_pg_fsm_error_response_table,
    .function_call_response = (pg_fsm_int4_cb)ngx_pg_fsm_function_call_response,
    .no_data = (pg_fsm_cb)ngx_pg_fsm_no_data,
    .notice_response = (pg_fsm_int4_cb)ngx_pg_fsm_notice_response,
    .notification_response_done = (pg_fsm_cb)ngx_pg_fsm_notification_response_done,
    .notification_response_extra = (pg_fsm_str_cb)ngx_pg_fsm_notification_response_extra,
    .notification_response = (pg_fsm_int4_cb)ngx_pg_fsm_notification_response,
    .notification_response_pid = (pg_fsm_int4_cb)ngx_pg_fsm_notification_response_pid,
    .notification_response_relname = (pg_fsm_str_cb)ngx_pg_fsm_notification_response_relname,
    .parameter_status_application_name = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_application_name,
    .parameter_status_client_encoding = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_client_encoding,
    .parameter_status_datestyle = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_datestyle,
    .parameter_status_default_transaction_read_only = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_default_transaction_read_only,
    .parameter_status_in_hot_standby = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_in_hot_standby,
    .parameter_status_integer_datetimes = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_integer_datetimes,
    .parameter_status_intervalstyle = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_intervalstyle,
    .parameter_status_is_superuser = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_is_superuser,
    .parameter_status = (pg_fsm_int4_cb)ngx_pg_fsm_parameter_status,
    .parameter_status_server_encoding = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_server_encoding,
    .parameter_status_server_version = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_server_version,
    .parameter_status_session_authorization = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_session_authorization,
    .parameter_status_standard_conforming_strings = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_standard_conforming_strings,
    .parameter_status_timezone = (pg_fsm_str_cb)ngx_pg_fsm_parameter_status_timezone,
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

static void ngx_pg_save_cln_handler(void *data) {
    ngx_pg_save_t *s = data;
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_str_t *channel = s->channels.elts;
    for (ngx_uint_t i = 0; i < s->channels.nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "channel[%ui] = %V", i, &channel[i]);
        ngx_http_push_stream_delete_channel_my(c->log, &channel[i], NULL, 0, c->pool);
    }
/*    ngx_chain_t *out, *last;
    if (!(out = ngx_pg_terminate(c->pool))) return;
    ngx_chain_writer_ctx_t ctx = { .out = out, .last = &last, .connection = c, .pool = c->pool, .limit = 0 };
    ngx_chain_writer(&ctx, NULL);*/
}

static ngx_int_t ngx_pg_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pg_data_t *d = data;
    ngx_int_t rc;
    switch ((rc = d->peer.get(pc, d->peer.data))) {
        case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_DONE"); break;
        case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_OK"); break;
        default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc); return rc;
    }
    ngx_pg_save_t *s = NULL;
    ngx_http_request_t *r = d->request;
    ngx_pg_loc_conf_t *plcf = d->plcf;
    ngx_pg_srv_conf_t *pscf = d->pscf;
    ngx_pg_connect_t *connect = pscf ? &pscf->connect : &plcf->connect;
    ngx_http_upstream_t *u = r->upstream;
    if (pc->connection) {
        ngx_connection_t *c = pc->connection;
        for (ngx_pool_cleanup_t *cln = c->pool->cleanup; cln; cln = cln->next) if (cln->handler == ngx_pg_save_cln_handler) { s = d->save = cln->data; break; }
        if (!s) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!s"); return NGX_ERROR; }
        if (!(u->request_bufs = ngx_pg_queries(d, &plcf->queries))) return NGX_ERROR;
#if (NGX_HTTP_SSL)
        if (pc->sockaddr->sa_family != AF_UNIX && connect->sslmode != ngx_pg_ssl_disable) {
            u->ssl = 1;
            if (c->write->ready) { ngx_post_event(c->write, &ngx_posted_events); }
        }
#endif
    } else {
        pc->get = ngx_event_get_peer;
        switch ((rc = ngx_event_connect_peer(pc))) {
            case NGX_AGAIN: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_AGAIN"); break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_DONE"); break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = NGX_OK"); break;
            default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc); return rc;
        }
        pc->get = ngx_pg_peer_get;
        ngx_connection_t *c = pc->connection;
        if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!c"); return NGX_ERROR; }
        if (c->pool) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "c->pool"); return NGX_ERROR; }
        if (!(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); return NGX_ERROR; }
        if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        s->connection = c;
        ngx_pool_cleanup_t *cln;
        if (!(cln = ngx_pool_cleanup_add(c->pool, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
        cln->data = s;
        cln->handler = ngx_pg_save_cln_handler;
        if (!(s->fsm = ngx_pcalloc(c->pool, pg_fsm_size()))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        pg_fsm_init(s->fsm);
#if (NGX_HTTP_SSL)
        if (pc->sockaddr->sa_family != AF_UNIX && connect->sslmode != ngx_pg_ssl_disable) {
            if (!(u->request_bufs = ngx_pg_ssl_request(r->pool))) return NGX_ERROR;
        } else
#endif
        if (!(u->request_bufs = ngx_pg_startup_message(r->pool, &connect->options))) return NGX_ERROR;
    }
    s->data = d;
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = u->request_bufs; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%ui:%d:%c", i++, *p, *p);
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
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "n = %z", n);
        b->last += n;
//        ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "%ui:%d:%c", i++, *p, *p);
        s->rc = NGX_OK;
        while (b->pos < b->last && s->rc == NGX_OK) b->pos += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->pos, b->last);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "s->rc = %i", s->rc);
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
    if (!ngx_terminate && !ngx_exiting && !c->error && !ev->error && !ev->timedout && ngx_pg_process(s) == NGX_OK) { ngx_add_timer(c->read, s->timeout); return; }
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
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %ui", state);
    ngx_pg_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    ngx_pg_save_t *s = d->save;
    d->save = NULL;
    s->data = NULL;
    if (!ngx_queue_empty(&d->queue) && s->pid && s->key) {
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
            default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc); return;
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
    ngx_pg_srv_conf_t *pscf = d->pscf;
    if (!pscf) return;
    ngx_memzero(&s->error, sizeof(s->error));
    ngx_connection_t *c = s->connection;
    if (c->read->timer_set) s->timeout = c->read->timer.key - ngx_current_msec;
    if (s->error.all.data) ngx_pfree(c->pool, s->error.all.data);
    if (!s->buffer.start) {
        ngx_http_request_t *r = d->request;
        ngx_http_upstream_t *u = r->upstream;
        if (!(s->buffer.start = ngx_palloc(c->pool, u->conf->buffer_size))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_palloc"); return; }
        s->buffer.end = s->buffer.start + u->conf->buffer_size;
        s->buffer.tag = u->output.tag;
        s->buffer.temporary = 1;
    }
    s->buffer.last = s->buffer.start;
    s->buffer.pos = s->buffer.start;
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

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_pg_peer_set_session(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pg_data_t *d = data;
    return d->peer.set_session(pc, d->peer.data);
}

static void ngx_pg_peer_save_session(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_pg_data_t *d = data;
    d->peer.save_session(pc, d->peer.data);
}
#endif

static ngx_int_t ngx_pg_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "srv_conf = %s", uscf->srv_conf ? "true" : "false");
    ngx_pg_data_t *d;
    if (!(d = ngx_pcalloc(r->pool, sizeof(*d)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    if (uscf->srv_conf) {
        ngx_pg_srv_conf_t *pscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_pg_module);
        if (pscf->peer.init(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
        d->pscf = pscf;
    } else {
        if (ngx_http_upstream_init_round_robin_peer(r, uscf) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_init_round_robin_peer != NGX_OK"); return NGX_ERROR; }
    }
    ngx_queue_init(&d->queue);
    ngx_pg_loc_conf_t *plcf = ngx_http_get_module_loc_conf(r, ngx_pg_module);
    d->plcf = plcf;
    ngx_http_upstream_t *u = r->upstream;
    d->peer = u->peer;
    d->request = r;
    u->conf->upstream = uscf;
    u->peer.data = d;
    u->peer.free = ngx_pg_peer_free;
    u->peer.get = ngx_pg_peer_get;
#if (NGX_HTTP_SSL)
    u->peer.save_session = ngx_pg_peer_save_session;
    u->peer.set_session = ngx_pg_peer_set_session;
#endif
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
    if (!plcf->queries.nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!queries"); return NGX_ERROR; }
    return NGX_OK;
}

static void ngx_pg_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
}

static ngx_int_t ngx_pg_process_header(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_buf_t *b = &u->buffer;
//    ngx_uint_t i = 0; for (u_char *p = b->pos; p < b->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%ui:%d:%c", i++, *p, *p);
    if (r->cached) {
        u->headers_in.status_n = NGX_HTTP_OK;
        u->keepalive = !u->headers_in.connection_close;
        return NGX_OK;
    }
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!s) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!s"); return NGX_ERROR; }
    ngx_pg_loc_conf_t *plcf = d->plcf;
    ngx_pg_srv_conf_t *pscf = d->pscf;
    ngx_pg_connect_t *connect = pscf ? &pscf->connect : &plcf->connect;
#if (NGX_HTTP_SSL)
    if (u->peer.sockaddr->sa_family != AF_UNIX && connect->sslmode != ngx_pg_ssl_disable && !u->ssl) {
        if (b->last - b->pos != 1) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last - b->pos != 1"); return NGX_ERROR; }
        switch (*b->pos++) {
            case 'N': if (connect->sslmode == ngx_pg_ssl_require) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sslmode == require"); return NGX_ERROR; } break;
            case 'S': u->ssl = 1; break;
            default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "*b->pos != 'S' && *b->pos != 'N'"); return NGX_ERROR;
        }
        if (!(u->request_bufs = ngx_pg_startup_message(r->pool, &connect->options))) return NGX_ERROR;
        u->request_sent = 0;
        u->write_event_handler(r, u);
        ngx_connection_t *c = r->connection;
        ngx_http_run_posted_requests(c);
        return NGX_AGAIN;
    }
#endif
    s->rc = NGX_OK;
    while (b->pos < b->last && s->rc == NGX_OK) b->pos += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->pos, b->last);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %i", s->rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos == b->last = %s", b->pos == b->last ? "true" : "false");
    if (s->rc == NGX_OK) s->rc = !ngx_queue_empty(&d->queue) || !s->pid || !s->key ? NGX_AGAIN : NGX_OK;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %i", s->rc);
    d->error = s->error;
    d->option = s->option;
    if (s->rc == NGX_OK && u->headers_in.status_n == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        if (s->error.column.data && !(d->error.column.data = ngx_pstrdup(r->pool, &s->error.column))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.column.len = s->error.column.len;
        if (s->error.constraint.data && !(d->error.constraint.data = ngx_pstrdup(r->pool, &s->error.constraint))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.constraint.len = s->error.constraint.len;
        if (s->error.context.data && !(d->error.context.data = ngx_pstrdup(r->pool, &s->error.context))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.context.len = s->error.context.len;
        if (s->error.datatype.data && !(d->error.datatype.data = ngx_pstrdup(r->pool, &s->error.datatype))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.datatype.len = s->error.datatype.len;
        if (s->error.detail.data && !(d->error.detail.data = ngx_pstrdup(r->pool, &s->error.detail))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.detail.len = s->error.detail.len;
        if (s->error.file.data && !(d->error.file.data = ngx_pstrdup(r->pool, &s->error.file))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.file.len = s->error.file.len;
        if (s->error.function.data && !(d->error.function.data = ngx_pstrdup(r->pool, &s->error.function))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.function.len = s->error.function.len;
        if (s->error.hint.data && !(d->error.hint.data = ngx_pstrdup(r->pool, &s->error.hint))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.hint.len = s->error.hint.len;
        if (s->error.internal.data && !(d->error.internal.data = ngx_pstrdup(r->pool, &s->error.internal))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.internal.len = s->error.internal.len;
        if (s->error.line.data && !(d->error.line.data = ngx_pstrdup(r->pool, &s->error.line))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.line.len = s->error.line.len;
        if (s->error.nonlocalized.data && !(d->error.nonlocalized.data = ngx_pstrdup(r->pool, &s->error.nonlocalized))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.nonlocalized.len = s->error.nonlocalized.len;
        if (s->error.primary.data && !(d->error.primary.data = ngx_pstrdup(r->pool, &s->error.primary))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.primary.len = s->error.primary.len;
        if (s->error.query.data && !(d->error.query.data = ngx_pstrdup(r->pool, &s->error.query))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.query.len = s->error.query.len;
        if (s->error.schema.data && !(d->error.schema.data = ngx_pstrdup(r->pool, &s->error.schema))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.schema.len = s->error.schema.len;
        if (s->error.severity.data && !(d->error.severity.data = ngx_pstrdup(r->pool, &s->error.severity))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.severity.len = s->error.severity.len;
        if (s->error.sqlstate.data && !(d->error.sqlstate.data = ngx_pstrdup(r->pool, &s->error.sqlstate))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.sqlstate.len = s->error.sqlstate.len;
        if (s->error.statement.data && !(d->error.statement.data = ngx_pstrdup(r->pool, &s->error.statement))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.statement.len = s->error.statement.len;
        if (s->error.table.data && !(d->error.table.data = ngx_pstrdup(r->pool, &s->error.table))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->error.table.len = s->error.table.len;
        if (s->option.application_name.data && !(d->option.application_name.data = ngx_pstrdup(r->pool, &s->option.application_name))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.application_name.len = s->option.application_name.len;
        if (s->option.client_encoding.data && !(d->option.client_encoding.data = ngx_pstrdup(r->pool, &s->option.client_encoding))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.client_encoding.len = s->option.client_encoding.len;
        if (s->option.datestyle.data && !(d->option.datestyle.data = ngx_pstrdup(r->pool, &s->option.datestyle))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.datestyle.len = s->option.datestyle.len;
        if (s->option.default_transaction_read_only.data && !(d->option.default_transaction_read_only.data = ngx_pstrdup(r->pool, &s->option.default_transaction_read_only))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.default_transaction_read_only.len = s->option.default_transaction_read_only.len;
        if (s->option.in_hot_standby.data && !(d->option.in_hot_standby.data = ngx_pstrdup(r->pool, &s->option.in_hot_standby))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.in_hot_standby.len = s->option.in_hot_standby.len;
        if (s->option.integer_datetimes.data && !(d->option.integer_datetimes.data = ngx_pstrdup(r->pool, &s->option.integer_datetimes))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.integer_datetimes.len = s->option.integer_datetimes.len;
        if (s->option.intervalstyle.data && !(d->option.intervalstyle.data = ngx_pstrdup(r->pool, &s->option.intervalstyle))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.intervalstyle.len = s->option.intervalstyle.len;
        if (s->option.is_superuser.data && !(d->option.is_superuser.data = ngx_pstrdup(r->pool, &s->option.is_superuser))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.is_superuser.len = s->option.is_superuser.len;
        if (s->option.server_encoding.data && !(d->option.server_encoding.data = ngx_pstrdup(r->pool, &s->option.server_encoding))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.server_encoding.len = s->option.server_encoding.len;
        if (s->option.server_version.data && !(d->option.server_version.data = ngx_pstrdup(r->pool, &s->option.server_version))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.server_version.len = s->option.server_version.len;
        if (s->option.session_authorization.data && !(d->option.session_authorization.data = ngx_pstrdup(r->pool, &s->option.session_authorization))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.session_authorization.len = s->option.session_authorization.len;
        if (s->option.standard_conforming_strings.data && !(d->option.standard_conforming_strings.data = ngx_pstrdup(r->pool, &s->option.standard_conforming_strings))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.standard_conforming_strings.len = s->option.standard_conforming_strings.len;
        if (s->option.timezone.data && !(d->option.timezone.data = ngx_pstrdup(r->pool, &s->option.timezone))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NGX_ERROR; } else d->option.timezone.len = s->option.timezone.len;
        s->rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %i", s->rc);
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
    while (b->pos < b->last && s->rc == NGX_OK) b->pos += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->pos, b->last);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, p->log, 0, "s->rc = %i", s->rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->pos == b->last = %s", b->pos == b->last ? "true" : "false");
    if (ngx_queue_empty(&d->queue) && s->pid && s->key) {
        p->length = 0;
        u->length = 0;
    }
    return s->rc;
}

static ngx_int_t ngx_pg_input_filter_init(void *data) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_event_pipe_t *p = u->pipe;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (ngx_queue_empty(&d->queue) && s->pid && s->key) {
        if (u->buffering) p->length = 0;
        u->length = 0;
    } else {
        if (u->buffering) p->length = 1;
        u->length = 1;
    }
//    ngx_uint_t i = 0; for (ngx_chain_t *cl = u->out_bufs; cl; cl = cl->next) for (u_char *p = cl->buf->pos; p < cl->buf->last; p++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%ui:%d:%c", i++, *p, *p);
    return NGX_OK;
}

static ngx_int_t ngx_pg_input_filter(void *data, ssize_t bytes) {
    ngx_http_request_t *r = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bytes = %z", bytes);
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_pg_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not pg"); return NGX_ERROR; }
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    ngx_buf_t *b = &u->buffer;
    u_char *last = b->last + bytes;
    s->rc = NGX_OK;
    while (b->last < last && s->rc == NGX_OK) b->last += pg_fsm_execute(s->fsm, &ngx_pg_fsm_cb, s, b->last, last);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "s->rc = %i", s->rc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "b->last == last = %s", b->last == last ? "true" : "false");
    if (ngx_queue_empty(&d->queue) && s->pid && s->key) u->length = 0;
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
    r->state = 0;
    u->abort_request = ngx_pg_abort_request;
    u->create_request = ngx_pg_create_request;
    u->finalize_request = ngx_pg_finalize_request;
    u->process_header = ngx_pg_process_header;
    u->reinit_request = ngx_pg_reinit_request;
    u->buffering = u->conf->buffering;
    u->input_filter_ctx = r;
    u->input_filter_init = ngx_pg_input_filter_init;
    u->input_filter = ngx_pg_input_filter;
    if (!(u->pipe = ngx_pcalloc(r->pool, sizeof(*u->pipe)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u->pipe->input_ctx = r;
    u->pipe->input_filter = ngx_pg_pipe_input_filter;
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
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.intercept_errors = NGX_CONF_UNSET;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.preserve_output = 1;
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
#if (NGX_HTTP_SSL)
    conf->ssl_conf_commands = NGX_CONF_UNSET_PTR;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    conf->upstream.ssl_certificate_key = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_name = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_passwords = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_server_name = NGX_CONF_UNSET;
    conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
    conf->upstream.ssl_verify = NGX_CONF_UNSET;
#endif
    return conf;
}

static ngx_path_init_t ngx_pg_temp_path = {
    ngx_string("/var/tmp/nginx/pg_temp"), { 1, 2, 0 }
};

#if (NGX_HTTP_SSL)
static char *ngx_pg_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    if (plcf->upstream.ssl_passwords != NGX_CONF_UNSET_PTR) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    if (!(plcf->upstream.ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]))) return "!ngx_ssl_read_password_file";
    return NGX_CONF_OK;
}

static char *ngx_pg_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data) {
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NGX_CONF_OK;
#endif
}

static ngx_int_t ngx_pg_set_ssl(ngx_conf_t *cf, ngx_pg_loc_conf_t *plcf) {
    if (!(plcf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t)))) return NGX_ERROR;
    plcf->upstream.ssl->log = cf->log;
    if (ngx_ssl_create(plcf->upstream.ssl, plcf->ssl_protocols, NULL) != NGX_OK) return NGX_ERROR;
    ngx_pool_cleanup_t *cln;
    if (!(cln = ngx_pool_cleanup_add(cf->pool, 0))) { ngx_ssl_cleanup_ctx(plcf->upstream.ssl); return NGX_ERROR; }
    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = plcf->upstream.ssl;
    if (ngx_ssl_ciphers(cf, plcf->upstream.ssl, &plcf->ssl_ciphers, 0) != NGX_OK) return NGX_ERROR;
    if (plcf->upstream.ssl_certificate) {
        if (!plcf->upstream.ssl_certificate_key) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no \"pg_ssl_certificate_key\" is defined for certificate \"%V\"", &plcf->upstream.ssl_certificate->value); return NGX_ERROR; }
        if (plcf->upstream.ssl_certificate->lengths || plcf->upstream.ssl_certificate_key->lengths) {
            if (!(plcf->upstream.ssl_passwords = ngx_ssl_preserve_passwords(cf, plcf->upstream.ssl_passwords))) return NGX_ERROR;
        } else {
            if (ngx_ssl_certificate(cf, plcf->upstream.ssl, &plcf->upstream.ssl_certificate->value, &plcf->upstream.ssl_certificate_key->value, plcf->upstream.ssl_passwords) != NGX_OK) return NGX_ERROR;
        }
    }
    if (plcf->upstream.ssl_verify) {
        if (!plcf->ssl_trusted_certificate.len) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no pg_ssl_trusted_certificate for pg_ssl_verify"); return NGX_ERROR; }
        if (ngx_ssl_trusted_certificate(cf, plcf->upstream.ssl, &plcf->ssl_trusted_certificate, plcf->ssl_verify_depth) != NGX_OK) return NGX_ERROR;
        if (ngx_ssl_crl(cf, plcf->upstream.ssl, &plcf->ssl_crl) != NGX_OK) return NGX_ERROR;
    }
    if (ngx_ssl_client_session_cache(cf, plcf->upstream.ssl, plcf->upstream.ssl_session_reuse) != NGX_OK) return NGX_ERROR;
    if (ngx_ssl_conf_commands(cf, plcf->upstream.ssl, plcf->ssl_conf_commands) != NGX_OK) return NGX_ERROR;
    return NGX_OK;
}

static ngx_conf_bitmask_t ngx_pg_ssl_protocols[] = {
  { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
  { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
  { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
  { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
  { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
  { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
  { ngx_null_string, 0 }
};

static ngx_conf_post_t ngx_pg_ssl_conf_command_post = { ngx_pg_ssl_conf_command_check };
#endif

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
#if (NGX_HTTP_SSL)
    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols, NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1|NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3);
    ngx_conf_merge_ptr_value(conf->ssl_conf_commands, prev->ssl_conf_commands, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key, prev->upstream.ssl_certificate_key, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate, prev->upstream.ssl_certificate, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_name, prev->upstream.ssl_name, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_passwords, prev->upstream.ssl_passwords, NULL);
    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");
    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
    ngx_conf_merge_str_value(conf->ssl_trusted_certificate, prev->ssl_trusted_certificate, "");
    ngx_conf_merge_uint_value(conf->ssl_verify_depth, prev->ssl_verify_depth, 1);
    ngx_conf_merge_value(conf->upstream.ssl_server_name, prev->upstream.ssl_server_name, 0);
    ngx_conf_merge_value(conf->upstream.ssl_session_reuse, prev->upstream.ssl_session_reuse, 1);
    ngx_conf_merge_value(conf->upstream.ssl_verify, prev->upstream.ssl_verify, 0);
    if (conf->connect.sslmode != ngx_pg_ssl_disable && ngx_pg_set_ssl(cf, conf) != NGX_OK) return "ngx_pg_set_ssl != NGX_OK";
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
    ngx_uint_t offset = data;
    ngx_str_t *error = (ngx_str_t *)((u_char *)&d->error + offset);
    if (!error->len) return NGX_OK;
    v->data = error->data;
    v->len = error->len;
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
    ngx_uint_t offset = data;
    ngx_str_t *option = (ngx_str_t *)((u_char *)&d->option + offset);
    if (!option->len) return NGX_OK;
    v->data = option->data;
    v->len = option->len;
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
    if (!(v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_sprintf(v->data, "%uD", s->pid) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static const ngx_http_variable_t ngx_pg_variables[] = {
  { ngx_string("pg_error_column"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, column), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_constraint"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, constraint), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_context"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, context), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_datatype"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, datatype), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_detail"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, detail), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_file"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, file), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_function"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, function), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_hint"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, hint), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_internal"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, internal), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_line"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, line), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_nonlocalized"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, nonlocalized), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_primary"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, primary), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_query"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, query), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_schema"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, schema), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_severity"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, severity), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_sqlstate"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, sqlstate), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_statement"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, statement), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_error_table"), NULL, ngx_pg_error_get_handler, offsetof(ngx_pg_error_t, table), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_application_name"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, application_name), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_client_encoding"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, client_encoding), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_datestyle"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, datestyle), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_default_transaction_read_only"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, default_transaction_read_only), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_in_hot_standby"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, in_hot_standby), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_integer_datetimes"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, integer_datetimes), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_intervalstyle"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, intervalstyle), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_is_superuser"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, is_superuser), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_server_encoding"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, server_encoding), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_server_version"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, server_version), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_session_authorization"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, session_authorization), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_standard_conforming_strings"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, standard_conforming_strings), NGX_HTTP_VAR_CHANGEABLE, 0 },
  { ngx_string("pg_option_timezone"), NULL, ngx_pg_option_get_handler, offsetof(ngx_pg_option_t, timezone), NGX_HTTP_VAR_CHANGEABLE, 0 },
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

static ngx_int_t ngx_pg_variable_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    v->not_found = 1;
    ngx_http_upstream_t *u = r->upstream;
    if (!u) return NGX_OK;
    if (u->peer.get != ngx_pg_peer_get) return NGX_OK;
    ngx_pg_data_t *d = u->peer.data;
    ngx_pg_save_t *s = d->save;
    if (!s) return NGX_OK;
    ngx_int_t index = data;
    ngx_pg_variable_t *variable = s->variables.elts;
    for (ngx_uint_t i = 0; i < s->variables.nelts; i++) if (variable[i].index == index) {
        v->data = variable[i].value.data;
        v->len = variable[i].value.len;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->valid = 1;
        return NGX_OK;
    }
    return NGX_OK;
}

static char *ngx_pg_argument_output_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_pg_query_t *query) {
    ngx_str_t *str = cf->args->elts;
    for (ngx_uint_t i = cmd->offset & ngx_pg_type_parse ? 3 : 2; i < cf->args->nelts; i++) {
        if (str[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            if (!(cmd->offset & ngx_pg_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("delimiter=") - 1))) return "empty \"delimiter\" value";
            if (str[i].len - (sizeof("delimiter=") - 1) > 1) return "\"delimiter\" value must be one character";
            query->output.delimiter = str[i].data[sizeof("delimiter=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            if (!(cmd->offset & ngx_pg_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("escape=") - 1))) { query->output.escape = '\0'; continue; }
            else if (str[i].len > 1) return "\"escape\" value must be one character";
            query->output.escape = str[i].data[sizeof("escape=") - 1];
            continue;
        }
        if (str[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            if (!(cmd->offset & ngx_pg_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("header=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("header=") - 1], str[i].len - (sizeof("header=") - 1))) break;
            if (!e[j].name.len) return "\"header\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            query->output.header = e[j].value;
            continue;
        }
        if (str[i].len > sizeof("output=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"output=", sizeof("output=") - 1)) {
            if (str[i].data[sizeof("output=") - 1] == '$' && cmd->offset & ngx_pg_type_upstream) {
                ngx_str_t name = str[i];
                name.data += sizeof("output=") - 1 + 1;
                name.len -= sizeof("output=") - 1 + 1;
                ngx_http_variable_t *variable;
                if (!(variable = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE))) return "!ngx_http_add_variable";
                if ((query->output.index = ngx_http_get_variable_index(cf, &name)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
                variable->get_handler = ngx_pg_variable_get_handler;
                variable->data = query->output.index;
                query->output.type = ngx_pg_output_type_value;
                continue;
            }
            if (!(cmd->offset & ngx_pg_type_output)) return "output not allowed";
            ngx_uint_t j;
            if (cmd->offset & ngx_pg_type_function) {
                static const ngx_conf_enum_t e[] = { { ngx_string("value"), ngx_pg_output_type_value }, { ngx_null_string, 0 } };
                for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("output=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("output=") - 1], str[i].len - (sizeof("output=") - 1))) break;
                if (!e[j].name.len) return "\"output\" value must be \"value\"";
                query->output.type = e[j].value;
            } else {
                static const ngx_conf_enum_t e[] = { { ngx_string("csv"), ngx_pg_output_type_csv }, { ngx_string("plain"), ngx_pg_output_type_plain }, { ngx_string("value"), ngx_pg_output_type_value }, { ngx_null_string, 0 } };
                for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("output=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("output=") - 1], str[i].len - (sizeof("output=") - 1))) break;
                if (!e[j].name.len) return "\"output\" value must be \"csv\", \"plain\" or \"value\"";
                query->output.type = e[j].value;
            }
            switch (query->output.type) {
                case ngx_pg_output_type_csv: {
                    ngx_str_set(&query->output.null, "");
                    query->output.delimiter = ',';
                    query->output.escape = '"';
                    query->output.header = 1;
                    query->output.quote = '"';
                } break;
                case ngx_pg_output_type_plain: {
                    ngx_str_set(&query->output.null, "\\N");
                    query->output.delimiter = '\t';
                    query->output.header = 1;
                } break;
                default: break;
            }
            continue;
        }
        if (str[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            if (!(cmd->offset & ngx_pg_type_output)) return "output not allowed";
            if (!(query->output.null.len = str[i].len - (sizeof("null=") - 1))) return "empty \"null\" value";
            query->output.null.data = &str[i].data[sizeof("null=") - 1];
            continue;
        }
        if (str[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            if (!(cmd->offset & ngx_pg_type_output)) return "output not allowed";
            if (!(str[i].len - (sizeof("quote=") - 1))) { query->output.quote = '\0'; continue; }
            else if (str[i].len - (sizeof("quote=") - 1) > 1) return "\"quote\" value must be one character";
            query->output.quote = str[i].data[sizeof("quote=") - 1];
            continue;
        }
        if (str[i].len > sizeof("string=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
            if (!(cmd->offset & ngx_pg_type_output)) return "output not allowed";
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("off"), 0 }, { ngx_string("no"), 0 }, { ngx_string("false"), 0 }, { ngx_string("on"), 1 }, { ngx_string("yes"), 1 }, { ngx_string("true"), 1 }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("string=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("string=") - 1], str[i].len - (sizeof("string=") - 1))) break;
            if (!e[j].name.len) return "\"string\" value must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"";
            query->output.string = e[j].value;
            continue;
        }
        ngx_pg_argument_t *argument;
        if (!query->arguments.elts && ngx_array_init(&query->arguments, cf->pool, 1, sizeof(*argument)) != NGX_OK) return "ngx_array_init != NGX_OK";
        if (!(argument = ngx_array_push(&query->arguments))) return "!ngx_array_push";
        ngx_memzero(argument, sizeof(*argument));
        ngx_str_t value = str[i];
        ngx_str_t oid = ngx_null_string;
        if (cmd->offset & ngx_pg_type_query || cmd->offset & ngx_pg_type_function) {
            u_char *colon;
            if ((colon = ngx_strstrn(value.data, "::", sizeof("::") - 1 - 1))) {
                value.len = colon - value.data;
                oid.data = colon + sizeof("::") - 1;
                oid.len = str[i].len - value.len - sizeof("::") + 1;
            }
        } else if (cmd->offset & ngx_pg_type_parse) oid = value;
        if (!(cmd->offset & ngx_pg_type_parse)) {
            if (value.data[0] == '$') {
                value.data++;
                value.len--;
                if ((argument->value.index = ngx_http_get_variable_index(cf, &value)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
            } else argument->value.str = value;
        }
        if (!oid.len) continue;
        if (oid.data[0] == '$') {
            oid.data++;
            oid.len--;
            if ((argument->oid.index = ngx_http_get_variable_index(cf, &oid)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
        } else {
            ngx_int_t n = ngx_atoi(oid.data, oid.len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            argument->oid.value = n;
        }
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_function_loc_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_array_t *queries) {
    ngx_pg_query_t *query;
    if (!queries->elts && ngx_array_init(queries, cf->pool, 1, sizeof(*query)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(query = ngx_array_push(queries))) return "!ngx_array_push";
    ngx_memzero(query, sizeof(*query));
    ngx_str_t *str = cf->args->elts;
    if (str[1].data[0] == '$') {
        str[1].data++;
        str[1].len--;
        if ((query->function.index = ngx_http_get_variable_index(cf, &str[1])) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    } else {
        ngx_int_t n = ngx_atoi(str[1].data, str[1].len);
        if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
        query->function.oid = n;
    }
    query->type = cmd->offset;
    return ngx_pg_argument_output_loc_conf(cf, cmd, query);
}

static char *ngx_pg_function_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    return ngx_pg_function_loc_ups_conf(cf, cmd, &plcf->queries);
}

static char *ngx_pg_function_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_pg_function_loc_ups_conf(cf, cmd, &pscf->queries);
}

static char *ngx_pg_log_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_log_set_log(cf, &pscf->log);
}

static char *ngx_pg_option_loc_ups_conf(ngx_conf_t *cf, ngx_pg_connect_t *connect) {
    if (connect->options.elts) return "duplicate";
    ngx_str_t *option;
    if (ngx_array_init(&connect->options, cf->pool, cf->args->nelts - 1, sizeof(*option)) != NGX_OK) return "ngx_array_init != NGX_OK";
    ngx_str_t *str = cf->args->elts;
#if (NGX_HTTP_SSL)
    connect->sslmode = ngx_pg_ssl_prefer;
#endif
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (str[i].len > sizeof("password=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"password=", sizeof("password=") - 1)) {
            if (!(connect->password.len = str[i].len - (sizeof("password=") - 1))) return "empty \"password\" value";
            connect->password.data = &str[i].data[sizeof("password=") - 1];
            continue;
        }
#if (NGX_HTTP_SSL)
        if (str[i].len > sizeof("sslmode=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"sslmode=", sizeof("sslmode=") - 1)) {
            ngx_uint_t j;
            static const ngx_conf_enum_t e[] = { { ngx_string("disable"), ngx_pg_ssl_disable }, { ngx_string("prefer"), ngx_pg_ssl_prefer }, { ngx_string("require"), ngx_pg_ssl_require }, { ngx_null_string, 0 } };
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str[i].len - (sizeof("sslmode=") - 1) && !ngx_strncasecmp(e[j].name.data, &str[i].data[sizeof("sslmode=") - 1], str[i].len - (sizeof("sslmode=") - 1))) break;
            if (!e[j].name.len) return "\"ssl\" value must be \"disable\", \"prefer\" or \"require\"";
            connect->sslmode = e[j].value;
            continue;
        }
#endif
        if (str[i].len > sizeof("user=") - 1 && !ngx_strncasecmp(str[i].data, (u_char *)"user=", sizeof("user=") - 1)) {
            if (!(connect->username.len = str[i].len - (sizeof("user=") - 1))) return "empty \"user\" value";
            connect->username.data = &str[i].data[sizeof("user=") - 1];
        }
        if (!(option = ngx_array_push(&connect->options))) return "!ngx_array_push";
        ngx_memzero(option, sizeof(*option));
        *option = str[i];
        for (ngx_uint_t j = 0; j < option->len; j++) if (option->data[j] == '=') option->data[j] = '\0';
    }
    return NGX_CONF_OK;
}

static char *ngx_pg_option_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    return ngx_pg_option_loc_ups_conf(cf, &plcf->connect);
}

static char *ngx_pg_option_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (uscf->peer.init_upstream != ngx_pg_peer_init_upstream) {
        pscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
        uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    }
    return ngx_pg_option_loc_ups_conf(cf, &pscf->connect);
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
#if (NGX_HTTP_SSL)
        plcf->connect.sslmode = ngx_pg_ssl_prefer;
#endif
        return NGX_CONF_OK;
    }
    ngx_url_t url = {0};
    if (!plcf->connect.options.elts) {
#if (NGX_HTTP_SSL)
        plcf->connect.sslmode = ngx_pg_ssl_prefer;
#endif
        url.no_resolve = 1;
    }
    url.url = str[1];
    if (!(plcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) return NGX_CONF_ERROR;
    ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
    uscf->peer.init_upstream = ngx_pg_peer_init_upstream;
    return NGX_CONF_OK;
}

static char *ngx_pg_parse_query_loc_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_array_t *queries) {
    ngx_pg_query_t *query;
    if (!queries->elts && ngx_array_init(queries, cf->pool, 1, sizeof(*query)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(query = ngx_array_push(queries))) return "!ngx_array_push";
    ngx_memzero(query, sizeof(*query));
    ngx_pg_command_t *command;
    if (ngx_array_init(&query->commands, cf->pool, 1, sizeof(*command)) != NGX_OK) return "ngx_array_init != NGX_OK";
    ngx_str_t *str = cf->args->elts;
    ngx_uint_t i = 1;
    query->type = cmd->offset;
    if (cmd->offset & ngx_pg_type_parse) {
        if (str[i].data[0] == '$') {
            str[i].data++;
            str[i].len--;
            if ((query->name.index = ngx_http_get_variable_index(cf, &str[i])) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
        } else query->name.str = str[i];
        i++;
    }
    u_char *b = str[i].data;
    u_char *e = str[i].data + str[i].len;
    u_char *n = b;
    u_char *s = n;
    while (s < e) {
        if (*s++ == '$') {
            if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || *s == '_') {
                if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
                ngx_memzero(command, sizeof(*command));
                command->str.data = n;
                command->str.len = s - n - 1;
                n = s;
                while (s < e && ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || *s == '_')) s++;
                if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
                ngx_memzero(command, sizeof(*command));
                command->str.data = n;
                command->str.len = s - n;
                n = s;
                if (*s != '$') if ((command->index = ngx_http_get_variable_index(cf, &command->str)) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
            } else {
                if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
                ngx_memzero(command, sizeof(*command));
                command->str.data = n;
                command->str.len = s - n;
                n = s;
            }
        }
    }
    if (n < s) {
        if (!(command = ngx_array_push(&query->commands))) return "!ngx_array_push";
        ngx_memzero(command, sizeof(*command));
        command->str.data = n;
        command->str.len = s - n;
    }
    return ngx_pg_argument_output_loc_conf(cf, cmd, query);
}

static char *ngx_pg_execute_loc_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_array_t *queries) {
    ngx_pg_query_t *query;
    if (!queries->elts && ngx_array_init(queries, cf->pool, 1, sizeof(*query)) != NGX_OK) return "ngx_array_init != NGX_OK";
    if (!(query = ngx_array_push(queries))) return "!ngx_array_push";
    ngx_memzero(query, sizeof(*query));
    ngx_str_t *str = cf->args->elts;
    if (str[1].data[0] == '$') {
        str[1].data++;
        str[1].len--;
        if ((query->name.index = ngx_http_get_variable_index(cf, &str[1])) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    } else query->name.str = str[1];
    query->type = cmd->offset;
    return ngx_pg_argument_output_loc_conf(cf, cmd, query);
}

static char *ngx_pg_execute_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    return ngx_pg_execute_loc_ups_conf(cf, cmd, &plcf->queries);
}

static char *ngx_pg_execute_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_pg_execute_loc_ups_conf(cf, cmd, &pscf->queries);
}

static char *ngx_pg_parse_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    return ngx_pg_parse_query_loc_ups_conf(cf, cmd, &plcf->queries);
}

static char *ngx_pg_parse_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_pg_parse_query_loc_ups_conf(cf, cmd, &pscf->queries);
}

static char *ngx_pg_query_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_loc_conf_t *plcf = conf;
    return ngx_pg_parse_query_loc_ups_conf(cf, cmd, &plcf->queries);
}

static char *ngx_pg_query_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_pg_srv_conf_t *pscf = conf;
    return ngx_pg_parse_query_loc_ups_conf(cf, cmd, &pscf->queries);
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
  { ngx_string("pg_execute"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_execute_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pg_type_location|ngx_pg_type_execute|ngx_pg_type_output, NULL },
  { ngx_string("pg_execute"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_execute_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pg_type_upstream|ngx_pg_type_execute, NULL },
  { ngx_string("pg_function"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_function_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pg_type_location|ngx_pg_type_function|ngx_pg_type_output, NULL },
  { ngx_string("pg_function"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_function_ups_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pg_type_upstream|ngx_pg_type_function, NULL },
  { ngx_string("pg_log"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_log_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_option"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_option_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_option"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_option_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_parse"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_parse_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pg_type_location|ngx_pg_type_parse, NULL },
  { ngx_string("pg_parse"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_parse_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pg_type_upstream|ngx_pg_type_parse, NULL },
  { ngx_string("pg_pass"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1, ngx_pg_pass_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_query"), NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE, ngx_pg_query_loc_conf, NGX_HTTP_LOC_CONF_OFFSET, ngx_pg_type_location|ngx_pg_type_query|ngx_pg_type_output, NULL },
  { ngx_string("pg_query"), NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, ngx_pg_query_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, ngx_pg_type_upstream|ngx_pg_type_query, NULL },
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
#if (NGX_HTTP_SSL)
  { ngx_string("pg_ssl_certificate_key"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_http_set_complex_value_zero_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.ssl_certificate_key), NULL },
  { ngx_string("pg_ssl_certificate"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_http_set_complex_value_zero_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.ssl_certificate), NULL },
  { ngx_string("pg_ssl_ciphers"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, ssl_ciphers), NULL },
  { ngx_string("pg_ssl_conf_command"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2, ngx_conf_set_keyval_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, ssl_conf_commands), &ngx_pg_ssl_conf_command_post },
  { ngx_string("pg_ssl_crl"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, ssl_crl), NULL },
  { ngx_string("pg_ssl_name"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.ssl_name), NULL },
  { ngx_string("pg_ssl_password_file"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_pg_ssl_password_file, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
  { ngx_string("pg_ssl_protocols"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, ssl_protocols), &ngx_pg_ssl_protocols },
  { ngx_string("pg_ssl_server_name"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.ssl_server_name), NULL },
  { ngx_string("pg_ssl_session_reuse"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.ssl_session_reuse), NULL },
  { ngx_string("pg_ssl_trusted_certificate"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, ssl_trusted_certificate), NULL },
  { ngx_string("pg_ssl_verify_depth"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, ssl_verify_depth), NULL },
  { ngx_string("pg_ssl_verify"), NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_pg_loc_conf_t, upstream.ssl_verify), NULL },
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
