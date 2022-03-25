typedef intptr_t (*pg_parser_cb) (void *data);
typedef intptr_t (*pg_parser_ptr_cb) (void *data, const void *ptr);
typedef intptr_t (*pg_parser_len_str_cb) (void *data, size_t len, const uint8_t *str);

typedef struct {
    pg_parser_cb auth;
    pg_parser_cb bind;
    pg_parser_cb close;
    pg_parser_cb fatal;
    pg_parser_cb idle;
    pg_parser_cb inerror;
    pg_parser_cb intrans;
    pg_parser_cb parse;
    pg_parser_cb ready;
    pg_parser_cb secret;
    pg_parser_len_str_cb byte;
    pg_parser_len_str_cb column;
    pg_parser_len_str_cb command;
    pg_parser_len_str_cb constraint;
    pg_parser_len_str_cb context;
    pg_parser_len_str_cb datatype;
    pg_parser_len_str_cb detail;
    pg_parser_len_str_cb file;
    pg_parser_len_str_cb function;
    pg_parser_len_str_cb hint;
    pg_parser_len_str_cb internal;
    pg_parser_len_str_cb line;
    pg_parser_len_str_cb name;
    pg_parser_len_str_cb nonlocalized;
    pg_parser_len_str_cb option;
    pg_parser_len_str_cb primary;
    pg_parser_len_str_cb query;
    pg_parser_len_str_cb schema;
    pg_parser_len_str_cb severity;
    pg_parser_len_str_cb sqlstate;
    pg_parser_len_str_cb statement;
    pg_parser_len_str_cb table;
    pg_parser_len_str_cb unknown;
    pg_parser_len_str_cb value;
    pg_parser_ptr_cb all;
    pg_parser_ptr_cb atttypmod;
    pg_parser_ptr_cb col;
    pg_parser_ptr_cb columnid;
    pg_parser_ptr_cb complete;
    pg_parser_ptr_cb error;
    pg_parser_ptr_cb format;
    pg_parser_ptr_cb key;
    pg_parser_ptr_cb method;
    pg_parser_ptr_cb nbytes;
    pg_parser_ptr_cb ncols;
    pg_parser_ptr_cb nrows;
    pg_parser_ptr_cb pid;
    pg_parser_ptr_cb row;
    pg_parser_ptr_cb status;
    pg_parser_ptr_cb tableid;
    pg_parser_ptr_cb typid;
    pg_parser_ptr_cb typlen;
} pg_parser_settings_t;

typedef struct pg_parser_t pg_parser_t;

inline static uint8_t *pg_write_uint16(uint8_t *p, uint16_t n) { for (uint8_t i = 2; i; *p++ = n >> (2 << 2) * --i); return p; }
inline static uint8_t *pg_write_uint32(uint8_t *p, uint32_t n) { for (uint8_t i = 4; i; *p++ = n >> (2 << 2) * --i); return p; }
inline static uint8_t *pg_write_uint8(uint8_t *p, uint8_t n) { *p++ = n; return p; }
size_t pg_parser_execute(pg_parser_t *parser, const uint8_t *p, const uint8_t *pe);
size_t pg_parser_size(void);
void pg_parser_init(pg_parser_t *parser, const pg_parser_settings_t *settings, const void *data);
