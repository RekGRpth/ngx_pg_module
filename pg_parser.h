typedef long int (*pg_parser_cb) (void *data);
typedef long int (*pg_parser_ptr_cb) (void *data, const void *ptr);
typedef long int (*pg_parser_str_cb) (void *data, size_t len, const unsigned char *str);

typedef struct {
    pg_parser_cb auth;
    pg_parser_cb bind;
    pg_parser_cb close;
    pg_parser_cb complete;
    pg_parser_cb error;
    pg_parser_cb field;
    pg_parser_cb idle;
    pg_parser_cb inerror;
    pg_parser_cb intrans;
    pg_parser_cb parse;
    pg_parser_cb ready;
    pg_parser_cb secret;
    pg_parser_cb tup;
    pg_parser_ptr_cb all;
    pg_parser_ptr_cb atttypmod;
    pg_parser_ptr_cb columnid;
    pg_parser_ptr_cb format;
    pg_parser_ptr_cb key;
    pg_parser_ptr_cb method;
    pg_parser_ptr_cb nbytes;
    pg_parser_ptr_cb nfields;
    pg_parser_ptr_cb ntups;
    pg_parser_ptr_cb pid;
    pg_parser_ptr_cb status;
    pg_parser_ptr_cb tableid;
    pg_parser_ptr_cb typid;
    pg_parser_ptr_cb typlen;
    pg_parser_str_cb byte;
    pg_parser_str_cb complete_val;
    pg_parser_str_cb name;
    pg_parser_str_cb status_key;
    pg_parser_str_cb status_val;
    pg_parser_str_cb unknown;
} pg_parser_settings_t;

typedef struct pg_parser_t pg_parser_t;

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *b, const unsigned char *p, const unsigned char *pe, const unsigned char *eof);
size_t pg_parser_size(void);
void pg_parser_init(pg_parser_t *parser, const void *data);
