typedef struct {
    int cs;
    int i;
    int len;
    int str;
    unsigned char any[4];
    void *data;
} pg_parser_t;

typedef int (*pg_parser_cb) (pg_parser_t *parser);
typedef int (*pg_parser_ptr_cb) (pg_parser_t *parser, const uintptr_t data);
typedef int (*pg_parser_str_cb) (pg_parser_t *parser, size_t len, const unsigned char *data);

typedef struct {
    pg_parser_cb auth;
    pg_parser_cb bind;
    pg_parser_cb close;
    pg_parser_cb complete;
    pg_parser_cb data;
    pg_parser_cb desc;
    pg_parser_cb idle;
    pg_parser_cb inerror;
    pg_parser_cb intrans;
    pg_parser_cb parse;
    pg_parser_cb ready;
    pg_parser_cb secret;
    pg_parser_cb status;
    pg_parser_cb status_done;
    pg_parser_cb status_open;
    pg_parser_ptr_cb all;
    pg_parser_ptr_cb atttypmod;
    pg_parser_ptr_cb columnid;
    pg_parser_ptr_cb data_len;
    pg_parser_ptr_cb format;
    pg_parser_ptr_cb key;
    pg_parser_ptr_cb len;
    pg_parser_ptr_cb method;
    pg_parser_ptr_cb nfields;
    pg_parser_ptr_cb pid;
    pg_parser_ptr_cb tableid;
    pg_parser_ptr_cb tupnfields;
    pg_parser_ptr_cb typid;
    pg_parser_ptr_cb typlen;
    pg_parser_str_cb complete_val;
    pg_parser_str_cb data_val;
    pg_parser_str_cb name;
    pg_parser_str_cb status_key;
    pg_parser_str_cb status_val;
} pg_parser_settings_t;

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *p, const unsigned char *pe);
void pg_parser_init(pg_parser_t *parser);
