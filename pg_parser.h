typedef struct {
    int index;
    int length;
    int state;
    int string;
    unsigned char any[4];
    void *data;
} pg_parser_t;

typedef int (*pg_parser_cb) (pg_parser_t *parser);
typedef int (*pg_parser_data_cb) (pg_parser_t *parser, const unsigned char *p, const unsigned char *pe);

typedef struct {
    pg_parser_cb parse;
    pg_parser_cb bind;
    pg_parser_cb close;
    pg_parser_cb complete;
    pg_parser_cb data;
    pg_parser_cb secret;
    pg_parser_cb auth;
    pg_parser_cb status;
    pg_parser_cb row;
    pg_parser_cb ready;
    pg_parser_data_cb on_url;
} pg_parser_settings_t;

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *p, const unsigned char *pe);
void pg_parser_init(pg_parser_t *parser);
