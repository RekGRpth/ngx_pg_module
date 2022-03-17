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
    pg_parser_cb on_message_begin;
    pg_parser_data_cb on_url;
} pg_parser_settings_t;

int pg_parser_execute(pg_parser_t *parser, const pg_parser_settings_t *settings, const unsigned char *p, const unsigned char *pe);
void pg_parser_init(pg_parser_t *parser);
