typedef struct {
    int index;
    int length;
    int state;
    int string;
    unsigned char any[4];
} pg_parser_t;

int pg_parser_execute(pg_parser_t *parser, const unsigned char *pos, const unsigned char *last);
void pg_parser_init(pg_parser_t *parser);
