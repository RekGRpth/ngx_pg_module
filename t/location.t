use Test::Nginx::Socket 'no_plan';

no_root_location;
no_shuffle;
run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- config
    location =/ {
        add_header complete $pg_complete always;
        add_header field-length-0 $pg_field_length_0 always;
        add_header field-mod-0 $pg_field_mod_0 always;
        add_header field-name-0 $pg_field_name_0 always;
        add_header field-oid-0 $pg_field_oid_0 always;
        add_header value-0-0 $pg_value_0_0 always;
        pg_con user=postgres database=postgres application_name=location;
        pg_out value;
        pg_pas postgres:5432;
        pg_sql "select 1";
    }
--- request
GET /
--- error_code: 200
--- response_headers
complete: SELECT 1
Content-Type: text/plain
field-length-0: 4
field-mod-0: 42
field-name-0: ?column?
field-oid-0: 23
value-0-0: 1
--- response_body chomp
1
--- timeout: 10

=== TEST 2:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- config
    location =/ {
        add_header error-file $pg_error_file always;
        add_header error-function $pg_error_function always;
        add_header error-nonlocalized $pg_error_nonlocalized always;
        add_header error-primary $pg_error_primary always;
        add_header error-severity $pg_error_severity always;
        add_header error-sqlstate $pg_error_sqlstate always;
        pg_con user=postgres database=postgres application_name=location;
        pg_out value;
        pg_pas postgres:5432;
        pg_sql "select 1/0";
    }
--- request
GET /
--- error_code: 502
--- response_headers
Content-Type: text/html
error-file: int.c
error-function: int4div
error-nonlocalized: ERROR
error-primary: division by zero
error-severity: ERROR
error-sqlstate: 22012
--- timeout: 10

=== TEST 3:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- config
    location =/ {
        add_header complete $pg_complete always;
        add_header field-length-0 $pg_field_length_0 always;
        add_header field-length-1 $pg_field_length_1 always;
        add_header field-mod-0 $pg_field_mod_0 always;
        add_header field-mod-1 $pg_field_mod_1 always;
        add_header field-name-0 $pg_field_name_0 always;
        add_header field-name-1 $pg_field_name_1 always;
        add_header field-oid-0 $pg_field_oid_0 always;
        add_header field-oid-1 $pg_field_oid_1 always;
        add_header value-0-0 $pg_value_0_0 always;
        add_header value-0-1 $pg_value_0_1 always;
        pg_con user=postgres database=postgres application_name=location;
        pg_out plain;
        pg_pas postgres:5432;
        pg_sql "select 12 as ab, 345 as cde";
    }
--- request
GET /
--- error_code: 200
--- response_headers
complete: SELECT 1
Content-Type: text/plain
field-length-0: 4
field-length-1: 4
field-mod-0: 42
field-mod-1: 42
field-name-0: ab
field-name-1: cde
field-oid-0: 23
field-oid-1: 23
value-0-0: 12
value-0-1: 345
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345"
--- timeout: 10
