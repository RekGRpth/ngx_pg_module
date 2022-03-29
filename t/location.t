use Test::Nginx::Socket 'no_plan';

no_root_location;
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
