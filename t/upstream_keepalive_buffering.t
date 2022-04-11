use Test::Nginx::Socket 'no_plan';

no_root_location;
no_shuffle;
repeat_each(2);
run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_pas pg;
        pg_sql "select 1";
        pg_upstream_buffering off;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/plain
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body chomp
1
--- timeout: 60

=== TEST 2:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header error-file $pg_error_file always;
        add_header error-function $pg_error_function always;
        add_header error-nonlocalized $pg_error_nonlocalized always;
        add_header error-primary $pg_error_primary always;
        add_header error-severity $pg_error_severity always;
        add_header error-sqlstate $pg_error_sqlstate always;
        pg_pas pg;
        pg_sql "select 1/0";
        pg_upstream_buffering off;
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
--- timeout: 60

=== TEST 3:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b 23;
        pg_out plain;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde";
        pg_upstream_buffering off;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/plain
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345"
--- timeout: 60

=== TEST 4:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b 23;
        pg_out plain;
        pg_pas pg;
        pg_sql "select $1 as ab union select $2 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/plain
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 5:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b 23;
        pg_arg $arg_c 23;
        pg_arg $arg_d 23;
        pg_out plain;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=12&b=345&c=67&d=89
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/plain
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}12\x{09}345\x{0a}67\x{09}89"
--- timeout: 60

=== TEST 6:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg NULL 25;
        pg_arg $arg_a 23;
        pg_arg $arg_b;
        pg_arg $arg_c 23;
        pg_out plain;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 2";
        pg_upstream_buffering off;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/plain
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}\\N\x{09}34\x{0a}qwe\x{09}89"
--- timeout: 60

=== TEST 7:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg NULL 25;
        pg_arg $arg_b 23;
        pg_arg $arg_c;
        pg_out plain;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=34&b=89&c=qwe
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/plain
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}\\N\x{0a}89\x{09}qwe"
--- timeout: 60

=== TEST 8:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b;
        pg_arg $arg_c 23;
        pg_arg NULL 25;
        pg_out plain;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/plain
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{09}cde\x{0a}34\x{09}qwe\x{0a}89\x{09}\\N"
--- timeout: 60

=== TEST 9:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b 23;
        pg_out csv;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde";
        pg_upstream_buffering off;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/csv
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}12,345"
--- timeout: 60

=== TEST 10:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b 23;
        pg_out csv;
        pg_pas pg;
        pg_sql "select $1 as ab union select $2 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=12&b=345
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/csv
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab\x{0a}12\x{0a}345"
--- timeout: 60

=== TEST 11:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b 23;
        pg_arg $arg_c 23;
        pg_arg $arg_d 23;
        pg_out csv;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=12&b=345&c=67&d=89
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/csv
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}12,345\x{0a}67,89"
--- timeout: 60

=== TEST 12:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg NULL 25;
        pg_arg $arg_a 23;
        pg_arg $arg_b;
        pg_arg $arg_c 23;
        pg_out csv;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 2";
        pg_upstream_buffering off;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/csv
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a},34\x{0a}qwe,89"
--- timeout: 60

=== TEST 13:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg NULL 25;
        pg_arg $arg_b 23;
        pg_arg $arg_c;
        pg_out csv;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=34&b=89&c=qwe
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/csv
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,\x{0a}89,qwe"
--- timeout: 60

=== TEST 14:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_arg $arg_a 23;
        pg_arg $arg_b;
        pg_arg $arg_c 23;
        pg_arg NULL 25;
        pg_out csv;
        pg_pas pg;
        pg_sql "select $1 as ab, $2 as cde union select $3, $4 order by 1";
        pg_upstream_buffering off;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/csv
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,"
--- timeout: 60

=== TEST 15:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header error-file $pg_error_file always;
        add_header error-function $pg_error_function always;
        add_header error-nonlocalized $pg_error_nonlocalized always;
        add_header error-primary $pg_error_primary always;
        add_header error-severity $pg_error_severity always;
        add_header error-sqlstate $pg_error_sqlstate always;
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        pg_pas pg;
        pg_sql "do $$begin raise info '%', 1;end;$$";
        pg_upstream_buffering off;
    }
--- request
GET /
--- error_code: 200
--- response_headers
Content-Type: text/plain
error-file: pl_exec.c
error-function: exec_stmt_raise
error-nonlocalized: INFO
error-primary: 1
error-severity: INFO
error-sqlstate: 00000
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- timeout: 60

=== TEST 16:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- http_config
    upstream pg {
        keepalive 1;
        pg_opt application_name=upstream;
        pg_opt database=postgres;
        pg_opt user=postgres;
        server unix:///run/postgresql/.s.PGSQL.5432;
    }
--- config
    location =/ {
        add_header option-application-name $pg_option_application_name always;
        add_header option-client-encoding $pg_option_client_encoding always;
        add_header option-integer-datetimes $pg_option_integer_datetimes always;
        add_header option-intervalstyle $pg_option_intervalstyle always;
        add_header option-is-superuser $pg_option_is_superuser always;
        add_header option-server-encoding $pg_option_server_encoding always;
        add_header option-session-authorization $pg_option_session_authorization always;
        add_header option-standard-conforming-strings $pg_option_standard_conforming_strings always;
        default_type text/csv;
        pg_pas pg;
        pg_sql "copy (select 34 as ab, 'qwe' as cde union select 89, null order by 1) to stdout with (format csv, header true)";
        pg_upstream_buffering off;
    }
--- request
GET /?a=34&b=qwe&c=89
--- error_code: 200
--- response_headers
Transfer-Encoding: chunked
Content-Type: text/csv
option-application-name: upstream
option-client-encoding: UTF8
option-integer-datetimes: on
option-intervalstyle: postgres
option-is-superuser: on
option-server-encoding: UTF8
option-session-authorization: postgres
option-standard-conforming-strings: on
--- response_body eval
"ab,cde\x{0a}34,qwe\x{0a}89,\x{0a}"
--- timeout: 60
