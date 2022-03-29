# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 8);

run_tests();

__DATA__

=== TEST 1:
--- main_config
    load_module /etc/nginx/modules/ngx_pg_module.so;
--- config
    location =/pg {
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
GET /pg
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
