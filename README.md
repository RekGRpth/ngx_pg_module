# Nginx raw PostgreSQL connection
it uses ragel-based PostgreSQL connection parser with zero-alloc and zero-copy

# Directives

pg_arg
-------------
* Syntax: **pg_arg** NULL | *$arg* [ *$type* ]
* Default: --
* Context: location, if in location

Sets query argument (nginx variables allowed) and type (nginx variables allowed), can be several:
```nginx
location =/ {
    pg_arg $argument $type; # argument is taken from $argument variable and type is taken from $type variable
    pg_arg $argument; # argument is taken from $argument variable and type is auto detect
    pg_arg NULL $type; # argument is NULL and type is taken from $type variable
    pg_arg NULL; # argument is NULL and type is auto detect
}
```
pg_con
-------------
* Syntax: **pg_con** *name*=*value*
* Default: --
* Context: location, if in location, upstream

Sets connection option (no nginx variables allowed), can be several:
```nginx
upstream pg {
    pg_con application_name=application_name; # set application_name
    pg_con database=database; # set database
    pg_con user=user; # set user
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream pg {
    pg_con application_name=application_name; # set application_name
    pg_con database=database; # set database
    pg_con user=user; # set user
    server unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
# or
location =/ {
    pg_con application_name=application_name; # set application_name
    pg_con database=database; # set database
    pg_con user=user; # set user
    pg_pas postgres:5432; # host is postgres and port is 5432
}
# or
location =/ {
    pg_con application_name=application_name; # set application_name
    pg_con database=database; # set database
    pg_con user=user; # set user
    pg_pas unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
```
In upstream also may use nginx keepalive module:
```nginx
upstream pg {
    keepalive 8;
    pg_con application_name=application_name; # set application_name
    pg_con database=database; # set database
    pg_con user=user; # set user
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream pg {
    keepalive 8;
    pg_con application_name=application_name; # set application_name
    pg_con database=database; # set database
    pg_con user=user; # set user
    server unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
```
pg_fun
-------------
* Syntax: **pg_fun** *$oid*
* Default: --
* Context: location, if in location

Sets function oid (nginx variables allowed) (with using [evaluate](https://github.com/RekGRpth/ngx_http_evaluate_module)):
```nginx
location =/function {
    pg_arg $arg_name;
    pg_arg $arg_schema;
    pg_out value;
    pg_pas pg;
    pg_sql "SELECT p.oid FROM pg_catalog.pg_proc AS p INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace WHERE proname = $1 AND nspname = $2";
}
location =/ {
    evaluate $now_oid /function?schema=pg_catalog&name=now;
    pg_fun $now_oid;
    pg_out value;
    pg_pas pg;
}
```
pg_log
-------------
* Syntax: **pg_log** *file* [ *level* ]
* Default: error_log logs/error.log error;
* Context: upstream

Configures logging (used when keepalive):
```nginx
upstream pg {
    pg_log /var/log/nginx/pg.err info;
}
```
pg_out
-------------
* Syntax: **pg_out** *csv* | *plain* | *value*
* Default: --
* Context: location, if in location

Configures output type (no nginx variables allowed):
```nginx
location =/ {
    pg_out csv; # set csv output
}
# or
location =/ {
    pg_out plain; # set plain output
}
# or
location =/ {
    pg_out value; # set value output (only one row and one col in result allowed)
}
```
pg_pas
-------------
* Syntax: **pg_pas** *host*:*port* | unix://*socket* | *$upstream*
* Default: --
* Context: location, if in location

Sets host (no nginx variables allowed) and port (no nginx variables allowed) or unix socket (no nginx variables allowed) or upstream (nginx variables allowed):
```nginx
location =/ {
    pg_pas postgres:5432; # host is postgres and port is 5432
}
# or
location =/ {
    pg_pas unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
# or
location =/ {
    pg_pas postgres; # upstream is postgres
}
# or
location =/ {
    pg_pas $postgres; # upstream is taken from $postgres variable
}
```
pg_sql
-------------
* Syntax: **pg_sql** *sql*
* Default: --
* Context: location, if in location

Sets SQL query (no nginx variables allowed):
```nginx
location =/ {
    pg_sql "SELECT now()"; # simple query
}
# or
location =/ {
    pg_sql "SELECT 1/0"; # simple query with error
}
# or
location =/ {
    pg_arg NULL 25; # first query argument is NULL and type of TEXTOID
    pg_arg $arg; # second query argument is taken from $arg variable and auto type
    pg_sql "SELECT $1, $2::text"; # extended query with 2 arguments
}
```
# Embedded Variables
$pg_pid
-------------
* Syntax: $pg_pid

Backend pid:
```nginx
add_header pid $pg_pid;
```
$pg_error_
-------------
* Syntax: $pg_error_*name*

Error *name* from connection:
```nginx
add_header error_column $pg_error_column;
add_header error_constraint $pg_error_constraint;
add_header error_context $pg_error_context;
add_header error_datatype $pg_error_datatype;
add_header error_detail $pg_error_detail;
add_header error_file $pg_error_file;
add_header error_function $pg_error_function;
add_header error_hint $pg_error_hint;
add_header error_internal $pg_error_internal;
add_header error_line $pg_error_line;
add_header error_nonlocalized $pg_error_nonlocalized;
add_header error_primary $pg_error_primary;
add_header error_query $pg_error_query;
add_header error_schema $pg_error_schema;
add_header error_severity $pg_error_severity;
add_header error_sqlstate $pg_error_sqlstate;
add_header error_statement $pg_error_statement;
add_header error_table $pg_error_table;
```
$pg_option_
-------------
* Syntax: $pg_option_*name*

Option *name* from connection:
```nginx
add_header option_application_name $pg_option_application_name;
add_header option_client_encoding $pg_option_client_encoding;
add_header option_datestyle $pg_option_datestyle;
add_header option_default_transaction_read_only $pg_option_default_transaction_read_only;
add_header option_in_hot_standby $pg_option_in_hot_standby;
add_header option_integer_datetimes $pg_option_integer_datetimes;
add_header option_intervalstyle $pg_option_intervalstyle;
add_header option_is_superuser $pg_option_is_superuser;
add_header option_server_encoding $pg_option_server_encoding;
add_header option_server_version $pg_option_server_version;
add_header option_session_authorization $pg_option_session_authorization;
add_header option_standard_conforming_strings $pg_option_standard_conforming_strings;
add_header option_timezone $pg_option_timezone;
```
$pg_field_mod_
-------------
* Syntax: $pg_field_mod_*col*

Result mod of *col*:
```nginx
add_header field_mod_0 $pg_field_mod_0;
add_header field_mod_1 $pg_field_mod_1;
```
$pg_field_format_
-------------
* Syntax: $pg_field_format_*col*

Result field_format_ of *col*:
```nginx
add_header field_format_0 $pg_field_format_0;
add_header field_format_1 $pg_field_format_1;
```
$pg_field_column_
-------------
* Syntax: $pg_field_column_*col*

Result field_column_ of *col*:
```nginx
add_header field_column_0 $pg_field_column_0;
add_header field_column_1 $pg_field_column_1;
```
$pg_complete
-------------
* Syntax: $pg_complete

Result complete:
```nginx
add_header complete $pg_complete;
```
$pg_field_name_
-------------
* Syntax: $pg_field_name_*col*

Result name of *col*:
```nginx
add_header field_name_0 $pg_field_name_0;
add_header field_name_1 $pg_field_name_1;
```
$pg_nfields
-------------
* Syntax: $pg_nfields

Result nfields:
```nginx
add_header nfields $pg_nfields;
```
$pg_nresults
-------------
* Syntax: $pg_nresults

Result nresults:
```nginx
add_header nresults $pg_nresults;
```
$pg_field_table_
-------------
* Syntax: $pg_field_table_*col*

Result table of *col*:
```nginx
add_header field_table_0 $pg_field_table_0;
add_header field_table_1 $pg_field_table_1;
```
$pg_field_oid_
-------------
* Syntax: $pg_field_oid_*col*

Result oid of *col*:
```nginx
add_header field_oid_0 $pg_field_oid_0;
add_header field_oid_1 $pg_field_oid_1;
```
$pg_field_length_
-------------
* Syntax: $pg_field_length_*col*

Result len of *col*:
```nginx
add_header field_length_0 $pg_field_length_0;
add_header field_length_1 $pg_field_length_1;
```
$pg_result_
-------------
* Syntax: $pg_result_*val*_*col*

Result of *val* and *col*:
```nginx
add_header result_0_0 $pg_result_0_0;
add_header result_0_1 $pg_result_0_1;
add_header result_1_0 $pg_result_1_0;
add_header result_1_1 $pg_result_1_1;
```
