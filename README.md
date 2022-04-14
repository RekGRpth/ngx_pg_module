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
    pg_pas pg;
    pg_sql "SELECT p.oid FROM pg_catalog.pg_proc AS p INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace WHERE proname = $1 AND nspname = $2";
}
location =/ {
    evaluate $now_oid /function?schema=pg_catalog&name=now;
    pg_fun $now_oid;
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
pg_opt
-------------
* Syntax: **pg_opt** *name*=*value*
* Default: --
* Context: location, if in location, upstream

Sets connection option (no nginx variables allowed), can be several:
```nginx
upstream pg {
    pg_opt application_name=application_name; # set application_name
    pg_opt database=database; # set database
    pg_opt user=user; # set user
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream pg {
    pg_opt application_name=application_name; # set application_name
    pg_opt database=database; # set database
    pg_opt user=user; # set user
    server unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
# or
location =/ {
    pg_opt application_name=application_name; # set application_name
    pg_opt database=database; # set database
    pg_opt user=user; # set user
    pg_pas postgres:5432; # host is postgres and port is 5432
}
# or
location =/ {
    pg_opt application_name=application_name; # set application_name
    pg_opt database=database; # set database
    pg_opt user=user; # set user
    pg_pas unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
```
In upstream also may use nginx keepalive module:
```nginx
upstream pg {
    keepalive 8;
    pg_opt application_name=application_name; # set application_name
    pg_opt database=database; # set database
    pg_opt user=user; # set user
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream pg {
    keepalive 8;
    pg_opt application_name=application_name; # set application_name
    pg_opt database=database; # set database
    pg_opt user=user; # set user
    server unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
```
pg_out
-------------
* Syntax: **pg_out** *csv* | *plain*
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
$pg_error_
-------------
* Syntax: $pg_error_*name*

Error *name* from connection:
```nginx
add_header error_column $pg_error_column always;
add_header error_constraint $pg_error_constraint always;
add_header error_context $pg_error_context always;
add_header error_datatype $pg_error_datatype always;
add_header error_detail $pg_error_detail always;
add_header error_file $pg_error_file always;
add_header error_function $pg_error_function always;
add_header error_hint $pg_error_hint always;
add_header error_internal $pg_error_internal always;
add_header error_line $pg_error_line always;
add_header error_nonlocalized $pg_error_nonlocalized always;
add_header error_primary $pg_error_primary always;
add_header error_query $pg_error_query always;
add_header error_schema $pg_error_schema always;
add_header error_severity $pg_error_severity always;
add_header error_sqlstate $pg_error_sqlstate always;
add_header error_statement $pg_error_statement always;
add_header error_table $pg_error_table always;
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
$pg_pid
-------------
* Syntax: $pg_pid

Backend pid:
```nginx
add_header pid $pg_pid;
```
