# Nginx raw PostgreSQL connection
it uses ragel-based PostgreSQL connection parser with zero-alloc and zero-copy

# Directives

pg_arg
-------------
* Syntax: **pg_arg** *$arg* | NULL [ *type* ]
* Default: --
* Context: location, if in location

Sets query argument (nginx variables allowed) and type (no nginx variables allowed), can be several:
```nginx
location = /pg {
    pg_arg NULL; # first query argument is NULL and auto type
    pg_arg NULL 25; # second query argument is NULL and type of TEXTOID
    pg_arg $arg; # third query argument is taken from $arg variable and auto type
    pg_arg $arg 25; # fourth query argument is taken from $arg variable and type of TEXTOID
}
```
pg_con
-------------
* Syntax: **pg_con** *option=value* [ ... ]
* Default: --
* Context: location, if in location, upstream

Sets connection option(s) (no nginx variables allowed):
```nginx
upstream pg {
    keepalive 8; # may use nginx keepalive module
    pg_con user=user database=database application_name=application_name; # set user, database and application_name
    server postgres:5432; # add server with host postgres and port 5432
}
# or
location = /pg {
    pg_con user=user database=database application_name=application_name; # set user, database and application_name
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
pg_pas
-------------
* Syntax: **pg_pas** *host:port* | *$upstream*
* Default: --
* Context: location, if in location

Sets PostgreSQL host and port or upstream (nginx variables allowed):
```nginx
location = /pg {
    pg_pas postgres:5432; # PostgreSQL host is postgres and port is 5432
}
# or
location = /pg {
    pg_pas postgres; # upstream is postgres
}
# or
location = /pg {
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
location = /pg {
    pg_sql "select now()"; # simple query
}
# or
location = /pg {
    pg_sql "select 1/0"; # simple query with error
}
# or
location = /pg {
    pg_arg NULL 25; # first query argument is NULL and type of TEXTOID
    pg_arg $arg; # second query argument is taken from $arg variable and auto type
    pg_sql "select $1, $2::text"; # extended query with 2 arguments
}
```
# Embedded Variables
$pg_pid
-------------
* Syntax: $pg_pid

Backend pid:
```nginx
add_header pid $pg_pid always;
```
$pg_err_
-------------
* Syntax: $pg_err_*name*

Error *name* from connection:
```nginx
add_header err_column $pg_err_column always;
add_header err_constraint $pg_err_constraint always;
add_header err_context $pg_err_context always;
add_header err_datatype $pg_err_datatype always;
add_header err_detail $pg_err_detail always;
add_header err_file $pg_err_file always;
add_header err_function $pg_err_function always;
add_header err_hint $pg_err_hint always;
add_header err_internal $pg_err_internal always;
add_header err_line $pg_err_line always;
add_header err_nonlocalized $pg_err_nonlocalized always;
add_header err_primary $pg_err_primary always;
add_header err_query $pg_err_query always;
add_header err_schema $pg_err_schema always;
add_header err_severity $pg_err_severity always;
add_header err_sqlstate $pg_err_sqlstate always;
add_header err_statement $pg_err_statement always;
add_header err_table $pg_err_table always;
```
$pg_opt_
-------------
* Syntax: $pg_opt_*name*

Option *name* from connection:
```nginx
add_header opt_application_name $pg_opt_application_name always;
add_header opt_client_encoding $pg_opt_client_encoding always;
add_header opt_datestyle $pg_opt_datestyle always;
add_header opt_default_transaction_read_only $pg_opt_default_transaction_read_only always;
add_header opt_in_hot_standby $pg_opt_in_hot_standby always;
add_header opt_integer_datetimes $pg_opt_integer_datetimes always;
add_header opt_intervalstyle $pg_opt_intervalstyle always;
add_header opt_is_superuser $pg_opt_is_superuser always;
add_header opt_server_encoding $pg_opt_server_encoding always;
add_header opt_server_version $pg_opt_server_version always;
add_header opt_session_authorization $pg_opt_session_authorization always;
add_header opt_standard_conforming_strings $pg_opt_standard_conforming_strings always;
add_header opt_timezone $pg_opt_timezone always;
```
$pg_field_mod_
-------------
* Syntax: $pg_field_mod_*col*

Result mod of *col*:
```nginx
add_header field_mod_0 $pg_field_mod_0 always;
add_header field_mod_1 $pg_field_mod_1 always;
```
$pg_field_format_
-------------
* Syntax: $pg_field_format_*col*

Result field_format_ of *col*:
```nginx
add_header field_format_0 $pg_field_format_0 always;
add_header field_format_1 $pg_field_format_1 always;
```
$pg_field_column_
-------------
* Syntax: $pg_field_column_*col*

Result field_column_ of *col*:
```nginx
add_header field_column_0 $pg_field_column_0 always;
add_header field_column_1 $pg_field_column_1 always;
```
$pg_cmd
-------------
* Syntax: $pg_cmd

Result cmd:
```nginx
add_header cmd $pg_cmd always;
```
$pg_field_name_
-------------
* Syntax: $pg_field_name_*col*

Result name of *col*:
```nginx
add_header field_name_0 $pg_field_name_0 always;
add_header field_name_1 $pg_field_name_1 always;
```
$pg_ncols
-------------
* Syntax: $pg_ncols

Result ncols:
```nginx
add_header ncols $pg_ncols always;
```
$pg_nvals
-------------
* Syntax: $pg_nvals

Result nvals:
```nginx
add_header nvals $pg_nvals always;
```
$pg_field_table_
-------------
* Syntax: $pg_field_table_*col*

Result table of *col*:
```nginx
add_header field_table_0 $pg_field_table_0 always;
add_header field_table_1 $pg_field_table_1 always;
```
$pg_field_oid_
-------------
* Syntax: $pg_field_oid_*col*

Result oid of *col*:
```nginx
add_header field_oid_0 $pg_field_oid_0 always;
add_header field_oid_1 $pg_field_oid_1 always;
```
$pg_field_len_
-------------
* Syntax: $pg_field_len_*col*

Result len of *col*:
```nginx
add_header field_len_0 $pg_field_len_0 always;
add_header field_len_1 $pg_field_len_1 always;
```
$pg_val_
-------------
* Syntax: $pg_val_*val*_*col*

Result of *val* and *col*:
```nginx
add_header val_0_0 $pg_val_0_0 always;
add_header val_0_1 $pg_val_0_1 always;
add_header val_1_0 $pg_val_1_0 always;
add_header val_1_1 $pg_val_1_1 always;
```
