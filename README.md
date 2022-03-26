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
$pg_col_mod_
-------------
* Syntax: $pg_col_mod_*col*

Result mod of *col*:
```nginx
add_header col_mod_0 $pg_col_mod_0 always;
add_header col_mod_1 $pg_col_mod_1 always;
```
$pg_col_fmt_
-------------
* Syntax: $pg_col_fmt_*col*

Result col_fmt_ of *col*:
```nginx
add_header col_fmt_0 $pg_col_fmt_0 always;
add_header col_fmt_1 $pg_col_fmt_1 always;
```
$pg_column_
-------------
* Syntax: $pg_column_*col*

Result col of *col*:
```nginx
add_header col_col_0 $pg_col_col_0 always;
add_header col_col_1 $pg_col_col_1 always;
```
$pg_cmd
-------------
* Syntax: $pg_cmd

Result command:
```nginx
add_header command $pg_cmd always;
```
$pg_col_name_
-------------
* Syntax: $pg_col_name_*col*

Result name of *col*:
```nginx
add_header col_name_0 $pg_col_name_0 always;
add_header col_name_1 $pg_col_name_1 always;
```
$pg_ncols
-------------
* Syntax: $pg_ncols

Result ncols:
```nginx
add_header ncols $pg_ncols always;
```
$pg_table_
-------------
* Syntax: $pg_table_*col*

Result tbl of *col*:
```nginx
add_header tbl_0 $pg_tbl_0 always;
add_header tbl_1 $pg_tbl_1 always;
```
$pg_oid_
-------------
* Syntax: $pg_oid_*col*

Result oid of *col*:
```nginx
add_header oid_0 $pg_oid_0 always;
add_header oid_1 $pg_oid_1 always;
```
$pg_col_len_
-------------
* Syntax: $pg_col_len_*col*

Result len of *col*:
```nginx
add_header col_len_0 $pg_col_len_0 always;
add_header col_len_1 $pg_col_len_1 always;
```
$pg_row_
-------------
* Syntax: $pg_row_*row*_*col*

Result of *row* and *col*:
```nginx
add_header row_0_0 $pg_row_0_0 always;
add_header row_0_1 $pg_row_0_1 always;
add_header row_1_0 $pg_row_1_0 always;
add_header row_1_1 $pg_row_1_1 always;
```
