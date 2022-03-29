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
pg_out
-------------
* Syntax: **pg_out** *csv* | *plain* | *value*
* Default: --
* Context: location, if in location

Configures output:
```nginx
location = /pg {
    pg_out csv;
}
# or
location = /pg {
    pg_out plain;
}
# or
location = /pg {
    pg_out value;
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
add_header option_application_name $pg_option_application_name always;
add_header option_client_encoding $pg_option_client_encoding always;
add_header option_datestyle $pg_option_datestyle always;
add_header option_default_transaction_read_only $pg_option_default_transaction_read_only always;
add_header option_in_hot_standby $pg_option_in_hot_standby always;
add_header option_integer_datetimes $pg_option_integer_datetimes always;
add_header option_intervalstyle $pg_option_intervalstyle always;
add_header option_is_superuser $pg_option_is_superuser always;
add_header option_server_encoding $pg_option_server_encoding always;
add_header option_server_version $pg_option_server_version always;
add_header option_session_authorization $pg_option_session_authorization always;
add_header option_standard_conforming_strings $pg_option_standard_conforming_strings always;
add_header option_timezone $pg_option_timezone always;
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
$pg_complete
-------------
* Syntax: $pg_complete

Result complete:
```nginx
add_header complete $pg_complete always;
```
$pg_field_name_
-------------
* Syntax: $pg_field_name_*col*

Result name of *col*:
```nginx
add_header field_name_0 $pg_field_name_0 always;
add_header field_name_1 $pg_field_name_1 always;
```
$pg_nfields
-------------
* Syntax: $pg_nfields

Result nfields:
```nginx
add_header nfields $pg_nfields always;
```
$pg_nresults
-------------
* Syntax: $pg_nresults

Result nresults:
```nginx
add_header nresults $pg_nresults always;
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
$pg_field_length_
-------------
* Syntax: $pg_field_length_*col*

Result len of *col*:
```nginx
add_header field_length_0 $pg_field_length_0 always;
add_header field_length_1 $pg_field_length_1 always;
```
$pg_result_
-------------
* Syntax: $pg_result_*val*_*col*

Result of *val* and *col*:
```nginx
add_header result_0_0 $pg_result_0_0 always;
add_header result_0_1 $pg_result_0_1 always;
add_header result_1_0 $pg_result_1_0 always;
add_header result_1_1 $pg_result_1_1 always;
```
