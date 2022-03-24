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
$pg_con_pid
-------------
* Syntax: $pg_con_pid

Backend pid:
```nginx
add_header pid $pg_con_pid always;
```
$pg_err_
-------------
* Syntax: $pg_err_*name*

Error *name* from connection:
```nginx
add_header column $pg_err_column always;
add_header constraint $pg_err_constraint always;
add_header context $pg_err_context always;
add_header datatype $pg_err_datatype always;
add_header detail $pg_err_detail always;
add_header file $pg_err_file always;
add_header function $pg_err_function always;
add_header hint $pg_err_hint always;
add_header internal $pg_err_internal always;
add_header line $pg_err_line always;
add_header nonlocalized $pg_err_nonlocalized always;
add_header primary $pg_err_primary always;
add_header query $pg_err_query always;
add_header schema $pg_err_schema always;
add_header severity $pg_err_severity always;
add_header sqlstate $pg_err_sqlstate always;
add_header statement $pg_err_statement always;
add_header table $pg_err_table always;
```
$pg_opt_
-------------
* Syntax: $pg_opt_*name*

Option *name* from connection:
```nginx
add_header application_name $pg_opt_application_name always;
add_header client_encoding $pg_opt_client_encoding always;
add_header datestyle $pg_opt_datestyle always;
add_header default_transaction_read_only $pg_opt_default_transaction_read_only always;
add_header in_hot_standby $pg_opt_in_hot_standby always;
add_header integer_datetimes $pg_opt_integer_datetimes always;
add_header intervalstyle $pg_opt_intervalstyle always;
add_header is_superuser $pg_opt_is_superuser always;
add_header server_encoding $pg_opt_server_encoding always;
add_header server_version $pg_opt_server_version always;
add_header session_authorization $pg_opt_session_authorization always;
add_header standard_conforming_strings $pg_opt_standard_conforming_strings always;
add_header timezone $pg_opt_timezone always;
```
$pg_res_nfields
-------------
* Syntax: $pg_res_nfields

Result nfields:
```nginx
add_header nfields $pg_res_nfields always;
```
$pg_res_command
-------------
* Syntax: $pg_res_command

Result command:
```nginx
add_header command $pg_res_command always;
```
$pg_res_atttypmod_
-------------
* Syntax: $pg_res_atttypmod_*number*

Result atttypmod of *number* field:
```nginx
add_header atttypmod_0 $pg_res_atttypmod_0 always;
add_header atttypmod_1 $pg_res_atttypmod_1 always;
```
$pg_res_columnid_
-------------
* Syntax: $pg_res_columnid_*number*

Result columnid of *number* field:
```nginx
add_header columnid_0 $pg_res_columnid_0 always;
add_header columnid_1 $pg_res_columnid_1 always;
```
$pg_res_format_
-------------
* Syntax: $pg_res_format_*number*

Result format of *number* field:
```nginx
add_header format_0 $pg_res_format_0 always;
add_header format_1 $pg_res_format_1 always;
```
$pg_res_name_
-------------
* Syntax: $pg_res_name_*number*

Result name of *number* field:
```nginx
add_header name_0 $pg_res_name_0 always;
add_header name_1 $pg_res_name_1 always;
```
$pg_res_tableid_
-------------
* Syntax: $pg_res_tableid_*number*

Result tableid of *number* field:
```nginx
add_header tableid_0 $pg_res_tableid_0 always;
add_header tableid_1 $pg_res_tableid_1 always;
```
$pg_res_typid_
-------------
* Syntax: $pg_res_typid_*number*

Result typid of *number* field:
```nginx
add_header typid_0 $pg_res_typid_0 always;
add_header typid_1 $pg_res_typid_1 always;
```
$pg_res_typlen_
-------------
* Syntax: $pg_res_typlen_*number*

Result typlen of *number* field:
```nginx
add_header typlen_0 $pg_res_typlen_0 always;
add_header typlen_1 $pg_res_typlen_1 always;
```
