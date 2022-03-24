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
pg_arg NULL; # query argument is NULL and auto type
pg_arg NULL 25; # query argument is NULL and type of TEXTOID
pg_arg $arg; # query argument is taken from $arg variable and auto type
pg_arg $arg 25; # query argument is taken from $arg variable and type of TEXTOID
```
pg_con
-------------
* Syntax: **pg_con** *option=value* [ ... ]
* Default: --
* Context: location, if in location, upstream

Sets connection option(s) (no nginx variables allowed):
```nginx
pg_con user=user database=database application_name=application_name; # set user, database and application_name
```
pg_pas
-------------
* Syntax: **pg_pas** *host:port* | *$upstream*
* Default: --
* Context: location, if in location

Sets PostgreSQL host and port or upstream (nginx variables allowed):
```nginx
pg_pas postgres:5432; # PostgreSQL host is postgres and port is 5432
pg_pas postgres; # upstream is postgres
pg_pas $postgres; # upstream is taken from $postgres variable
```
pg_sql
-------------
* Syntax: **pg_sql** *sql*
* Default: --
* Context: location, if in location

Sets SQL query (no nginx variables allowed):
```nginx
pg_sql "select 1"; # simple query
pg_sql "select 1/0"; # simple query with error
pg_sql "select now()"; # simple query
pg_sql "select $1, $2"; # extended query with 2 arguments, which must be defined abowe
```
# Embedded Variables
$pg_error_
-------------
* Syntax: $pg_error_*name*

Error *name* from connection:
```nginx
add_header column $pg_error_column always;
add_header constraint $pg_error_constraint always;
add_header context $pg_error_context always;
add_header datatype $pg_error_datatype always;
add_header detail $pg_error_detail always;
add_header file $pg_error_file always;
add_header function $pg_error_function always;
add_header hint $pg_error_hint always;
add_header internal $pg_error_internal always;
add_header line $pg_error_line always;
add_header nonlocalized $pg_error_nonlocalized always;
add_header primary $pg_error_primary always;
add_header query $pg_error_query always;
add_header schema $pg_error_schema always;
add_header severity $pg_error_severity always;
add_header sqlstate $pg_error_sqlstate always;
add_header statement $pg_error_statement always;
add_header table $pg_error_table always;
```
$pg_option_
-------------
* Syntax: $pg_option_*name*

Option *name* from connection:
```nginx
add_header application_name $pg_option_application_name always;
add_header client_encoding $pg_option_client_encoding always;
add_header DateStyle $pg_option_DateStyle always;
add_header default_transaction_read_only $pg_option_default_transaction_read_only always;
add_header in_hot_standby $pg_option_in_hot_standby always;
add_header integer_datetimes $pg_option_integer_datetimes always;
add_header IntervalStyle $pg_option_IntervalStyle always;
add_header is_superuser $pg_option_is_superuser always;
add_header server_encoding $pg_option_server_encoding always;
add_header server_version $pg_option_server_version always;
add_header session_authorization $pg_option_session_authorization always;
add_header standard_conforming_strings $pg_option_standard_conforming_strings always;
add_header TimeZone $pg_option_TimeZone always;
```
