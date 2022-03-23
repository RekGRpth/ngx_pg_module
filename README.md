nginx raw postgres connection

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
pg_connect
-------------
* Syntax: **pg_connect** *option=value* [ ... ]
* Default: --
* Context: location, if in location, upstream

Sets connection option(s) (no nginx variables allowed):
```nginx
pg_connect user=user database=database application_name=application_name; # set user, database and application_name
```
pg_pass
-------------
* Syntax: **pg_pass** *host:port* | *$upstream*
* Default: --
* Context: location, if in location

Sets PostgreSQL host and port or upstream (nginx variables allowed):
```nginx
pg_pass postgres:5432; # PostgreSQL host is postgres and port is 5432
pg_pass postgres; # upstream is postgres
pg_pass $postgres; # upstream is taken from $postgres variable
```
pg_query
-------------
* Syntax: **pg_query** *sql*
* Default: --
* Context: location, if in location

Sets SQL query (no nginx variables allowed):
```nginx
pg_query "select 1"; # simple query
pg_query "select 1/0"; # simple query with error
pg_query "select now()"; # simple query
pg_query "select $1, $2"; # extended query with 2 arguments, which must be defined abowe
```
# Embedded Variables
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
