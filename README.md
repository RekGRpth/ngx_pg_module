deprecated, use https://github.com/RekGRpth/ngx_pq_module instead

# Nginx raw PostgreSQL connection
it uses ragel-based PostgreSQL connection parser with zero-alloc and zero-copy

# Directives

pg_execute
-------------
* Syntax: **pg_execute** *$query* [ *$arg* ] [ output=*csv* | output=*plain* | output=*value* | output=*$variable* ]
* Default: --
* Context: location, if in location, upstream

Executes query(queries) (nginx variables allowed) sql(s) (named only nginx variables allowed as identifier only), optional argument(s) (nginx variables allowed) and output type (no nginx variables allowed):
```nginx
location =/postgres {
    pg_pass postgres; # upstream is postgres
    pg_execute $query str $arg output=plain; # execute extended query wich name is taken from $query variable with two arguments: first query argument is str and second query argument is taken from $arg variable and plain output type
}
```
pg_function
-------------
* Syntax: **pg_function** *$oid* [ *$arg* | *$arg*::*$oid* ] [ output=*value* ]
* Default: --
* Context: location, if in location, upstream

Sets function(s) oid (nginx variables allowed), optional argument(s) (nginx variables allowed) and it(s) oid(s) (nginx variables allowed) and output type (no nginx variables allowed):
```nginx
upstream postgres {
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    pg_query "select p.oid from pg_catalog.pg_proc as p inner join pg_catalog.pg_namespace as n on n.oid = p.pronamespace where proname = $1 and nspname = $2" now pg_catalog output=$now_oid; # extended query with two string arguments to variable
    server postgres:5432; # host is postgres and port is 5432
}
location =/now {
    pg_function $now_oid output=value; # call function by its oid
    pg_pass postgres; # upstream is postgres
}
```
pg_log
-------------
* Syntax: **pg_log** *file* [ *level* ]
* Default: error_log logs/error.log error;
* Context: upstream

Sets logging (used when keepalive):
```nginx
upstream postgres {
    pg_log /var/log/nginx/pg.err info; # set log level
}
```
pg_option
-------------
* Syntax: **pg_option** *name*=*value*
* Default: --
* Context: location, if in location, upstream

Sets connection option(s) (no nginx variables allowed), can be several:
```nginx
upstream postgres {
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream postgres {
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    server unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
# or
location =/postgres {
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    pg_pass postgres:5432; # host is postgres and port is 5432
}
# or
location =/postgres {
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    pg_pass unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
```
In upstream also may use nginx keepalive module:
```nginx
upstream postgres {
    keepalive 8;
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    server postgres:5432; # host is postgres and port is 5432
}
# or
upstream postgres {
    keepalive 8;
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    server unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
```
pg_prepare
-------------
* Syntax: **pg_prepare** *$query* *sql* [ *$oid* ]
* Default: --
* Context: location, if in location, upstream

Prepare query(queries) (nginx variables allowed) sql(s) (named only nginx variables allowed as identifier only), optional argument(s)'s oid(s) (nginx variables allowed):
```nginx
location =/postgres {
    pg_pass postgres; # upstream is postgres
    pg_prepare $query "SELECT $1, $2::text" 25 ""; # parser query wich name is taken from $query variable and two arguments: first query argument oid is 25 (TEXTOID) and second query argument is auto oid
}
# or
upstream postgres {
    pg_option user=user database=database application_name=application_name; # set user, database and application_name
    pg_prepare $query "SELECT $1, $2::text" 25 ""; # parser query wich name is taken from $query variable and two arguments: first query argument oid is 25 (TEXTOID) and second query argument is auto oid
    server postgres:5432; # host is postgres and port is 5432
}
```
pg_pass
-------------
* Syntax: **pg_pass** *host*:*port* | unix://*socket* | *$upstream*
* Default: --
* Context: location, if in location

Sets host (no nginx variables allowed) and port (no nginx variables allowed) or unix socket (no nginx variables allowed) or upstream (nginx variables allowed):
```nginx
location =/postgres {
    pg_pass postgres:5432; # host is postgres and port is 5432
}
# or
location =/postgres {
    pg_pass unix:///run/postgresql/.s.PGSQL.5432; # unix socket connetion
}
# or
location =/postgres {
    pg_pass postgres; # upstream is postgres
}
# or
location =/postgres {
    pg_pass $postgres; # upstream is taken from $postgres variable
}
```
pg_query
-------------
* Syntax: **pg_query** *sql* [ *$arg* | *$arg*::*$oid* ] [ output=*csv* | output=*plain* | output=*value* | output=*$variable* ]
* Default: --
* Context: location, if in location, upstream

Sets query(queries) sql(s) (named only nginx variables allowed as identifier only), optional argument(s) (nginx variables allowed) and it(s) oid(s) (nginx variables allowed) and output type (no nginx variables allowed):
```nginx
location =/postgres {
    pg_pass postgres; # upstream is postgres
    pg_query "SELECT now()" output=csv; # simple query and csv output type
}
# or
location =/postgres {
    pg_pass postgres; # upstream is postgres
    pg_query "listen $channel"; # listen channel from variable $channel
}
# or
location =/postgres {
    pg_pass postgres; # upstream is postgres
    pg_query "SELECT 1/0"; # simple query with error
}
# or
location =/postgres {
    pg_pass postgres; # upstream is postgres
    pg_query "SELECT $1, $2::text" str::25 $arg output=plain; # extended query with two arguments: first query argument is str and its oid is 25 (TEXTOID) and second query argument is taken from $arg variable and auto oid and plain output type
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
