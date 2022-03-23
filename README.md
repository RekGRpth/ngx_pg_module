# nginx raw postgres connection

pg_arg
-------------
* Syntax: **pg_arg** *$arg* | NULL [ *type* ]
* Default: --
* Context: location, if in location

Sets query argument and type, can be several:
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

Sets connection option(s):
```nginx
pg_connect user=user database=database application_name=application_name; # set user, database and application_name
```
pg_pass
-------------
* Syntax: **pg_pass** *host:port* | *$upstream*
* Default: --
* Context: location, if in location

Sets PostgreSQL host and port or upstream:
```nginx
pg_pass postgres:5432; # PostgreSQL host is postgres and port is 5432
pg_pass postgres; # upstream is postgres
pg_pass $postgres; # upstream is taken from $postgres variable
```
