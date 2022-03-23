# nginx raw postgres connection

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
