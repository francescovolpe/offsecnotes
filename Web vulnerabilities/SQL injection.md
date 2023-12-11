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
