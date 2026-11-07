# **SQL Parameter Syntax Across Databases**

[https://gemini.google.com/app/c09563593cd52f6d](https://gemini.google.com/app/c09563593cd52f6d)

*User prompt: compare the syntax for sql parameters in different databases as a table*

Response:

| Database Engine | Native Parameter Syntax | Example Query | Common Driver Alternatives | Key Characteristics |
| :---- | :---- | :---- | :---- | :---- |
| **PostgreSQL** | Positional numbered ($N) | SELECT \* FROM users WHERE id \= $1 AND role \= $2; | ? (JDBC/ODBC) | Native protocol uses $1, $2. Parameter numbers can be repeated in the same query (e.g., WHERE created\_at \> $1 OR updated\_at \> $1). |
| **Microsoft SQL Server** | Named (@name) | SELECT \* FROM users WHERE id \= @id AND role \= @role; | ? (ODBC/OLE DB) | Native T-SQL (sp\_executesql) uses @ prefix. Parameters are passed by name or ordinal position in execution calls. |
| **Oracle Database** | Named (:name) or Positional (:N) | SELECT \* FROM users WHERE id \= :id AND role \= :role; | ? (JDBC) | Native OCI protocol uses colon prefixes (:name or :1). Variable names are case-insensitive by default. |
| **MySQL / MariaDB** | Positional anonymous (?) | SELECT \* FROM users WHERE id \= ? AND role \= ?; | %s, %(name)s (Python) | Server prepared statements natively accept only ?. Client drivers map named parameters to ? before sending queries. |
| **SQLite** | Multi-style (?, ?NNN, :name, @name, $name) | SELECT \* FROM users WHERE id \= :id AND role \= @role; | N/A | Native C engine directly supports positional (?, ?1), colon (:id), at-sign (@id), and dollar ($id) formats out of the box. |
| **IBM DB2** | Positional anonymous (?) or Named (:name) | SELECT \* FROM users WHERE id \= ? AND role \= ?; | :name (Embedded SQL) | Native CLI and ODBC drivers rely on ?. Embedded SQL and stored procedures support named :name syntax. |
| **Snowflake** | Positional numbered (:N) or Anonymous (?) | SELECT \* FROM users WHERE id \= :1 AND role \= :2; | %s, %(name)s (Python driver) | Native SQL uses numeric colons (:1). Connectors translate client parameters into the format required by the driver SDK. |

## **Client Driver Abstractions (PEP 249 & JDBC)**

In application development, the parameter syntax written in code often depends on the **programming language driver** rather than the database engine's native protocol.

> * **Python (PEP 249 DB-API):** Drivers declare a paramstyle module attribute:  
  * qmark: WHERE id \= ? (e.g., sqlite3, pyodbc)  
  * numeric: WHERE id \= :1 (e.g., Oracle oracledb)  
  * named: WHERE id \= :name (e.g., Oracle oracledb)  
  * format: WHERE id \= %s (e.g., psycopg2, mysql-connector-python)  
  * pyformat: WHERE id \= %(id)s (e.g., psycopg2, mysql-connector-python)  
> * **JDBC (Java):** Standardizes placeholders to positional ? across all relational database vendors, automatically converting them to vendor-native syntax under the hood.  
> * **ADO.NET (C\# / .NET):** Uses @ named parameters (e.g., @id), mapping them to positional placeholders if required by underlying database protocols.

---

