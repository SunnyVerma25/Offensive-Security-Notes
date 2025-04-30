---
description: >-
  Developing a methodology to confirm if SQLi exists or not. Inspired by Rana
  Khalil's videos and WAHH
---

# SQLi Methodology

### **Injecting into String Data:**

1. **Confirm that the application is interacting with the database ->** This can be done with the help of the % character. The % character is a wild-card character in SQL and if inserted into a database query may return a large list of results (based on the overall data present in the database). Anyways, once it's confirmed that the specific parameter in which the % character is injected returns a lot of results, we can start testing the specific parameter for SQL-Injection vulnerabilities.

&#x20;

2. **Prove that the vulnerable query parameter exists** -> This can be tested by a single quote to break out of the SQL query that the application will have constructed to request data from the DB. Observe for any noticeable changes in the application response, whether it being an error that is returned, or if the results differs from the original result. (Look out for 500 ISEs, or any other error that appears to be related to a broken SQL query (not an error like "product not found")). But better option is to use a payload such as " <mark style="color:yellow;">`' || (SELECT '') || '`</mark> " to confirm whether the application attempts to resolve the SQL query injected into the parameter, or is the error being caused by something else. Also try to use the " <mark style="color:yellow;">`' || (SELECT '' FROM dual) || '`</mark> " to check if the DB is Oracle or Postgres

<mark style="color:yellow;">`(SELECT '')`</mark> -> This payload will return a 'NULL' value

<figure><img src="../../../.gitbook/assets/image (115).png" alt=""><figcaption><p>The SELECT '' payload will return NULL</p></figcaption></figure>

<mark style="color:yellow;">`' || NULL || '`</mark> -> This means that NULL is being concatenated with rest of the output from the other SQL queries in the context. Anything concatenated with NULL will return the same thing, thus not affecting the output in any fashion, but still telling us that SQL query injected was successfully executed, thereby confirming that SQL queries are being injected for this parameter. &#x20;

2.
