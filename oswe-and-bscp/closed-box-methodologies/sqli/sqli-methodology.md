---
description: >-
  Developing a methodology to confirm if SQLi exists or not. Inspired by Rana
  Khalil's videos
---

# SQLi Methodology

1. **Prove that the vulnerable query parameter exists** -> This can be tested by a single quote, and then two single quotes to check if  the underlying SQL query breaks, and if the app gives us an error. Look out for 500 ISEs, or any other error that appears to be related to a broken SQL query (not an error like "product not found". But better option is to use a payload such as " <mark style="color:yellow;">`' || (SELECT '') || '`</mark> " to confirm whether the application attempts to resolve the SQL query injected into the parameter, or is the error being caused by something else. Also try to use the " <mark style="color:yellow;">`' || (SELECT '' FROM dual) || '`</mark> " to check if the DB is Oracle or Postgres

<mark style="color:yellow;">`(SELECT '')`</mark> -> This payload will return a 'NULL' value

<figure><img src="../../../.gitbook/assets/image (115).png" alt=""><figcaption><p>The SELECT '' payload will return NULL</p></figcaption></figure>

<mark style="color:yellow;">`' || NULL || '`</mark> -> This means that NULL is being concatenated with rest of the output from the other SQL queries in the context. Anything concatenated with NULL will return the same thing, thus not affecting the output in any fashion, but still telling us that SQL query injected was successfully executed, thereby confirming that SQL queries are being injected for this parameter. &#x20;

2.
