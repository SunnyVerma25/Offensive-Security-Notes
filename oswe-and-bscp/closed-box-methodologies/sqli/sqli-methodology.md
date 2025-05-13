---
description: >-
  Developing a methodology to confirm if SQLi exists or not. Inspired by Rana
  Khalil's videos and WAHH
---

# SQLi Methodology

## **Injecting into String Data:**

1. **Confirm that the application is interacting with the database ->** This can be done with the help of the <mark style="color:yellow;">`%`</mark> character. The <mark style="color:yellow;">`%`</mark> character is a wild-card character in SQL and if inserted into a database query may return a large list of results (based on the overall data present in the database). Anyways, once it's confirmed that the specific parameter in which the <mark style="color:yellow;">`%`</mark> character is injected returns a lot of results, we can start testing the specific parameter for SQL-Injection vulnerabilities.

&#x20;

2. **Prove that the vulnerable query parameter exists** -> This can be tested by a single quote to break out of the SQL query that the application will have constructed to request data from the DB. Observe for any noticeable changes in the application response, whether it being an error that is returned, or if the results differs from the original result. (Look out for 500 ISEs, or any other error that appears to be related to a broken SQL query (not an error like "product not found")). Then, we inject another single quote to complete the query started by the first single quote character we injected, and look to see if we are getting the same results that we would get without injecting the single quote. Then, to validate the SQLi vulnerability, an option is to use concatenation characters in SQL, such as a payload that is " <mark style="color:yellow;">`' || (SELECT '') || '`</mark> " to confirm whether the application attempts to resolve the SQL query injected into the parameter, or is the error being caused by something else. Also try to use the " <mark style="color:yellow;">`' || (SELECT '' FROM dual) || '`</mark> " to check if the DB is Oracle or Postgres

<mark style="color:yellow;">`(SELECT '')`</mark> -> This payload will return a 'NULL' value

<figure><img src="../../../.gitbook/assets/image (115).png" alt=""><figcaption><p>The SELECT '' payload will return NULL</p></figcaption></figure>

<mark style="color:yellow;">`' || NULL || '`</mark> -> This means that NULL is being concatenated with rest of the output from the other SQL queries in the context. Anything concatenated with NULL will return the same thing, thus not affecting the output in any fashion, but still telling us that SQL query injected was successfully executed, thereby confirming that SQL queries are being injected for this parameter. &#x20;

## **Injecting into Integer Data:**

**If numerical data is being transmitted to the database by the application, chances are that this numerical value is being transmitted as it is, and is not being transmitted into a string. As a result, it is advised that we perform the above-mentioned attacks to confirm the presence of SQLi but along with that, also perform the following steps:**

1. **Submit a mathematical expression:** If there's a parameter that accepts numerical value <mark style="color:yellow;">`2004`</mark>, try injecting <mark style="color:yellow;">`2006-2`</mark> or <mark style="color:yellow;">`2000+4`</mark>, and check if the response returned by the application is the same that is returned when <mark style="color:yellow;">`2004`</mark> is injected into the parameter. If the response returned is the same, than the parameter may be vulnerable

<figure><img src="../../../.gitbook/assets/image (120).png" alt=""><figcaption><p>The year requested is 2004</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (119).png" alt=""><figcaption><p>Th year requested is 2006-2 (which is 2004), and the database does resolve it and returns the result for 2004</p></figcaption></figure>

2. **Submit an expression containing SQL methods in it to analyze if the expression is being resolved**: If the above case resolves properly, try injecting a payload that contains a SQL method, and observe if the result is the same. For example, a common SQL method is ASCII(), which can be used to convert the value of the character to it's ASCII value. So, in the below example. we can use the payload 1+ASCII(1) to retrieve the details for the user Clark, since Clark's empId = 50 and ASCII(1)=49.&#x20;

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption><p>The original database</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>The empId solves the arithmetic expression involving the SQL ASCII method</p></figcaption></figure>

## Edge cases:&#x20;

1. **sort keyword**: If in an application, the user is able to supply a user-controlled input to determine how the results should be sorted (in ascending or descending order), it may open up the attack surface for SQLi, especially that the application allows the user to supply the sort order keyword (ASC or DESC). Imagine that we have a bookstore on which users can fetch books belonging to different genre and can be viewed based on prices.&#x20;

<figure><img src="../../../.gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

Chances are that the SQL query may look like:

<mark style="color:yellow;">`SELECT name,title,price FROM bookstore WHERE genre = 'Thriller' ORDER BY price asc;`</mark>

Now, if this price and the asc keywords are user-supplied (seen in many applications, and the screenshot above), then the price and the asc keywords will be directly added to the ORDER BY clause (in the case of a vulnerable app). As such, an attacker can instead supply a SQLi payload such as the following:&#x20;

<figure><img src="../../../.gitbook/assets/image (123).png" alt=""><figcaption></figcaption></figure>

<mark style="color:yellow;">`SELECT name,title,price FROM bookstore WHERE genre = 'Thriller' ORDER BY price';--`</mark>

Thereby breaking the SQL query and causing an error (since there will be an extra single-quote character that is not required).

For blind-sqli, we can use a time-based injection with the following payload:

<mark style="color:yellow;">`(CASE WHEN 1=1 THEN pg_sleep(5) ELSE price END)`</mark>

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

The query becomes <mark style="color:yellow;">`SELECT name,title,price FROM bookstore WHERE genre = 'Thriller' ORDER BY (CASE WHEN 1=1 THEN pg_sleep(5) ELSE price END)`</mark>&#x20;

***

## Fingerprinting Database Information

While there's the classic way of injecting queries such as @@VERSION or other similar queries to identify the exact database we are dealing with in the application, there maybe cases where these strings are not working as expected. As such, we have alternative ways of confirming at least the database type by performing the following actions:&#x20;

### Injecting into strings:&#x20;

Each database-type handles concatenating strings differently. Here's an example to explain things:

Assume that we have the following database:

<figure><img src="../../../.gitbook/assets/image (125).png" alt=""><figcaption></figcaption></figure>

Now, if we perform the following query, we will get information for the user 'Clark':

<mark style="color:yellow;">`SELECT * FROM EMPLOYEE WHERE name='Clark';`</mark>

<figure><img src="../../../.gitbook/assets/image (126).png" alt=""><figcaption></figcaption></figure>

However, if we inject the following query, we also get the results for the user Clark.&#x20;

<mark style="color:yellow;">`SELECT * FROM EMPLOYEE WHERE name='Cla' 'rk';`</mark>

<figure><img src="../../../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>

Hence, we can use this technique when testing parameter values to confirm which database may be being used by the application. One case would be to use the normal string (clark in our case) to observe the results. Then, use different iterations of clark (such as 'cla' 'rk', 'cla''rk', 'cla' || 'rk') etc to determine which iteration returns a similar result. That may help determine the correct database. Since we are using MySQL, using a payload such as 'cla''rk' (notice the missing space) will not yield the right result

<figure><img src="../../../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>
