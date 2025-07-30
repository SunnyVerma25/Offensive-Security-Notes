---
description: Burp Lab Solutions with walkthrough and understanding
---

# Burp Lab Solutions

***

### <mark style="color:yellow;">SQL injection vulnerability in WHERE clause allowing retrieval of hidden data</mark>

Lab description mentions that the vulnerability lies in the "category" parameter, as the user can select products from different categories.&#x20;

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption><p>The vulnerable application</p></figcaption></figure>

The vulnerable request looks like:&#x20;

[https://0a8c00fb047975cf822f01c2003a00bf.web-security-academy.net/filter?category=Lifestyle](https://0a8c00fb047975cf822f01c2003a00bf.web-security-academy.net/filter?category=Lifestyle%27+AND+1%3d1--)

The backend SQL query may look something like:

<mark style="color:yellow;">`SELECT * FROM product WHERE category='Gifts'`</mark>

Now, what if we enter a ' after Gifts to see what happens

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption><p>We get a 500 ISE. Interesting!</p></figcaption></figure>

So now, what if we enter <mark style="color:yellow;">`' AND 1=1--`</mark>, so that request (after URL encoding) looks like:

<mark style="color:yellow;">`https://0a8c00fb047975cf822f01c2003a00bf.web-security-academy.net/filter?category=Gifts'+AND+1%3d1--`</mark>

We get an extra product returned back to us!! (The hidden product)

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption><p>The Conversation Controlling Lemon is an unreleased product, but now is visible to us, thanks to the SQLi</p></figcaption></figure>

Now, the AND operator will ensure that only the released and unreleased items in the GIFT category are returned, as the SQL query will look like the following, effectively commenting out the check for released filter:

<mark style="color:yellow;">`SELECT * FROM product WHERE category='Gifts' AND 1=1-- AND released=1`</mark>

If we want to return all products from all categories, whether released or unreleased, we will modify the SQL query to be the following, so that the OR statement containing 1=1 resolves to true, and we know that any OR statement that has one true in it resolves to true, thereby returning all the data:

<mark style="color:yellow;">`SELECT * FROM product WHERE category='Gifts' OR 1=1-- AND released=1`</mark>

<figure><img src="../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption><p><a href="https://0a8c00fb047975cf822f01c2003a00bf.web-security-academy.net/filter?category=Gifts%27+OR+1%3d1--">https://0a8c00fb047975cf822f01c2003a00bf.web-security-academy.net/filter?category=Gifts%27+OR+1%3d1--</a></p></figcaption></figure>

***

### <mark style="color:yellow;">SQL injection vulnerability allowing login bypass</mark>

Lab description mentions that the vulnerability lies in the login page, where the administrator input field is not sanitizing the user-input data properly.&#x20;

The underlying SQL query may look like this for the login function:

<mark style="color:yellow;">`SELECT * FROM users WHERE username='wiener' AND password='bluecheese'`</mark>

Makes sense, as the SQL query will confirm whether the username wiener has the password bluecheese before returning all data back to the application.&#x20;

However, what happens if the input-data is not sanitized properly, and as a result, we can enter a payload as following to log in as any user:

<mark style="color:yellow;">`SELECT * FROM users WHERE username='administrator'--' AND password='anything'`</mark>

Since we entered the <mark style="color:yellow;">`--`</mark> it will comment out the password check query, and allows us to login as administrator user!&#x20;

<figure><img src="../../../.gitbook/assets/image (8) (1).png" alt=""><figcaption><p>The payload is accepted and the user is redirected to the my-account page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (9) (1).png" alt=""><figcaption><p>Attacker is logged in as Administrator</p></figcaption></figure>

***

### <mark style="color:yellow;">SQL injection UNION attack, determining the number of columns returned by the query</mark> - (using the NULL attack, and also the ORDER BY operator)

Lab description mentions the presence of a SQL vulnerability in the category parameter. Since the results from the SQL query (including the error) are returned in the application response, we are required to extract the number of columns in the other databases that the application may be using. Since the application description mentions that the lab is solved when the application returns an extra row containing NULL values, we must the NULL attack to solve the lab.&#x20;

<figure><img src="../../../.gitbook/assets/image (25).png" alt=""><figcaption><p>Start of the lab</p></figcaption></figure>

The product category parameter is vulnerable to SQLi

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption><p>A single ' returns an ISE</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (27).png" alt=""><figcaption><p>Two ' result in a query such as <code>SELECT * FROM products WHERE category='Gifts'''</code> ,thereby nullifying the single ' injected</p></figcaption></figure>

Since we can see the results of our SQLi query in the response, time to figure out the amount of columns being used. Because the lab description specifically asked us to solve the lab using the NULL attack, we will use the UNION SELECT payloads.&#x20;

Start off with <mark style="color:yellow;">`' UNION SELECT NULL --`</mark> payload. We observe that we are still receiving 500 ISE

<figure><img src="../../../.gitbook/assets/image (29).png" alt=""><figcaption><p>A single NULL returns ISE</p></figcaption></figure>

The second payload also returns 500 ISE. <mark style="color:yellow;">`' UNION SELECT NULL,NULL --`</mark>

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption><p>The second payload returns ISE</p></figcaption></figure>

The third payload, however, returns 200 OK, indicating that there are 3 columns present in the database. <mark style="color:yellow;">`' UNION SELECT NULL,NULL,NULL --`</mark>

<figure><img src="../../../.gitbook/assets/image (32).png" alt=""><figcaption><p>The 3rd payload is successful, as it returns 200 OK instead of 500 ISE, confirming that the vuln exists.</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption><p>An extra row is returned when 3 NULLs are returned, indicating that SQLi was successful</p></figcaption></figure>

This is confirmed if we also enter the 4th payload, which again returns 500 ISE (as there's no 4th column in the database).&#x20;

<figure><img src="../../../.gitbook/assets/image (33).png" alt=""><figcaption><p>The 4th payload again returns 500 ISE</p></figcaption></figure>

This lab can also be solved using the ORDER BY operator. Here's how:

First payload will be <mark style="color:yellow;">`' ORDER BY 1 --`</mark> . Observe that there's no significant change in the ordering, as the first column could be the Id column

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption><p>No significant change in ordering of items</p></figcaption></figure>

Second payload will be <mark style="color:yellow;">`' ORDER BY 2 --`</mark> . Observe that how the titles are now in an ordered manner, indicating that the ORDER BY query is being executed.

<figure><img src="../../../.gitbook/assets/image (35).png" alt=""><figcaption><p>Items are ordered by title</p></figcaption></figure>

Third payload will be <mark style="color:yellow;">`' ORDER BY 3 --`</mark>&#x20;

<figure><img src="../../../.gitbook/assets/image (36).png" alt=""><figcaption><p>Items are ordered by price</p></figcaption></figure>

Fourth payload will be <mark style="color:yellow;">`' ORDER BY 4 --`</mark>&#x20;

<figure><img src="../../../.gitbook/assets/image (37).png" alt=""><figcaption><p>ISE because no 4th column present in the database!</p></figcaption></figure>

***

### <mark style="color:yellow;">SQL injection UNION attack, finding a column containing text</mark>

Since the results of SQLi query are present in the front-end of the application, Lab description tells us to first fetch the number of columns, and then determine which columns contain string type (or compatible) data, and then fetch a specific string provided in the lab as a part of an additional row.&#x20;

<figure><img src="../../../.gitbook/assets/image (38).png" alt=""><figcaption><p>Start of the lab, in the Pets category</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (39).png" alt=""><figcaption><p>ISE received when single quote is injected</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (40).png" alt=""><figcaption><p>200 OK when two single quotes are injected, confirming presence of SQLi</p></figcaption></figure>

Using ORDER BY operator to confirm that we have 3 columns

<figure><img src="../../../.gitbook/assets/image (41).png" alt=""><figcaption><p>ORDER BY 3 allows us to order the database by price of the products</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (42).png" alt=""><figcaption><p>ORDER BY 4 returns ISE, indicating that 4th column does not exist</p></figcaption></figure>

Now, the application asked us to retrieve the string UwY4TS. Since we know that there's 3 columns only, with first column usually reserved for IDs (integer value), and the price being a float value, we can make an intelligent guess and use our UNION SELECT payload with the second column as follows:

<mark style="color:yellow;">`' UNION SELECT NULL,'Uw4YTS',NULL --`</mark>&#x20;

<figure><img src="../../../.gitbook/assets/image (43).png" alt=""><figcaption><p>And... we have our expected response. A new row, which has the string we requested, and with no price (since it technically does not exist in the database, and is a result of the UNION Injection attack which shows a new row at the end of the database)</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (44).png" alt=""><figcaption><p>Shown in the browser</p></figcaption></figure>

***

### <mark style="color:yellow;">SQL injection UNION attack, retrieving data from other tables</mark>

Building on to our prior labs, the lab description tells us that the UNION injection attack is possible (due to data being visible on the front-end of the application/response returned by the application). Now, for this application, the lab tells us that there's another table in the database called "users", with two columns called "username" and "password". We have to retrieve this data, fetch the password for the username "administrator", and log in using the administrator user.

<figure><img src="../../../.gitbook/assets/image (45).png" alt=""><figcaption><p>Lab is started</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (46).png" alt=""><figcaption><p>500 ISE when single-quote is injected</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (47).png" alt=""><figcaption><p>200 OK when two single-quotes are injected, indicating that SQLi exists</p></figcaption></figure>

Confirmed that there are two columns in the table, since ORDER BY 2 arranges the table by the description column (first description starts with A, second with B, etc).&#x20;

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption><p>Using ORDER BY 2 to confirm there are 2 columns</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (49).png" alt=""><figcaption><p>ORDER BY 3 results in ISE</p></figcaption></figure>

Using UNION SELECT, we are able to make the table fetch us some arbitrary string and confirm both columns support string-type data.

<figure><img src="../../../.gitbook/assets/image (51).png" alt=""><figcaption><p>Using UNION SELECT 'unique-string-1','unique-string-2' -- to confirm that both columns support string-type data</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (50).png" alt=""><figcaption><p>The unique-string-1 and unique-string-2 strings are returned by the table</p></figcaption></figure>

Now, because we already know that there's a presence of the table "users" containing the columns "username" and "password" in the database that we are targeting, we can use the UNION operator to fetch information from this table along with our original query. Our query will look like the following:

<mark style="color:yellow;">`SELECT * FROM products WHERE category = 'Gifts' UNION SELECT username,password FROM users -- '`</mark>

<figure><img src="../../../.gitbook/assets/image (52).png" alt=""><figcaption><p>The SQLi payload is inserted</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (53).png" alt=""><figcaption><p>The data returned by the application contains data from both tables!!</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (54).png" alt=""><figcaption><p>Logged into the application as the user Administrator, and the lab is solved</p></figcaption></figure>

***

### SQL injection UNION attack, retrieving multiple values in a single column

Same lab as previously, however this time we have to fetch the values from the second table via one column only. One example of this could be that our original table only supports string type data in limited columns, but the target table has more columns containing string type data. Hence, to exfiltrate these multiple columns, we can construct a SQL query instructing the database to concatenate the strings from multiple columns and combine that with the columns from our first table

<figure><img src="../../../.gitbook/assets/image (55).png" alt=""><figcaption><p>Start of the lab</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (56).png" alt=""><figcaption><p>Two columns in our current table</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (57).png" alt=""><figcaption><p>ORDER BY 3 returns 500 ISE, hence confirmed presence of 2 columns</p></figcaption></figure>

Using the UNION SELECT payload, we can see that only the second column returns string data

<figure><img src="../../../.gitbook/assets/image (58).png" alt=""><figcaption><p>Sending unique-string-1 and unique-string-2 returns 500 ISE, indicating that one of the columns does not support string-type data</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (59).png" alt=""><figcaption><p>Now, unique-string-2 is returned in the response, indicating that the second column has string-type data in it</p></figcaption></figure>

As such, since we need to exfiltrate both username and password from the users table, but we only have one column that supports string-type data in our original table, we can construct a SQL query so that the username and password values stored in the users table is concatenate. We can add a separator in between to ensure that we know where the username ends and the password begins (now this may also be guesswork, since we do not know what sort of database is running in the background. Hence why, we used the cheatsheet to look at different payloads for concatenation, and try them one by one: [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet))

<mark style="color:yellow;">`SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL,username||'!@$'||password FROM users -- '`</mark>&#x20;

Here, the seperator string is !@$. Converting this into paylaod becomes:

<mark style="color:yellow;">`' UNION SELECT NULL,username||'!@$'||password FROM users -- '`</mark>

<figure><img src="../../../.gitbook/assets/image (60).png" alt=""><figcaption><p>The username and password are exfiltrated together!</p></figcaption></figure>

Use the password to log in as administrator, and the lab is solved!

<figure><img src="../../../.gitbook/assets/image (61).png" alt=""><figcaption><p>User is able to log in as password</p></figcaption></figure>

***

### SQL injection attack, querying the database type and version on MySQL and Microsoft

In previous labs, we have been provided information on the database types, tables and columns names. Now, it's time that we learned how to identify this information ourselves. This lab focusses on identifying the underlying database type, which is crucial information as it will help us build our payloads accordingly to extract sensitive information later on.&#x20;

There are multiple query strings that we can send as a part of the UNION SQLi attacks to understand what may be the underlying database version. For this, we can also refer to the SQLi cheatsheet. [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

<figure><img src="../../../.gitbook/assets/image (62).png" alt=""><figcaption><p>The different database version strings</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (63).png" alt=""><figcaption><p>Start of the lab, and we have been tasked to return the specific string as a part of the application response</p></figcaption></figure>

Confirming that SQLi is present, and using ORDER BY to confirm that there are 2 columns in the current table. Interesting observation was that previously, we would use a payload such as ' ORDER BY 2 -- and that would work. However, because the underlying database is MySQL this time, we had to modify the comment to include an extra space at the end, for it work properly

<figure><img src="../../../.gitbook/assets/image (64).png" alt=""><figcaption><p>An extra + at the end (URL-encoded for space) returns the expected data</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (66).png" alt=""><figcaption><p>The same payload, except for the missing + at the end (URL-encoded for space) results in 500 ISE</p></figcaption></figure>

A hashtag at the end also worked, since MySQL uses # as a way to inform that the rest of the data is a comment.&#x20;

<figure><img src="../../../.gitbook/assets/image (67).png" alt=""><figcaption><p>A hash at the end of the query also worked like a charm!</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (68).png" alt=""><figcaption><p>Both columns support string type. Great!</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70).png" alt=""><figcaption><p>The database version is displayed after using our payload <mark style="color:yellow;"><code>'+UNION+SELECT+'The-database-type-is',@@version%23</code></mark></p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption><p>Lab is solved!</p></figcaption></figure>

***

### SQL injection attack, listing the database contents on non-Oracle databases

Same as previous labs, now we need to first identify the table and column names, and then dump the tables to identify the username and password to log in as the user administrator.

<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption><p>Start of the lab</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (73).png" alt=""><figcaption><p>Confirmed that there are 2 columns</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (74).png" alt=""><figcaption><p>ORDER BY 3 returns 500 ISE, hence confirmed there are 2 columns</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (75).png" alt=""><figcaption><p>Both columns have string type data, hence can be used to extract information</p></figcaption></figure>

Now, if we use a payload such as <mark style="color:yellow;">`' UNION SELECT * FROM information_schema.tables --`</mark>, we get 500 ISE. The reason being that information\_schema.tables has more columns than what our original table has (2). As such, if we use the payload, it does not satisfy the condition for UNION Injection attacks (the number of columns must be the same for original table and targeted table), and as such, our attack will fail.&#x20;

<figure><img src="../../../.gitbook/assets/image (76).png" alt=""><figcaption><p>The first payload is not successful (<mark style="color:yellow;"><code>' UNION SELECT * FROM information_schema.tables --</code></mark>)</p></figcaption></figure>

Now, looking at what content is usually present within the information\_schema.tables, it's as follows:

<figure><img src="../../../.gitbook/assets/image (77).png" alt=""><figcaption><p>Output of the information_schema.tables table</p></figcaption></figure>

Hence, we know that there is a column called table\_name. So why not extract the values stored in that column?&#x20;

Modifying our payload to be: <mark style="color:yellow;">`' UNION SELECT NULL,table_name FROM information_schema.tables --`</mark>

<figure><img src="../../../.gitbook/assets/image (80).png" alt=""><figcaption><p>Result is 200 OK!</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (81).png" alt=""><figcaption><p>The different tables that exist in the database have been returned</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (82).png" alt=""><figcaption><p>There's a users table in the database called users_uiyxio</p></figcaption></figure>

Now that we know the table name we are targeting is users\_uiyxio, why not obtain the column names within this table too? To do this, we will need to request this information from the information\_schema.columns table. The payload will be: <mark style="color:yellow;">`' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users_uiyxio' --`</mark>

<figure><img src="../../../.gitbook/assets/image (83).png" alt=""><figcaption><p>The list of column names present in the users table is requested</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (84).png" alt=""><figcaption><p>The columns are obtained!</p></figcaption></figure>

Now, we know that the table is users\_uiyxio, the columns are username\_qibzyk and password\_zzuysp. As such, we can now just request information as follows: <mark style="color:yellow;">`' UNION SELECT username_qibzyk,password_zzuysp FROM users_uiyxio --`</mark>

<figure><img src="../../../.gitbook/assets/image (85).png" alt=""><figcaption><p>The final payload is delivered</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (86).png" alt=""><figcaption><p>The username and password is obtained!</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption><p>The lab is solved!</p></figcaption></figure>

***

## SQL injection attack, querying the database type and version on Oracle

Straight-forward solutin as compared to previous labs. The payload used is <mark style="color:yellow;">`'+UNION%20SELECT%20NULL%2cbanner%20FROM%20v%24version--`</mark>

<figure><img src="../../../.gitbook/assets/image (88).png" alt=""><figcaption><p>Lab is solved!</p></figcaption></figure>

***

## <mark style="color:yellow;">SQL injection attack, listing the database contents on Oracle</mark>

Lab is the same as previous labs, just that this is targeting Oracle DB. As such, gotta use Oracle DB payloads, which are available via the cheat sheet: [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

<figure><img src="../../../.gitbook/assets/image (89).png" alt=""><figcaption><p>The payload is used to return the table names from the Oracle database</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (90).png" alt=""><figcaption><p>The USERS_RWXGMM table is returned from the Oracle Database</p></figcaption></figure>

Using the extracted table name, we can get the column\_names:

<mark style="color:yellow;">`' UNION SELECT NULL,column_name FROM all_tab_columns WHERE table_name = 'USERS_RWXGMM'`</mark>

<figure><img src="../../../.gitbook/assets/image (91).png" alt=""><figcaption><p>SQLi payload is injected to obtain the list of columns</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (92).png" alt=""><figcaption><p>List of columns from the database!</p></figcaption></figure>

<mark style="color:yellow;">`' UNION SELECT USERNAME_ITIFHM,PASSWORD_ZYWWZK FROM USERS_RWXGMM`</mark>

<figure><img src="../../../.gitbook/assets/image (93).png" alt=""><figcaption><p>Final SQLi payload is injected</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (94).png" alt=""><figcaption><p>Credentials are dumped!</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (95).png" alt=""><figcaption><p>Lab is solved!</p></figcaption></figure>

***

### <mark style="color:yellow;">Blind SQL injection with conditional responses</mark>

Lab description mentions that the application no longer returns verbose SQLi errors, and that the user has to depend on the application's behavior to understand whether a SQLi exists or not. In this case, if the user submits a tracking cookie with the HTTP request, the application will check with the database to confirm whether the said cookie belongs to an existing user. If yes, it will return the message "Welcome back". If not, the "Welcome back" message is not returned. This can be used with conditional checks (AND 1=1/AND 1=2) to confirm the presence of SQLi, before exploiting it to retrieve the password for the administrator user.&#x20;

Hint: The lab tells us that the password string for the user is made up of alphanumeric characters (lowerase characters only, along with numbers)

<figure><img src="../../../.gitbook/assets/image (96).png" alt=""><figcaption><p>Start of the application, with the Welcome Back message visible</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (97).png" alt=""><figcaption><p>Start of the lab</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (98).png" alt=""><figcaption><p>Injecting a single quote leads to the application not returning the "Welcome back" error message</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (99).png" alt=""><figcaption><p>Injecting a true statement leads to the application returning the Welcome Back message again! Nice indicator that SQLi exists</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (100).png" alt=""><figcaption><p>Whereas injecting a false statement leads to the application not returning the Welcome Back message at all. </p></figcaption></figure>

Using the payload:

<mark style="color:yellow;">`' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'a`</mark>

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption><p>The Welcome Back message is returned, indicating that the first character of the password is greater than a</p></figcaption></figure>

Using the payload:

<mark style="color:yellow;">`' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'm`</mark>

<figure><img src="../../../.gitbook/assets/image (102).png" alt=""><figcaption><p>The Welcome Back message is not returned, indicating that the first character of the password is not greater than the character m</p></figcaption></figure>

By using binary searching pattern, we use the payload:&#x20;

<mark style="color:yellow;">`' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) = 'h`</mark>

<figure><img src="../../../.gitbook/assets/image (103).png" alt=""><figcaption><p>The Welcome Back message is returned, indicating that first character of the password string is h</p></figcaption></figure>

Now, we know that the first character is 'h', we can use Burp Intruder to automate these requests to identify the characters for the different positions in the string! (2nd character, 3rd character etc)

<figure><img src="../../../.gitbook/assets/image (105).png" alt=""><figcaption><p>Setting up the Cluster Bomb attack against the application</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (106).png" alt=""><figcaption><p>Payload 1 is numbers from 1 to 20</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (107).png" alt=""><figcaption><p>Payload 2 will be alphanumeric characters</p></figcaption></figure>

Using this attack, we will observe the results that have a different response length, along with the fact that they contain the string "Welcome Back!"

<figure><img src="../../../.gitbook/assets/image (108).png" alt=""><figcaption><p>Some results confirm the characters for each position in the password string</p></figcaption></figure>

Piecing these together, the final password string is: hsr2230u20hyug5uneum

<figure><img src="../../../.gitbook/assets/image (109).png" alt=""><figcaption><p>And the lab is solved!</p></figcaption></figure>

***

### <mark style="color:yellow;">Blind SQL injection with conditional errors</mark>

Lab description mentions that the lab no longer returns verbose error messages, and that the response of SQLi payloads is also not returned in the application body. However, if for some reason, the SQL query breaks, then it will throw 500 ISE. As such, we will have to query the underlying database in such a manner that if the query we send is technically true (such as first character of the password is the character a), then this query should break, and return 500 ISE. Else, it will keep returning HTTP 200 OK to us.

From the lab: This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.

<figure><img src="../../../.gitbook/assets/image (110).png" alt=""><figcaption><p>Start of the lab</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (111).png" alt=""><figcaption><p>500 ISE returned when a single-quote is injected in the cookie</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (112).png" alt=""><figcaption><p>200 OK when two single-quote characters are injected, thereby indicating the presence of a possible SQLi</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (113).png" alt=""><figcaption><p>Injecting ' AND '1'='1 returns the as-expected response</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (114).png" alt=""><figcaption><p>Injecting ' AND '1'='2 also returns the same response (the reason being, the SQL server does not return any verbose error if there are empty rows returned as a part of the SQL query (in our case, the query '1'='2' is false, so it will return false, making the full-query return false, but no errors are returned (unlike previous labs), since the query that we requested finally still returns a valid answer, whether that answer be 0</p></figcaption></figure>

To confirm that the tracking cookie parameter is vulnerable to SQLi, we use the concatenation payload (explained in SQLi Methodology tab) to see if we can make the SQL server throw an error.&#x20;

<mark style="color:yellow;">`' || (SELECT '' FROM dual) || '`</mark>

<figure><img src="../../../.gitbook/assets/image (116).png" alt=""><figcaption><p>Requesting nothing ('') from the dual table will return NULL, which when concatenated with the original trackingID value will return the trackingID value, thus returning a true statement and hence the 200 OK</p></figcaption></figure>

<mark style="color:yellow;">`' || (SELECT '' FROM dualsff) || '`</mark>

<figure><img src="../../../.gitbook/assets/image (117).png" alt=""><figcaption><p>When requesting information from a table that does not exist (dualsff), the SQL server will return an error, which will break the SQL query, hence return the 500 ISE</p></figcaption></figure>

So now, we need to use queries that can make the SQL server return an unexpected response, which could lead to SQLi being exploited (modify the query so that it causes a database error only if the condition is true)

We can first confirm that the users table exists:

<mark style="color:yellow;">`'||(SELECT '' FROM users WHERE rownum=1)||'`</mark>&#x20;

Explanation of payload is that check for the users table. If it exists, where there's at least 1 row, select NULL, and append it to cookie. Hence, we get 200 OK.&#x20;

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

But if we modify the users table to some other value, we get 500 ISE, because the usersasd table does not exist.&#x20;

<figure><img src="../../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

Now, we confirmed that the users table exists, so time to check that the administrator user exists. The idea is that we will want to intentionally trigger an error in SQL if the user exists. If the user does not exists, then our intentional error will not trigger, and as such, we will know that the user does not exist.&#x20;

To do so, we will use the following payload:

<mark style="color:yellow;">`' || (SELECT TO_CHAR(1/0) FROM users WHERE username='administrator') || '`</mark>

<figure><img src="../../../.gitbook/assets/image (140).png" alt=""><figcaption></figcaption></figure>

The response we get is 500 ISE, which indicates the presence of the administrator user. The reason why we get 500 is explained as follows:&#x20;

The payload: <mark style="color:yellow;">`' || (SELECT TO_CHAR(1/0) FROM users WHERE username='administrator') || '`</mark>

First check is done to confirm if the users table exist. Since we already confirmed that users table exists, we move onto next stage. If users table did not exist, then SQL would have thrown 500 ISE at this stage itself, and we would have no idea if the 500 we got is because of our intentional payload of 1/0, or because the users table does not exist.&#x20;

Second check is that SQL checks that if the username administrator exists, and returns a row? If there's a row that's returned, then the SELECT operation is executed on it.&#x20;

However, if the administrator user does not exist, then there will be no row returned. As such, there's no row for the SELECT operation to be executed on, and we would get 200 OK as a response (since there will be NULL that will be concatenated to the original cookie payload.&#x20;

<figure><img src="../../../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

Now, if we wish to find the password (assuming length of password is 20, or we can confirm it by using the payload <mark style="color:yellow;">`' || (SELECT TO_CHAR(1/0) FROM users WHERE username='administrator' AND LENGTH(password) = 20) || '`</mark> , we can do so using the following payload:&#x20;

<mark style="color:yellow;">`' || (SELECT TO_CHAR(1/0) FROM users WHERE username = 'administrator' AND SUBSTR(password,1,1) = 'a') || '`</mark>

Now, if we run this payload, we get a 200 OK, which indicates the following:&#x20;

First check: users table exists, so we move to next round of execution

Second check: we check the where clause to see if the administrator user exists AND whether the first character of the password is the letter 'a'. Since we confirmed the presence of the administrator user earlier, that would have returned true. But since we are getting 200 OK, that means that potentially the first character of password is not the alphabet 'a', and we have to check it.&#x20;

We can run the Intruder attack, and guess what? We get a 500 ISE for the letter 'y'.

So now, we know the first letter of the password for the user administrator is the alphabet 'y'. Now, we can run a cluster bomb attack to uncover the remaining 19 characters.&#x20;

<figure><img src="../../../.gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure>

Running the clusterbomb attack........

<figure><img src="../../../.gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure>

We are logged in as administrator!

<figure><img src="../../../.gitbook/assets/image (135).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (145).png" alt=""><figcaption></figcaption></figure>

