---
description: Burp Lab Solutions with walkthrough and understanding
---

# Burp Lab Solutions

## HTTP request smuggling, basic CL.TE vulnerability

This lab involves exploiting the basic CL.TE vulnerability, where the front-end server appears to be using "Content-Length" header to understand where to terminate an HTTP request, but the back-end server appears to be using the "Transfer-Encoding" header to determine the end of the HTTP request. The whole idea of the lab is to understand how unwanted data can be smuggled to the back-end server to bypass protections. In this lab, we have to smuggle the character "G", so that this "G" character is dangling at the back-end, and then gets appended to an unsuspecting POST request from a different user. Since the application only supports GET and POST HTTP methods, GPOST is not a supported HTTP Method, and the unsuspecting user who made a POST request, will get the response that GPOST is an incorrect HTTP method.

<figure><img src="../../../.gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

We deploy the lab, and target the root endpoint. Upon sending the root endpoint to the Repeater tab, make the following changes:

1. Change the HTTP version to 1.1 from 2 using the "Request query parameters"
2. Change the request method from GET to POST by right-clicking the request, and selecting "Change request method"
3. Click on the settings option (next to the "Send" button, and unselect the "Update Content-Length" option
4. Enable the non-printable (CRLF) characters

Then, we confirm that we can use the POST method to call the endpoint normally.

<figure><img src="../../../.gitbook/assets/image (166).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>



Great, now that we confirmed that we can make the POST request, let's introduce the "`Transfer-Encoding`" header, and introduce our payload.&#x20;

POST / HTTP/1.1\
Host: 0a310081038a2f60804a8527005600d4.web-security-academy.net\
Transfer-Encoding: chunked\
Content-Type: application/x-www-form-urlencoded\
Content-Length: 6

0

G

<figure><img src="../../../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

Observe that the Content-Length is set to 6, which includes the character 0, the CRLF characters in line 7 (after the 0 character), followed by the CRLF characters in line 8, followed by the character G. Now, since the front-end server looks at this request and counts the characters until 6 character length is matched, it will think the payload is:

0

G

And it will pass this request as it is to back-end server, thinking that this HTTP request terminates at the character "G".

However, because the back-end server (appropriately, according to the RFC) gives preference to Transfer-Encoding HTTP header present in the request, it notices the "0" in the payload, indicating that this is the last chunk, and the request terminates at 0. As such, the "G" character is left dangling.&#x20;

At the same time, another user makes an unsuspecting POST request to the same endpoint, also looking to load the website. This user does not have any content-body, and just wants to load the main page. Since the Content-Length header is missing and there's no body, the front-end server also passes this request to back-end server.&#x20;

<figure><img src="../../../.gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

However, this is where the desync happens. Because the "G" character is dangling from the previous request, the back-end server assumes that this "G" character is part of the next request, making the HTTP method as GPOST. Since there's no GPOST method that is supported by the back-end server, it returns the error "Unrecognized method GPOST", which is eventually retuned to the unsuspecting user, who just made a normal request.

<figure><img src="../../../.gitbook/assets/image (172).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

***

## HTTP request smuggling, basic TE.CL vulnerability

This lab involves exploiting the basic TE.CL vulnerability, where the front-end server appears to be using "Transfer Encoding" header to understand where to terminate an HTTP request, but the back-end server appears to be using the "Content-Length" header to determine the end of the HTTP request. The whole idea of the lab is to understand how unwanted data can be smuggled to the back-end server to bypass protections. In this lab, we have to smuggle the character "G", so that this "G" character is dangling at the back-end, and then gets appended to an unsuspecting POST request from a different user. Since the application only supports GET and POST HTTP methods, GPOST is not a supported HTTP Method, and the unsuspecting user who made a POST request, will get the response that GPOST is an incorrect HTTP method.

<figure><img src="../../../.gitbook/assets/image (173).png" alt=""><figcaption></figcaption></figure>

We deploy the lab, and target the root endpoint. Upon sending the root endpoint to the Repeater tab, make the following changes:

1. Change the HTTP version to 1.1 from 2 using the "Request query parameters"
2. Change the request method from GET to POST by right-clicking the request, and selecting "Change request method"
3. Click on the settings option (next to the "Send" button, and unselect the "Update Content-Length" option
4. Enable the non-printable (CRLF) characters

Then, we confirm that we can use the POST method to call the endpoint normally.

<figure><img src="../../../.gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

Great. Now that we have confirmed that POST request works as expected, let's introduce the "Transfer-Encoding" header as well, since our front-end server supports it.&#x20;

Now, the goal is to smuggle the "G" character onto the POST method of an unsuspecting victim. Hence, we will supply the following payload:

<figure><img src="../../../.gitbook/assets/image (176).png" alt=""><figcaption></figcaption></figure>

In this payload, we deliberately set the Content-Length to 3, so that even though the front-end sees the chunked packet of size 1 byte containing G and sends it to the back-end server to process it, the back-end server will see that the Content-Length is set to 3, which means that it ends at the CRLF character of the line 7 containing 1, thereby leaving lines 8 and 9 (containing G and 0) dangling.&#x20;

And this behavior is confirmed in the next request that is sent, as a valid POST call returns the error "G0POST in not a valid method".&#x20;

<figure><img src="../../../.gitbook/assets/image (177).png" alt=""><figcaption></figcaption></figure>

Now, since we cannot remove this "0" from being processed (after all, 0 is used to denote the last chunk, and hence is mandatory to end), we will have "G0" smuggled, and hence it prevents us from obtaining the objective of the lab. We can try to remove 0 from the payload, but this is the error we get (because the front-end server uses Transfer-Encoding, and hence does not like that chunk formatting is not followed properly).

<figure><img src="../../../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (179).png" alt=""><figcaption></figcaption></figure>

Since we cannot remove the 0 from being smuggled, we cannot achieve our objective. But, what if we decided to instead smuggle the whole request we wanted the victim user to see? This is how we construct our payload for the attack request:

1. Copy the line 1, 3, 4 and add it to bottom of our payload, making it seem that we have two requests. Ensure that the method of the copied call is changed to GPOST from POST, as this will be our "smuggled" request that the victim gets the response of

<figure><img src="../../../.gitbook/assets/image (181).png" alt=""><figcaption></figcaption></figure>

2. Since we are using the Transfer-Encoding on the front, we need to end this request with a "0" to denote the last chunk. So we attach a 0 at the end, and follow it with \r\n\r\n

<figure><img src="../../../.gitbook/assets/image (182).png" alt=""><figcaption></figcaption></figure>

3. We need to calculate the chunk size of the smuggled request, to add it before our smuggled request begins (following the format of chunk-size, chunk body). This is calculated to be 86 bytes (represented as 56 in hexa), and hence 56 is added before the smuggled request

<figure><img src="../../../.gitbook/assets/image (183).png" alt=""><figcaption></figcaption></figure>

4. Now, we need to adjust the Content-Length of the original request. Since we want the back-end server to see the GPOST as a 2nd request, we need to modify the content-length to terminate the original request at the end of line 7 (containing 56). Hence, we modify the original content-length to 4 bytes

<figure><img src="../../../.gitbook/assets/image (184).png" alt=""><figcaption></figcaption></figure>

5. The last modification that we need to make is to modify the Content-Length of the smuggled request. The body of the request is 5 bytes (since we need to end the 0 with \r\n\r\n, hence 5 bytes). Now, if we keep the Content-Length to 5, it completes the smuggled request, and it becomes more of a response smuggling attack, and the response will be sent out immediately, but probably not caught by another victim (since a victim may, or may not send a request at the exact same time). However, if we increase the Content-Length by 1 (make it 6 in this case), it leaves the smuggled request hanging for the back-end server, where it waits for the next request. If the next request is another POST request, it will take the "P" out of the POST to complete the smuggled request, and then return the error "Invalid method GPOST" to the victim user.

<figure><img src="../../../.gitbook/assets/image (185).png" alt=""><figcaption></figcaption></figure>

Now, if we make a normal POST request to the endpoint, we get the error!

<figure><img src="../../../.gitbook/assets/image (186).png" alt=""><figcaption></figcaption></figure>

&#x20;

<figure><img src="../../../.gitbook/assets/image (187).png" alt=""><figcaption></figcaption></figure>
