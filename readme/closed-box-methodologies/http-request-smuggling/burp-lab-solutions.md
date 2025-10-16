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

