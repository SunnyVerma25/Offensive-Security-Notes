# Burp Lab Solutions

### Lab: Stored XSS into anchor `href` attribute with double quotes HTML-encoded

The lab tells us that the injected data can be used to alter the value of the href attribute of an anchor tag. The lab environment is a blog that allows us to leave a comment on the blog, indicating possibility of a stored XSS

<figure><img src="../../../../.gitbook/assets/image (196).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (197).png" alt=""><figcaption></figcaption></figure>

It can be seen that the value we entered in the website column is being injected into the href attribute of the anchor tag

<figure><img src="../../../../.gitbook/assets/image (198).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>

In this case, a simple javascript:alert() can do the trick for us! Since it's a hyperlink, we will have to click on it to execute our alert popup.

<figure><img src="../../../../.gitbook/assets/image (200).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (201).png" alt=""><figcaption></figcaption></figure>
