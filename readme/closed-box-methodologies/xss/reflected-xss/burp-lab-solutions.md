# Burp Lab Solutions

### Lab 1: Reflected XSS into HTML context with nothing encoded

The lab contains a Reflected XSS in the search functionality. Any data that is entered into the search functionality is not encoded by the application, and is returned as it is.&#x20;

<figure><img src="../../../../.gitbook/assets/image (189).png" alt=""><figcaption></figcaption></figure>

So, we can supply a payload in the search parameter in the URL as search=hello123456<%2Fh1>alert()<%2Fscript>, which would trigger the alert popup and solve the lab.

<figure><img src="../../../../.gitbook/assets/image (188).png" alt=""><figcaption></figcaption></figure>

### Lab: Reflected XSS into attribute with angle brackets HTML-encoded

Sometimes, the injected data is injected into an HTML tag attribute value, and we might try to close out the attribute value, and introduce another attribute that can allow us to inject scriptable context.

<figure><img src="../../../../.gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

In the above case, we can see that the angle-brackets are being encoded, so we cannot terminate the tag and start a new tag. But since the double-quotes are not being encoded, we can terminate the "value" attribute, and inject a new attribute into the tag.

<figure><img src="../../../../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (191).png" alt=""><figcaption></figcaption></figure>
