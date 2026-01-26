# Burp Lab Solutions

### Lab: DOM XSS in `document.write` sink using source `location.search`

This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

We will use DOMInvader to help streamline our testing, and also learning about dangerous sinks. We enabled DOMInvader, and refreshed the page.&#x20;

<figure><img src="../../../../.gitbook/assets/image (202).png" alt=""><figcaption></figcaption></figure>

After entering the DOMInvader canary in the search string, we are informed by the extension that the canary is being consumed by the dangerous sink `document.write`, and we are given an exploit option.&#x20;

<figure><img src="../../../../.gitbook/assets/image (203).png" alt=""><figcaption></figcaption></figure>

Before clicking automatically on exploit and solving the lab, let's look at the Stack Trace to identify where the sink is being called from.

<figure><img src="../../../../.gitbook/assets/image (204).png" alt=""><figcaption></figcaption></figure>

From the above screenshot, we see that there's a function called trackSearch, loading in the ?search=\<string> URL. It's being loaded by the Search button on line 57 in the HTML response from the server. Further, we can see that the trackSearch function is defined on line 61, showing the actual function, along with the source (being obtained from the window.location.search property), and being passed into the document.write sink within the trackSearch function.&#x20;

<figure><img src="../../../../.gitbook/assets/image (206).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (205).png" alt=""><figcaption></figcaption></figure>

Now, if we either enter the payload manually, or click the "Exploit" button in DOM Invader, we can solve the lab using the following payload (URL-encoded):

`'"><img src=x onerror=alert()>`&#x20;

<figure><img src="../../../../.gitbook/assets/image (211).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

### Lab: DOM XSS in `innerHTML` sink using source `location.search`&#x20;

This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

We will use DOMInvader to help streamline our testing, and also learning about dangerous sinks. We enabled DOMInvader, and refreshed the page.&#x20;

<figure><img src="../../../../.gitbook/assets/image (213).png" alt=""><figcaption></figcaption></figure>

After entering the DOMInvader canary in the search string, we are informed by the extension that the canary is being consumed by the dangerous sink `element.innerHTML`, and we are given an exploit option.

<figure><img src="../../../../.gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

Before clicking automatically on exploit and solving the lab, let's look at the Stack Trace to identify where the sink is being called from.

<figure><img src="../../../../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

From the above screenshot, we see that there's a function called doSearchQuery, loading in the ?search=\<string> URL. We can see that the doSearchQuery function is defined on line 53, showing the actual function, along with the source (being obtained from the window.location.search property), and being passed into the element.innerHTML sink within the doSearchQuery function.

<figure><img src="../../../../.gitbook/assets/image (216).png" alt=""><figcaption></figcaption></figure>

Since we are taking the search value from the URL, and using it to set the 'searchMessage' element's innerHTML (the searchMessage element is defined as `<span id="searchMessage"></span>`, we can use a payload like `</span><img src=x onerror=alert()>` (after URL encoding it), so that this dangerous value gets sent to the doSearchQuery JS function, and it sets this value to the "searchMessage" element's innerHTML property, thus popping the alert box!&#x20;

<figure><img src="../../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (218).png" alt=""><figcaption></figcaption></figure>
