---
description: And other sub-libraries that may help automating exploits
---

# Using the HTTPX library

The \`HTTPX\` library in Python allows us to submit HTTP requests to the webserver, and play with the response. All you gotta do to interact with the target webserver is just use the simple HTTPX library, and it does the heavy-lifting for you.&#x20;

We can:&#x20;

* Make requests using common HTTP methods (GET, POST, PUT etc)
* **Customize** the requests’ headers and data using the query string and message body
* Inspect the data from the response to grep useful data
* Make authenticated requests
* And moreover, use these to pass our OSWE challenge

We could have used the 'requests' library (which the authors of the HTTPX library give a lot of credit to for inspiration), but HTTPX has multiple features that make it a better alternative than requests, and a better option to learn for longer learning, out of which the two main features are:

* Natively supporting async operations
* Support for HTTP/2

***

## Setting up the HTTPX library

We can install the HTTPX library using pip

Set up the virtual environment using `python -m venv <virtual-env-name>`

Then, install httpx using pip. `pip3 install httpx`

Then, whenever we wish to write a python program that will include making connections to HTTP server, we will import the HTTPX module

`import httpx`

***

## Making the first HTTP GET request

Now, let's write the first program to make an HTTP GET request, and look at the response

```python
import httpx

r = httpx.get('https://httpbin.org/get')
print(r.text)
```

Now, this program uses the HTTPX GET method to make the HTTP GET request to the https://httpbin.org/get URL, and then we look at response

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

So now, we can see the output of the HTTP GET request that we made via the httpx.get method

***

## Supplying query parameters via GET request

Now, before we move onto POST and other methods, we will learn how to supply parameters via GET request as well, which is a very important requirement

Here's the code:

```python
import httpx

vuln_params = {'key': 'value1', 'key2': 'value2'}
r = httpx.get('https://httpbin.org/get', params = vuln_params)
print(r.text)
```

We use the 'vuln\_params' dictionary object to define a list of parameters and values.&#x20;

Then, when we make the GET call using httpx.get method, we pass this 'vuln\_params' dictionary object as an argument to the 'params' keyword, so that all the values defined in the vuln\_params object will be passed as query parameters to the GET request.

And here's the response:

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

We can see in the response that the server confirmed that it got 2 args (key and key2), and we can also see the URL shows that the call was made to [https://httpbin.org/get?key=value1\&key2=value2](https://httpbin.org/get?key=value1\&key2=value2)

If we want to submit multiple values to same key value, we can modify the code as follows:

```python
import httpx

vuln_params = {'key': 'value1', 'key2': 'value2', 'key3':['value3', 'value4']}
r = httpx.get('https://httpbin.org/get', params = vuln_params)
print(r.text)
print(r.url)
```

So that the response will be:&#x20;

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Another example for GET request, calling the [https://www.example.org/](https://www.example.org/) page to see how HTML code is returned:

```python
import httpx

vuln_params = {'key': 'value1', 'key2': 'value2', 'key3':['value3', 'value4']}
r = httpx.get('https://www.example.org/', params = vuln_params)
print(r.text)
print(r.url)
```

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

***

## Supplying custom headers via HTTP request

If we wish to supply custom headers as a part of our HTTP request, we can do so by defining a header dictionary object (appropriately named vuln\_headers, cause why not)?, and need to pass it as an argument for the headers object when calling the httpx.get() object (or any other API call).&#x20;

The code:

```python
import httpx

vuln_headers = {'user-agent': 'SQLi-payload here', 'X-Forwarded-For': '127.0.0.1'}
vuln_params = {'key': 'value1', 'key2': 'value2', 'key3':['value3', 'value4']}
r = httpx.get('https://httpbin.org/get', params = vuln_params, headers = vuln_headers)
print(r.text)
```

The response:&#x20;

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

***

## Confused on what values we could provide in GET (or any request)?&#x20;

The answer is simple. We can supply multiple arguments to the function. Let's look into the `httpx` module that we defined, specifically the `_api.py` file located at `.\virtual-env\Lib\site-packages\httpx`.&#x20;

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

As we can see, we can supply params (parameters), headers, cookies, auth (authentication), proxy, follow\_redirects (which is set to false by default, so we need to set it to true in case we want the redirects to happen), verify (verify the SSL certificate for HTTPS website, and is set to True, but needs to be set to False for Burp and other proxies) etc.&#x20;

Hence, we can make a request such as follows:&#x20;

```python
import httpx

vuln_headers = {'user-agent': 'SQLi-payload here', 'X-Forwarded-For': '127.0.0.1'}
vuln_params = {'key': 'value1', 'key2': 'value2', 'key3':['value3', 'value4']}
vuln_cookies = {'cookie1': 'cookie-value-1', 'cookie2': 'cookie-value-2'}
proxies = "http://127.0.0.1:8080"
r = httpx.get('https://httpbin.org/get', params = vuln_params, headers = vuln_headers, proxy = proxies, cookies = vuln_cookies, verify=False)
print(r.text)
print(r.headers)
```

Which will result in the request going through our Burp Suite proxy&#x20;

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

And the response:&#x20;

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

