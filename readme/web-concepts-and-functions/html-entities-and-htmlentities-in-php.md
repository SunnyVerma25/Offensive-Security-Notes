---
description: Understand HTML encoding done to prevent XSS attacks
---

# HTML Entities and htmlentities() in PHP

Inspired from: [http://www.tizag.com/htmlT/entities.php](http://www.tizag.com/htmlT/entities.php); basically, as the blog mentions, entities = symbols. It's just a fancy way of saying a "symbol" (such as %,$,&,@) etc.&#x20;

When we want to display these characters on HTML pages, we need to make sure that we have a standardized (and safe) way of rendering these symbols in the browser without compromising on security (think how rendering < and > symbols in HTML without proper output encoding is not a good idea :) ).&#x20;

To do so, HTML entities are divided into three parts:

1. It begins with the `&` sign
2. Continues with the entities name
3. Terminated with the `;` sign

For example, the `<` and `>` symbols when HTML encoded becomes `&lt;` and `&gt;` symbols, and hence can be safely rendered in the browser without introducing XSS possibilities.&#x20;

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

The `htmlentities()` function in PHP achieves the function of taking in raw user input, and performs conversion of this raw user input into HTML encoded data before being displayed back in the browser. From a pentest perspective, you can enter `<>` symbols in a text field to test for HTML Injection or XSS. However, if these payloads are not being fired as the data is HTML output encoded before being rendered, then that means a function similar to `htmlentities()` might be implemented in the source code.&#x20;

Upon reading the [PHP Manual](https://www.php.net/manual/en/function.htmlentities.php) and helpful blogs, it's clear that `htmlentities()` can take multiple arguments as inputs, to determine what characters (read quotes) will be encoded, any specific encoding techniques to be used etc. Here's an example of code being used in W3 School:

```
<?php
$str = '<a href="https://www.w3schools.com/php/func_string_htmlentities.asp">Go to w3schools.com to learn about htmlentities() function</a>';
echo htmlentities($str);
?>
```

The output of this will be:

```
<a href="https://www.w3schools.com/php/func_string_htmlentities.asp">Go to w3schools.com to learn about htmlentities() function</a>
Converting characters into entities are often used to prevent browsers from using it as an HTML element. This can be especially useful to prevent code from running when users have access to display input on your homepage.
```

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

Upon inspection, it's clearly seen that the input data is encoded properly&#x20;

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

Now, this function when used with flags allows for customization in what part of the input string will be encoded. The default format of the function is htmlentities(_string,flags,character-set,double\_encode_), with everything explained below:

1. string: The input that needs to be formatted
2. flags: Specifies how to handle quotes, invalid encoding and the used document type.
3. character-set: Any specific character-set to use while performing encoding?
4. double\_encode: A boolean value that specifies whether to encode existing html entities or not

All flag values defined here: [https://www.w3schools.com/php/func\_string\_htmlentities.asp](https://www.w3schools.com/php/func_string_htmlentities.asp)

For example, let's take this payload:

```
<?php
$str = "This is a really 'large' text with multiple symbols such as <>'\"'|'\"";
echo htmlentities($str);
?>
```

The output of this will be:

```
This is a really &#039;large&#039; text with multiple symbols such as &lt;&gt;&#039;&quot;&#039;|&#039;&quot;
```

And the payload:

```
<?php
$str = "This is a really 'large' text with multiple symbols such as <>'\"'|'\"";
echo htmlentities($str,ENT_NOQUOTES);
?>
```

leads to

```
This is a really 'large' text with multiple symbols such as &lt;&gt;'"'|'"
```

Because the `ENT_NOQUOTES` is a flag that tells the `htmlentities()` function to not encode any of the quotes present in the string.&#x20;

#### Possibility of XSS even when using htmlentities() function

Just because developer would use `htmlentities()` to perform HTML encoding on user-input was not enough to stop XSS attack vectors from existing within the application.&#x20;

Until PHP 8.0, the default flag for `htmlentities()` was set to `ENT_COMPAT`, which would only encode the double quote character by default and not the single-quote character. This could introduce XSS if developers forgot to assign the `ENT_QUOTES` flag to the `htmlentities()` function. An example code is provided below (note that because W3 school supports the latest version of PHP, i.e. `8.1` which uses `ENT_QUOTES` as default flag, the XSS attack is demonstrated by hard-coding the flag value to `ENT_COMPAT` to simulate the behavior of `PHP 8.0` and lower versions).&#x20;

```
<?php
$_GET['a'] = "#000' onload='alert(document.cookie)";
$href = htmlEntities($_GET['a'],ENT_COMPAT);
print "<body bgcolor='$href'>";
?>
```

Playing this code in W3 terminal would result in:&#x20;

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Looking at HTML source, this is what is returned:

```
<body bgcolor='#000' onload='alert(document.cookie)'>
```

As seen, it's clear that if we use ENT\_COMPAT flag (which was default behavior until PHP 8.0), it would not encode the single-quote character, therefore allowing an attacker to escape out of the bgcolor attribute and inject an onload attribute, allowing malicious javascript to be executed.

However, if ENT\_QUOTES is used (which is the default flag as of PHP 8.1), the single-quote character is also encoded.&#x20;

```
<?php
$_GET['a'] = "#000' onload='alert(document.cookie)";
$href = htmlEntities($_GET['a']);
print "<body bgcolor='$href'>";
?>
```

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

With the source being:

```
<body bgcolor='#000&#039; onload=&#039;alert(document.cookie)'>
```

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption><p>Credits: <a href="https://php.watch/codex/htmlentities#changes-php-8.1">https://php.watch/codex/htmlentities#changes-php-8.1</a></p></figcaption></figure>

