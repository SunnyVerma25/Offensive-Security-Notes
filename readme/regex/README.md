---
description: >-
  Because I decided to hurt myself (mentally). Content inspired by Hacking Hub -
  Learn Regex chapter
---

# Regex!!

#### What is Regex?

Standing for regular expressions, regex is a programmatical tool to help us search for particular patterns amongst a sea of data. Think that you have a giant document, and you want to search for the word "fountain". You press CTRL + F to launch the find window within the document, type "fountain", and if there are any instances of the word "fountain" in the document, they pop up. The phenomenon of these words popping up is made possible thanks to regex.&#x20;

Hence, in short and simple words, regex provides us with the ability to search for specific content amongst a lot of data. It has a lot of other use cases as well. Regex can be used to:

* Instantly pick out precise content from messy logs.
* Find potential vulnerabilities in code reviews.
* Rapidly search for secrets like API keys or passwords in a leaked codebase.
* Identify areas of an application that are likely to use Regex and know where it can go wrong ( even without seeing the source code).

#### Literal Match

As the name suggests, this means we are literally searching for the exact character match. The act of pressing CTRL+F in a document and searching for the exact word is a good example of literal match, as we are "literally" searching for occurrence of the exact pattern of characters in a given content.&#x20;

A **literal match** means you're telling regex to look for _exactly_ the text you type, character for character.

* If you write `hello`, it will match only the string `hello`.
* No wildcards, no magic just a direct match.

But, there's a slight problem. If you search for the word `computer` in a document (or any other word; `computer` is just an example), the document can return 5 (again, just an example) occurrences of the word `computer`. 4 of these could be the word `computer`, but the 5th word can be the word `supercomputer`. Since `computer` is part of the word `supercomputer`, hence why there are 5 instances of these words returned, which may be problematic if you are only looking for the word `computer`. This problem brings us to the next example of `Exact Strings` in regex.

#### Exact String

So, you want to find the occurrence of an exact word in a sea of text. You don't want false positives like supercomputer or computerx. You only want to highlight the exact word "computer".&#x20;

In order to do so, regex provides the usage of metacharacters/special characters. To use these, we usually start with a `/` character, followed by whatever type of metacharacter we wish to use. In our specific case, we can use the `word boundary` character (`/b`) that is used to denote the empty space between two words.&#x20;

So, if use a regex like `\bcomputer\b`, it is basically looking for the exact occurrence of the computer word in the text. It does not take into account words like `supercomputer` (no space between r and c, so regex fails), or `computerx`(again, no space between r and x, and hence regex fails).&#x20;

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

#### Anchor - Starts with

We learned to search for literal matches, and for exact strings. Now, these matches can occur at any position within our content. But what if we wanted to search for a specific text, and make sure that this content occurs at the beginning of the string or line? Or what if as a developer, we want to make sure that the input provided by a user matches the format of https://\<content-com>?&#x20;

This can be made possible with another bunch of metacharacters called **Anchors**. These are special regex characters that **don’t match characters**, they match **positions** in a string (a.k.a, where does the pattern exist in a string).

Now, if we wish to perform a check for a pattern that appears at the beginning of a string, we can do so with the help of another metacharacter called the `Caret` symbol. We use the `^` (caret symbol) character to ensure that our search for the specific pattern includes the check that the pattern appears at the beginning of a string or a line.&#x20;

It means: “Only match if this pattern is at the very start.”

For example, we want to validate that the URL supplied by an end-user must begin with `https://` so we know its a valid url and not `file://` which could potentially leak a file on the file system.

In this case, we will write the following regex: `^https:\/\/`

This makes sure that the input supplied begins with https. You'll also note that the forward slashes `/` need to be escaped with a backslash `\` first to keep the regex valid.

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

#### Anchor - Ends with

Similar to what we saw earlier, if we want to make sure that the payload that we have received ends with a specifc pattern, we can do so with the help of another anchor metacharacter called the `$` (dollar sign).&#x20;

Simply write `<your-pattern-here>$` , and the regex check will make sure that the payload you have received ends with your specific pattern. Usually implemented by developers for email-fields, where they want to make sure that the email field contains an email that ends with either a specific domain, or a typical email pattern.&#x20;

For example, we are going to try and match a user supplied email address to make sure the string ends in `@challenge.ctf`&#x20;

To do so, the regex will look like: `@challenge\.ctf$`

Now, the `$` makes sure that the input provided matches the pattern `@challenge.ctf`. The forward slash is important in our scenario, because the `.` character means `literally everything (all characters)` in regex. So if we forget to escape the `.` using the forward slash (which developers do sometimes), it can allow someone to enter a value like `test@challengexctf`, and it will a value that is accepted by the application (thereby, introducing a possible vulnerability).&#x20;

<figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

#### Character Sets

Now, it's nice that we can grep for a specific character at a specific position. But what if we want to grab multiple words that are made up of different characters, but all have a specific pattern (for example, a pattern like `<organization-code>.<employeeID>`, where organization code is a 4 character string made up of characters A-Z, and employee ID is 3 character string made up of characters 0-9).&#x20;

In this case, we can use something called character sets, which help us search for words made up using different characters but satisfy our pattern.&#x20;

Character sets are denoted by \[], and within the \[] brackets, we can define properties of our character sets, such as:

1. Any range of characters we are targeting? (A-Z, a-z, 0-9, or maybe something like abc)
2. The order of characters inside the brackets doesn’t matter.
3. One character set matches one character at a time. If your pattern has 6 characters, you will need 6 character sets
4. We can mix numbers, alphabets, and even special characters all in one character set

An example of a regex pattern that searches for dates in the format of `YYYY-MM-DD` will be as follows:

`^[0-2][0-9][0-9][0-9]-[0-1][1-9]-[0-3][1-9]$`

Similarly, if we want to perform a check where the character set should check for all characters but a specific character, we can use the `^` within the character set to perform an `Invert check`.

If we are performing a check where we do not want a specific character in a specific position, that's when we can use the invert check. But be careful while using the invert check. Let's say that you are okay with the `string starting with anything but the character x`, the regex check might look something like:

`^[^x]`.... so on

Now, we have to solve an exercise, where we have to extract usernames from a text. The usernames are made up of the following pattern:

1. First 4 characters are all caps
2. Second character appears to be the capital alphabet A
3. Next 2 characters are number in the range 0-9.
4. Usernames are separater by the space character

So, the regex will look like:

`\b[A-Z][A][A-Z][A-Z][0-9][0-9]\b`

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

OR

`\b[A-Z][A-Z][A-Z][A-Z][0-9][0-9]\b`

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

Both are okay. The reason being both patterns look for individual, standalone strings that match the username format.

#### Quantifiers

With Character sets, we defined the occurrence of a single character in a string. We can use character sets to define at which position which string should appear. Which is great. But like in our last example of grabbing usernames from a string (`\b[A-Z][A-Z][A-Z][A-Z][0-9][0-9]\b`), typing each character set for each character within the string can be time-consuming, especially if they are all in the same pattern (in last example, the first 4 characters were upper case alphabets, and last two characters were numbers).&#x20;

As such, to save time, we can use something called "Quantifiers" to denote the number of times a character, a character set, or a group should occur in our search.&#x20;

There are multiple quantifiers that can be used by us, as follows:

`*` denotes 0 or more times

Content grabbed from HackingHub:&#x20;

Let's say we are doing a code-review, where the code quality is messy. The developers have assigned values to&#x20;

The pattern we used in last example `\b[A-Z][A-Z][A-Z][A-Z][0-9][0-9]\b`  can be rewritten in the following manner: `\b[A-Z]{4}[0-9]{2}\b`

Explanation follows:

