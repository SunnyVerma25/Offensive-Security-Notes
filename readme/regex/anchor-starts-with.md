# Anchor - Starts with

We learned to search for literal matches, and for exact strings. Now, these matches can occur at any position within our content. But what if we wanted to search for a specific text, and make sure that this content occurs at the beginning of the string or line? Or what if as a developer, we want to make sure that the input provided by a user matches the format of https://\<content-com>?&#x20;

This can be made possible with another bunch of metacharacters called **Anchors**. These are special regex characters that **don’t match characters**, they match **positions** in a string (a.k.a, where does the pattern exist in a string).

Now, if we wish to perform a check for a pattern that appears at the beginning of a string, we can do so with the help of another metacharacter called the `Caret` symbol. We use the `^` (caret symbol) character to ensure that our search for the specific pattern includes the check that the pattern appears at the beginning of a string or a line.&#x20;

It means: “Only match if this pattern is at the very start.”

For example, we want to validate that the URL supplied by an end-user must begin with `https://` so we know its a valid url and not `file://` which could potentially leak a file on the file system.

In this case, we will write the following regex: `^https:\/\/`

This makes sure that the input supplied begins with https. You'll also note that the forward slashes `/` need to be escaped with a backslash `\` first to keep the regex valid.

<figure><img src="../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>
