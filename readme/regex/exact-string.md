# Exact String

So, you want to find the occurrence of an exact word in a sea of text. You don't want false positives like supercomputer or computerx. You only want to highlight the exact word "computer".&#x20;

In order to do so, regex provides the usage of metacharacters/special characters. To use these, we usually start with a `/` character, followed by whatever type of metacharacter we wish to use. In our specific case, we can use the `word boundary` character (`/b`) that is used to denote the empty space between two words.&#x20;

So, if use a regex like `\bcomputer\b`, it is basically looking for the exact occurrence of the computer word in the text. It does not take into account words like `supercomputer` (no space between r and c, so regex fails), or `computerx`(again, no space between r and x, and hence regex fails).&#x20;

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
