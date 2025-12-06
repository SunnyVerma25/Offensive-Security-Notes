# Literal Match

As the name suggests, this means we are literally searching for the exact character match. The act of pressing CTRL+F in a document and searching for the exact word is a good example of literal match, as we are "literally" searching for occurrence of the exact pattern of characters in a given content.&#x20;

A **literal match** means you're telling regex to look for _exactly_ the text you type, character for character.

* If you write `hello`, it will match only the string `hello`.
* No wildcards, no magic just a direct match.

But, there's a slight problem. If you search for the word `computer` in a document (or any other word; `computer` is just an example), the document can return 5 (again, just an example) occurrences of the word `computer`. 4 of these could be the word `computer`, but the 5th word can be the word `supercomputer`. Since `computer` is part of the word `supercomputer`, hence why there are 5 instances of these words returned, which may be problematic if you are only looking for the word `computer`. This problem brings us to the next example of `Exact Strings` in regex.
