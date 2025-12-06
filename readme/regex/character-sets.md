# Character Sets

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

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

OR

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

Both are okay. The reason being both patterns look for individual, standalone strings that match the username format.
