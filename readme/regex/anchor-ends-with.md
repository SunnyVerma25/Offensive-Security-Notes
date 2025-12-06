# Anchor - Ends with

Similar to what we saw earlier, if we want to make sure that the payload that we have received ends with a specifc pattern, we can do so with the help of another anchor metacharacter called the `$` (dollar sign).&#x20;

Simply write `<your-pattern-here>$` , and the regex check will make sure that the payload you have received ends with your specific pattern. Usually implemented by developers for email-fields, where they want to make sure that the email field contains an email that ends with either a specific domain, or a typical email pattern.&#x20;

For example, we are going to try and match a user supplied email address to make sure the string ends in `@challenge.ctf`&#x20;

To do so, the regex will look like: `@challenge\.ctf$`

Now, the `$` makes sure that the input provided matches the pattern `@challenge.ctf`. The forward slash is important in our scenario, because the `.` character means `literally everything (all characters)` in regex. So if we forget to escape the `.` using the forward slash (which developers do sometimes), it can allow someone to enter a value like `test@challengexctf`, and it will a value that is accepted by the application (thereby, introducing a possible vulnerability).&#x20;

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>
