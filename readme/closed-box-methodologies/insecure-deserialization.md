# Insecure Deserialization

When we deploy a web application, we may have built it using PHP, JAVA or some other development programming language. This web application will have a front-end through which users may interact with the web application, and in some instances, they may want to send data to the application (such as a POST request to update their user profile). Now, when a user wants to send their data, they cannot send JAVA object via the API call. When the user enters data into the text-field of the application, this data gets stored in the memory of the browser (temporarily).&#x20;

When the user click on 'Submit' button, this in-memory object gets converted into an object format that can be sent over the wire (aka the internet/network). To do this, the browser will most likely use a format (such as JSON, URL Form, Multi-part data, etc) that can be used to transfer the data over the internet connection.&#x20;

This data object (let's say JSON), when being sent over the wire (in the form of bytes), is called a 'Serialized' object. When this object reaches the back-end of the application, the application must take this stream of bytes (the JSON object), and then convert it into the format it understands (let's say JAVA). This conversion of JSON object to JAVA object is known as deserialization.&#x20;

<figure><img src="../../.gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>

Serialized objects often have a specific format, where the format is "Data type: Data". For example, in our serialization example using PHP, the serialized object looks like:

O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:9:"not admin";}

Which means there's an object of class "User", with length of 4 bytes (U S E R), with 2 properties. These properties are type "string" (hence, the s), with byte size 8 for username, with the name "vickie", bytes 6.&#x20;

Now, if we deserialize this serialized data using the unserialize library, we get the deserialized data:

<figure><img src="../../.gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

The deserialized data shows that there's a user named vickie, who's status is "not\_admin"

Now, what if we decide to mess with the serialized value, and change the value of status from not\_admin to admin?&#x20;

<figure><img src="../../.gitbook/assets/image (162).png" alt=""><figcaption></figcaption></figure>

O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:5:"admin";}

<figure><img src="../../.gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

Well, the user is now an admin user!
