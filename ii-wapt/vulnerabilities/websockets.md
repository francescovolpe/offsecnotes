# WebSockets

WebSocket connections are long-lived HTTP initiations, enabling bidirectional, non-transactional messaging. The connection remains open and idle until a message is sent by either the client or server. WebSocket excels in low-latency and server-triggered message scenarios, like real-time financial data feeds.

## How are WebSocket connections established?

WebSocket connections are normally created using client-side JavaScript like the following:

`var ws = new WebSocket("wss://normal-website.com/chat");`

The `wss` protocol establishes a WebSocket over an encrypted TLS connection, while the `ws` protocol uses an unencrypted connection.

To establish the connection, the browser and server perform a WebSocket handshake via HTTP. The browser sends a WebSocket handshake request like this:

```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

## Headers

* The `Connection` and `Upgrade` headers in the request and response indicate that this is a WebSocket handshake.
* The `Sec-WebSocket-Version` request header specifies the WebSocket protocol version that the client wishes to use. This is typically 13.
* The `Sec-WebSocket-Key` request header contains a Base64-encoded random value, which should be randomly generated in each handshake request.
* The `Sec-WebSocket-Accept` response header contains a hash of the value submitted in the Sec-WebSocket-Key request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.

## What do WebSocket messages look like?

* WebSocket messages can contain any content or data format
  * `ws.send("Peter Wiener");`
* It is common to use json
  * `{"user":"Hal Pline","content":"I wanted to be a Playstation growing up, not a device to answer your inane questions"}`

## WebSockets security vulnerabilities

* If inputs are transmitted and processed server-side
  * Server-side attacks (SQLi, XXE, etc.)
* If attacker-controlled data is transmitted via WebSockets to other application users
  * Client-side attacks (XSS, etc.)
    * Example if the content of a message is transmitted to another user (via chat...)
    * `{"message":"<img src=1 onerror='alert(1)'>"}`
* Also blind vulnerabilities

## Manipulating WebSocket connections

To do ...

## Cross-site WebSocket hijacking

An attacker can craft a malicious webpage on their domain, initiating a cross-site WebSocket connection to the susceptible application.

* Perform unauthorized actions masquerading as the victim user (like CSRF)
* Retrieve sensitive data that the user can access.
  * Cross-site WebSocket hijacking grants the attacker bidirectional access to the vulnerable application via the hijacked WebSocket. If the application utilizes server-generated WebSocket messages to send sensitive user data, the attacker can intercept these messages and capture the victim user's data.
* Waiting for incoming messages to arrive containing sensitive data.

## Defences

* Use the wss:// protocol
* Hard code the URL of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
* Protect the WebSocket handshake message against CSRF --> token
* Treat data received via the WebSocket as untrusted in both directions ... like SQLi, XSS, etc.
