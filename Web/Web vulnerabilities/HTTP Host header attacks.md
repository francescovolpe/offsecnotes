# HTTP Host header attacks

## Virtual hosting
- Single web server hosts multiple websites or applications.
- Slthough each of these distinct websites will have a different domain name, they all share a common IP address with the server. 
- Websites hosted in this way on a single server are known as "virtual hosts".

## Routing traffic via an intermediary
- Websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system.
- This could be a simple load balancer or a reverse proxy server of some kind.

## HTTP Host header
```
GET /web-security HTTP/1.1
Host: portswigger.net
```
Http host header refers to the Host header to determine the intended back-end


## Defences
TO DO...

## Exploiting
TO DO...
