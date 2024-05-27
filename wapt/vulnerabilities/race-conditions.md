# Race conditions

This happens when websites process requests concurrently without proper safeguards, leading to multiple threads accessing the same data simultaneously, causing unintended application behavior due to "collisions." The period of time during which a collision is possible is known as the "race window"

## Impact

* Redeeming a gift card multiple times
* Rating a product multiple times
* Withdrawing or transferring cash in excess of your account balance
* Reusing a single CAPTCHA solution
* Bypassing an anti-brute-force rate limit
* Etc.

## Detecting and exploiting limit overrun race conditions with Burp Repeater

* Even when sending requests simultaneously, uncontrollable external factors can influence the server's request processing timing and order, making it unpredictable.
* Burp automatically adjusts the technique
* Although triggering an exploit often requires just two requests, sending a substantial number of requests like this helps reduce internal latency, referred to as server-side jitter.

## Other

To do ...
