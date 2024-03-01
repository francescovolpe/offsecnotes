# Web cache poisoning

Two phases:
1. The attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload
2. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims

## Cache keys and cache unkeyed
- When the cache receives an HTTP request, it first has to determine whether there is a cached response that it can serve directly.
- Caches identify equivalent requests by comparing a predefined subset of the request's components, known collectively as the "cache key". (Typically, this would contain the request line and Host header)
- Components of the request that are not included in the cache key are said to be "unkeyed".
- --> If the cache key of an incoming request matches the key of a previous request, then the cache considers them to be equivalent. As a result, it will serve a copy of the cached response that was generated for the original request

## Impact of a web cache poisoning attack
Depend on two key factors:
1. What exactly the attacker can successfully get cached
2. The amount of traffic on the affected page
- Note: Note that the duration of a cache entry doesn't necessarily affect the impact of web cache poisoning. An attack can usually be scripted in such a way that it re-poisons the cache indefinitely.

## Constructing a web cache poisoning attack 
1. Identify and evaluate unkeyed inputs
2. Elicit a harmful response from the back-end server
3. Get the response cached

### Identify and evaluate unkeyed inputs
TO DO
