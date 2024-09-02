# API

## <mark style="color:yellow;">API documentation</mark>

* Endpoints that may refer to API documentation:

```
/api
/swagger/index.html
/openapi.json
```

* If you identify the resource endpoint `/api/swagger/v1/users/123` use a list of common paths to directly fuzz for documentation

```
/api/swagger/v1
/api/swagger
/api
```

## <mark style="color:yellow;">API endpoints</mark>

* Browsing application (even if you have access to documentation, as it may be inaccurate)
* Look out for JavaScript files&#x20;

{% hint style="info" %}
**Tip**: JS Link Finder BApp (Burp extension)
{% endhint %}

## <mark style="color:yellow;">Supported HTTP methods</mark>

Test all potential methods when you're investigating API endpoints

{% hint style="success" %}
**Tip**: Use HTTP verbs list in Burp Intruder
{% endhint %}

## <mark style="color:yellow;">Supported content types</mark>

Changing the content type may enable you to

* Trigger errors that disclose useful information.
* Bypass flawed defenses.
* Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.

To change the content type, modify the Content-Type header and reformat the request body

{% hint style="success" %}
**Tip**: Content type converter BApp automatically converts request data between XML and JSON.
{% endhint %}

## <mark style="color:yellow;">Hidden endpoints</mark>

Consider `PUT /api/user/update`

* Fuzz the `/update` with a list of other common functions, such as `delete` and `add`
* Use wordlists based on common API naming

## <mark style="color:yellow;">Hidden parameters</mark>

* Bruteforce with wordlists
* Param miner (Burp extension)

## <mark style="color:yellow;">Mass assignment vulnerabilities</mark>

Software frameworks sometime allow developers to automatically bind HTTP request parameters into program code variables or objects to make using that framework easier on developers.

**Premise**

Consider `PATCH /api/users/` which enables users to update their username and email `{"username": "lebron", "email": "lebron@example.com"}`

A concurrent `GET /api/users/123` request returns the following JSON: `{"id": 123, "name": "Lebron James", "email": "leb@example.com", "isAdmin": "false"}`

This may indicate that the hidden id and isAdmin parameters are bound to the internal user object, alongside the updated username and email parameters.

***

**Testing**

To test whether you can modify the enumerated isAdmin parameter value, send two PATCH request:

* `{"username": "lebron", "email": "leb@example.com", "isAdmin": false}`
* `{"username": "lebron","email": "leb@example.com", "isAdmin": "foo",}`

If the application behaves differently, may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user. (Set it to true)

Note: We change isAdmin to "foo" because we want see if the user input is processed. If we get an error may indicate that the user input is being processed.
