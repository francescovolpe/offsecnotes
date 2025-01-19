# API

## <mark style="color:purple;">Discover</mark>

**Documentation**

Endpoints that may refer to API documentation

```
/api
/swagger/index.html
/openapi.json
```

Use common paths to directly fuzz for doc: `/api/swagger/v1/users/123`

```
/api/swagger/v1
/api/swagger
/api
```

***

**Endpoints**

* Browsing application (even if you have access to documentation, as it may be inaccurate)
* Consider `PUT /api/user/update`, fuzz the `/update` with a list of other common functions, such as `delete` and `add`
* Use wordlists based on common API naming
* Look out for JavaScript files&#x20;

{% hint style="success" %}
**Tip**: JS Link Finder BApp (Burp extension)
{% endhint %}

***

**HTTP methods**

Test all potential methods when you're investigating API endpoints

{% hint style="success" %}
**Tip**: Use HTTP verbs list in Burp Intruder
{% endhint %}

***

**Hidden parameters**

* Bruteforce with wordlists
* Param miner (Burp extension)

## <mark style="color:purple;">Change content types</mark>

Changing the content type may enable you to

* Trigger errors that disclose useful information.
* Bypass flawed defenses.
* Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.

To change the content type, modify the Content-Type header and reformat the request body

{% hint style="success" %}
**Tip**: Content type converter BApp automatically converts request data between XML and JSON.
{% endhint %}

## <mark style="color:purple;">Mass assignment vulnerabilities</mark>

<details>

<summary>Theory</summary>

Software frameworks sometime allow developers to automatically bind HTTP request parameters into program code variables or objects to make using that framework easier on developers.

**Premise**

Consider `PATCH /api/users/` which enables users to update their username and email `{"username": "lebron", "email": "lebron@example.com"}`

A concurrent `GET /api/users/123` request returns the following JSON: `{"id": 123, "name": "Lebron James", "email": "leb@example.com", "isAdmin": "false"}`

This may indicate that the hidden id and isAdmin parameters are bound to the internal user object, alongside the updated username and email parameters.

</details>

To test whether you can modify the enumerated isAdmin parameter value, send two PATCH request:

* `{"username": "lebron", "email": "leb@example.com", "isAdmin": false}`
* `{"username": "lebron","email": "leb@example.com", "isAdmin": "foo",}`

If the application behaves differently, may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user. (Set it to true)

{% hint style="info" %}
**Note**: We change isAdmin to "foo" because we want see if the user input is processed. If we get an error may indicate that the user input is being processed.
{% endhint %}

## <mark style="color:purple;">Server-side parameter pollution</mark> <a href="#server-side-parameter-pollution" id="server-side-parameter-pollution"></a>

You make the request and the server queries an internal API

```sh
# Your browser
GET /userSearch?name=test&back=/home
# Internal queries
GET /users/search?name=test&publicProfile=true
```

**Truncating query strings**

If you use a URL-encoded `#` you can truncate the server-side request

```sh
# Your browser
GET /userSearch?name=test%23foo&back=/home
# Internal queries
GET /users/search?name=test#foo&publicProfile=true
```

***

**Injecting invalid parameters**

You can use an URL-encoded `&` character and review the response for clue about the additional parameter is parsed. (if the response is unchanged it may indicate that the parameter was successfully injected but ignored by the application)

```sh
# Your browser
GET /userSearch?name=test%26foo=xyz&back=/home
# Internal queries
GET /users/search?name=test&foo=xyz&publicProfile=true
```

***

**Injecting valid or override parameters**

The impact of this depends on how the application processes the second parameter.
