# API testing

<details>

<summary>$\huge{\text{API Recon}}$</summary>

* You need to find out as much information about the API as possible
  * Discover API endpoint
  * Input data the API processes (compulsory and optional parameters).
  * Supported HTTP methods and media formats.
  * Rate limits and authentication mechanisms.

\


</details>

<details>

<summary>$\huge{\text{Discovering API documentation}}$</summary>

* Endpoints that may refer to API documentation:
  * `/api`, `/swagger/index.html`, `/openapi.json`
* If you identify the resource endpoint `/api/swagger/v1/users/123` use a list of common paths to directly fuzz for documentation
  * `/api/swagger/v1`, `/api/swagger`, `/api`

\


</details>

<details>

<summary>$\huge{\text{Identifying API endpoints}}$</summary>

* Browsing application
  * (even if you have access to documentation, as it may be inaccurate)
* Look out for JavaScript files (These can contain references to API endpoints)
  * Suggestion: JS Link Finder BApp

\


</details>

<details>

<summary>$\huge{\text{Identifying supported HTTP methods}}$</summary>

* Test all potential methods when you're investigating API endpoints
  * Use HTTP verbs list in Burp Intruder

\


</details>

<details>

<summary>$\huge{\text{Identifying supported content types}}$</summary>

Changing the content type may enable you to

* Trigger errors that disclose useful information.
* Bypass flawed defenses.
* Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.
* To change the content type, modify the Content-Type header, then reformat the request body accordingly
  * Suggestion: Content type converter BApp automatically convert data submitted within requests between XML and JSON

\


</details>

<details>

<summary>$\huge{\text{Fuzzing to find hidden endpoints}}$</summary>

* `PUT /api/user/update`
  * Fuzz the `/update` with a list of other common functions, such as `delete` and `add`
  * Use wordlists based on common API naming

\


</details>

<details>

<summary>$\huge{\text{Finding hidden parameters}}$</summary>

* Wordlists
  * Burp Intruder, Param miner BApp

\


</details>

<details>

<summary>$\huge{\text{Mass assignment vulnerabilities}}$</summary>

* Software frameworks sometime allow developers to automatically bind HTTP request parameters into program code variables or objects to make using that framework easier on developers
* Consider `PATCH /api/users/` which enables users to update their username and email and includes the following JSON
  * `{"username": "wiener", "email": "wiener@example.com",}`
* A concurrent `GET /api/users/123` request returns the following JSON:
  * `{"id": 123, "name": "John Doe", "email": "john@example.com", "isAdmin": "false"}`
  * This may indicate that the hidden id and isAdmin parameters are bound to the internal user object, alongside the updated username and email parameters
* Testing
  * To test whether you can modify the enumerated isAdmin parameter value, add it to the PATCH request:
  * `{"username": "wiener", "email": "wiener@example.com", "isAdmin": false,}`
  * In addition, send a PATCH request with an invalid isAdmin parameter value:
  * `{"username": "wiener","email": "wiener@example.com", "isAdmin": "foo",}`
  * If the application behaves differently, this may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user. (Set it to true)
    * Note: We change isAdmin to "foo" because we want see if the user input is processed. If we get an error may indicate that the user input is being processed

\


</details>

<details>

<summary>$\huge{\text{Preventing vulnerabilities in APIs}}$</summary>

* Secure your documentation if you don't intend your API to be publicly accessible.
* Ensure your documentation is kept up to date so that legitimate testers have full visibility of the API's attack surface.
* Apply an allowlist of permitted HTTP methods.
* Validate that the content type is expected for each request or response.
* Use generic error messages to avoid giving away information that may be useful for an attacker.
* Use protective measures on all versions of your API, not just the current production version. To prevent mass assignment vulnerabilities, allowlist the properties that can be updated by the user, and blocklist sensitive properties that shouldn't be updated by the user.

\


</details>
