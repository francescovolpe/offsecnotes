# GraphQL API

## <mark style="color:yellow;">GraphQL endpoints</mark> <a href="#finding-graphql-endpoints" id="finding-graphql-endpoints"></a>

### <mark style="color:yellow;">Universal queries</mark> <a href="#universal-queries" id="universal-queries"></a>

Sending `query{__typename}` to a GraphQL endpoint will return `{"data": {"__typename": "query"}}` in the response

## <mark style="color:yellow;">Common endpoint names</mark> <a href="#common-endpoint-names" id="common-endpoint-names"></a>

```
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
/v1/graphql
/v1/api
/v1/api/graphql
/v1/graphql/api
/v1/graphql/graphql
```

{% hint style="info" %}
**Note**: Response could be "query not present" or similar. (meaning it's present)
{% endhint %}

## <mark style="color:yellow;">Request methods</mark>

Now, test using different request methods.&#x20;

While production endpoints usually accept POST requests with `application/json` to prevent CSRF, some may accept GET or POST with `x-www-form-urlencoded`.

Resending the universal query using alternative HTTP methods.

## <mark style="color:yellow;">Exploiting unsanitized arguments</mark> <a href="#exploiting-unsanitized-arguments" id="exploiting-unsanitized-arguments"></a>

If the API uses arguments to access objects directly, it may be vulnerable to access control/IDOR vulnerabilities.

## <mark style="color:yellow;">Discovering schema information</mark> <a href="#discovering-schema-information" id="discovering-schema-information"></a>

### <mark style="color:yellow;">Using introspection</mark> <a href="#using-introspection" id="using-introspection"></a>

\


