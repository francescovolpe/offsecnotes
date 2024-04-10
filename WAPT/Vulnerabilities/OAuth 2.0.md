# OAuth 2.0

## What is OAuth?
- OAuth is a commonly used authorization framework that enables web applications to request limited access to a user's account on another application.

## How does OAuth 2.0 work?
- **Client application** - The website that wants to access the user's data.
- **Resource owner** - The user whose data the client application wants to access.
- **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

## OAuth grant type / OAuth flows
- The OAuth grant type determines the exact sequence of steps that are involved in the OAuth process.
- There are several different grant types, each with varying levels of complexity and security considerations.
- Note: (We'll focus on the "authorization code" and "implicit" grant types as these are by far the most common.)
- TO DO....

## OAuth authentication
- Although not originally intended for this purpose, OAuth has evolved into a means of authenticating users as well.
- From an end-user perspective, the result of OAuth authentication is something that broadly resembles SAML-based single sign-on (SSO).
- OAuth authentication is generally implemented as follows:
  - The user chooses the option to log in with their social media account. The client application then uses the social media site's OAuth service to request access to some data that it can use to identify the user. This could be the email address that is registered with their account, for example.
  - After receiving an access token, the client application requests this data from the resource server, typically from a dedicated /userinfo endpoint.
  - Once it has received the data, the client application uses it in place of a username to log the user in. The access token that it received from the authorization server is often used instead of a traditional password.

## Identifying OAuth authentication
-  If you see an option to log in using your account from a different website, this is a strong indication that OAuth is being used.
-  Regardless of which OAuth grant type is being used, the first request of the flow will always be a request to the `/authorization` endpoint containing a number of query parameters that are used specifically for OAuth. In particular, keep an eye out for the `client_id`, `redirect_uri`, and `response_type` parameters

### Recon
- TO DO...

## Vulnerabilities in the OAuth client application
### Improper implementation of the implicit grant type
### Flawed CSRF protection
