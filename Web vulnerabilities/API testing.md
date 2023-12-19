# API testing

- You need to find out as much information about the API as possible
  - Discover API endpoint
  - Input data the API processes (compulsory and optional parameters).
  - Supported HTTP methods and media formats.
  - Rate limits and authentication mechanisms.
 
## Discovering API documentation 
- Endpoints that may refer to API documentation:
  - `/api`, `/swagger/index.html`, `/openapi.json`

- If you identify the resource endpoint `/api/swagger/v1/users/123` use a list of common paths to directly fuzz for documentation
  - `/api/swagger/v1`, `/api/swagger`, `/api`
