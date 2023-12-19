# API testing

## API Recon
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
 
## Identifying API endpoints
- Browsing application
  - (even if you have access to documentaion, as it may be inaccurate)
- Look out for JavaScript files (These can contain references to API endpoints)
  - Suggestion: JS Link Finder BApp 
