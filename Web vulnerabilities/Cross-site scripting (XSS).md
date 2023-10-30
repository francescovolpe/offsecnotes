# Cross-site scripting (XSS)

## General info
Cross-site scripting works by manipulating a vulnerable web site so that it returns malicious JavaScript to users

## Alert() limitation
TO DO

## Types of XSS
- Reflected XSS, where the malicious script comes from the current HTTP request.
  - `https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>`
- Stored XSS, where the malicious script comes from the website's database.
  - POST example: `comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E`
- DOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.




