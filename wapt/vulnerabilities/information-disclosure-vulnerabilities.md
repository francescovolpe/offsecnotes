# Information disclosure vulnerabilities

## Fuzzing

* Add payload positions to parameters and use pre-built wordlists of fuzz strings to test a high volume of different inputs in quick succession.
* Easily identify differences in responses by comparing HTTP status codes, response times, lengths, and so on.
* Use grep matching rules to quickly identify occurrences of keywords, such as error, invalid, SELECT, SQL, and so on.
* Apply grep extraction rules to extract and compare the content of interesting items within responses.

## Common sources of information disclosure

* Files for web crawlers
  * /robots.txt
  * /sitemap.xml
* Developer comments
* Error messages
  * These can provide information about different technologies -> documented exploits
  * Check whether there are any configuration errors or dangerous default settings that you may be able to exploit
  * Observing differences in error messages is a crucial aspect of many techniques, such as SQLi, username enume...
* Debugging data
  * Debugging information may sometimes be logged in a separate file
* User account pages
  * Example: via IDOR
* Source code disclosure via backup files
  * Text editors often generate temporary backup files while the original file is being edited
    * appending a tilde (`~`) to the filename or adding a different file extension
* Information disclosure due to insecure configuration
  * Websites are sometimes vulnerable as a result of improper configuration especially common due to the widespread use of third-party technologies, whose vast array of configuration options are not necessarily.
  * Example HTTP TRACE. Occasionally could leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.
* Version control history
  * Browsing to `/.git`
  * TO DO...
