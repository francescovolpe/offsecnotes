# Javascript security considerations

## Javascript eval() - DOM XSS

* In all these case an alert will appear
  * `let text = alert();`
  * `let text = 'test' - alert();`
    * (you can use other symbols instead of `-`)
* Consider `eval('var searchResultsObj = ' + this.responseText);`
  * If you can manipulate the `this.responseText` string you can execute an alert.
    * (The response is taken with ajax)
  * If the response is `{"results":[],"searchTerm":"XSS"}` and you are able to change `XSS` keyword into `\"-alert(1)}//` the result will be `{"results":[],"searchTerm":"\\"-alert(1)}//"}` and an alert will appear
  * Note 1: Notice that JSON automatically escape the double quote `"` (standard feature of javascript string) so we need to use `\"`
  * Note 2: We add // to comment the rest
  * Note 3: This specific example with JSON works because the site didn't use `JSON.parse(this.responseText)`
  * This 4: This specific example is a case of Reflected DOM XSS

## Javascript replace() problem

* The replace() method of String values returns a new string with one, some, or all matches of a pattern replaced by a replacement. The pattern can be a string or a RegExp, and the replacement can be a string or a function called for each match.
* If pattern is a string, only the first occurrence will be replaced. The original string is left unchanged.

```
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```

* You can easy bypass this with `<><img src=1 onerror=alert(1)>`

## Javascript innerHTML

```
name = "<script>alert('I am John in an annoying alert!')</script>";
el.innerHTML = name; // harmless in this case
```

* HTML specifies that a `<script>` tag inserted with innerHTML should not execute
  * In this case you can use `const name = "<img src='x' onerror='alert(1)'>";`

## Javascript location

* In JavaScript, the location variable represents the object that provides information about the URL (Uniform Resource Locator) of the current document

```
<script>
location = 'https://google.it';
</script>
```

* The browser will interpret this assignment as a command to change the location of the current web page and redirect it to "https://google.it."

## Javascript href Attribute

| Value | Description          |
| ----- | -------------------- |
| URL   | The URL of the link. |

Possible values:

* An absolute URL - points to another web site (like href="http://www.example.com/default.htm")
* A relative URL - points to a file within a web site (like href="default.htm")
* Link to an element with a specified id within the page (like href="#section2")
* Other protocols (like https://, ftp://, mailto:, file:, etc..)
* A script (like href="javascript:alert('Hello');")
