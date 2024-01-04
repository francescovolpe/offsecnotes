# Clickjacking

- Clickjacking is a type of attack where a user is deceived into clicking on something on a hidden website by making them click on something else on a decoy website.
- The method involves embedding an invisible, interactive web page (or multiple pages) that contains a button or hidden link, typically within an iframe. This iframe is then placed over the expected content of the user's decoy web page.
- Clickjacking attacks are not mitigated by the CSRF token as a target session is established with content loaded from an authentic website and with all requests happening on-domain
```
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test</div>
<iframe src=""></iframe>
```
## Clickjacking with prefilled form input
- Some websites that require form completion and submission permit prepopulation of form inputs using GET parameters prior to submission
  - http://website.com/account?email=test@test.com
  - In this case the email form field will be set to test@test.com

## Frame busting scripts
- Clickjacking attacks can occur whenever websites can be framed. To prevent such attacks, techniques focus on limiting the framing ability of websites. A common client-side defense implemented through web browsers is the use of frame-busting or frame-breaking scripts.
  - These can be implemented via proprietary browser JavaScript add-ons or extensions such as NoScript (make all frames visible, prevent clicking on invisible frames, etc.)
- An effective attacker workaround against frame busters is to use the HTML5 iframe `sandbox` attribute.
    - ` <iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe> `
    - When this is set with the `allow-forms` or `allow-scripts` values and the `allow-top-navigation` value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window

## Combining clickjacking with a DOM XSS attack
- Some websites that require form completion and submission permit prepopulation of form inputs using GET parameters prior to submission
    - https://website.com/account?email=test@test.com

## Multistep clickjacking
- Attacker manipulation of inputs to a target website may necessitate multiple actions
- These actions can be implemented by the attacker using multiple divisions or iframes

# Prevent clickjacking attacks
1) X-Frame-Options
   - X-Frame-Options is not implemented consistently across browsers
   - ` X-Frame-Options: deny `
   - ` X-Frame-Options: sameorigin `
   - ` X-Frame-Options: allow-from https://normal-website.com `
2) Content Security Policy (CSP)
   - CSP is usually implemented in the web server as a return header
   - CSP also validates each frame in the parent frame hierarchy, whereas X-Frame-Options only validates the top-level frame.
   - ` Content-Security-Policy: frame-ancestors 'self'; ` similar to -> X-Frame-Options deny
   - ` Content-Security-Policy: frame-ancestors normal-website.com; ` similar to -> X-Frame-Options sameorigin

Combine this with the X-Frame-Options header to provide protection on older browsers that don't support CSP, such as Internet Explorer.

