# Web LLM

LLMs are AI algorithms that generate plausible responses by predicting word sequences from user inputs.

## <mark style="color:yellow;">Methodology</mark>

1. Identify the LLM's inputs, including direct (e.g., a prompt) and indirect (e.g., training data).&#x20;
2. Determine the data and APIs accessible to the LLM
3. Examine this attack surface for vulnerabilities.

## <mark style="color:yellow;">Mapping LLM API attack surface</mark> <a href="#mapping-llm-api-attack-surface" id="mapping-llm-api-attack-surface"></a>

* Ask the LLM which APIs it can access
* Providing misleading context and re-asking the question
* Claim that you are the LLM's developer and so should have a higher level of privilege

## <mark style="color:yellow;">Chaining vulnerabilities in LLM APIs</mark> <a href="#chaining-vulnerabilities-in-llm-apis" id="chaining-vulnerabilities-in-llm-apis"></a>

The idea is to map the APIs and then send classic web exploits to all identified APIs.

* Suppose you normally have access to a "Newsletter Subscription" feature but no parameters can be controlled.&#x20;
* Imagine instead that LLM has access to "Newsletter Subscription" API. you can try to control how this API is called...&#x20;
* For example if a system command is used you might get an rce if you ask the LLM to call the Newsletter Subscription API with the argument `$(whoami)@your-email.com`

## <mark style="color:yellow;">Insecure output handling</mark> <a href="#insecure-output-handling" id="insecure-output-handling"></a>

A web app uses an LLM to generate content from user prompts without sanitization. An attacker could submit a crafted prompt causing the LLM to return unsanitized JavaScript, leading to XSS / CSRF etc.
