---
layout: page

title: WebSec

category: infosec
see_my_category_in_header: true

permalink: /infosec/web.html

published: true
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

* [OWASP](https://www.owasp.org/index.php/Main_Page) - Open Web Application Security Project
* [WASC](http://projects.webappsec.org/w/page/13246978/Threat%20Classification) - Web Application Security Consorcium - Threat Classification
* [MDN - web security](https://developer.mozilla.org/en-US/docs/Web/Security)

# Weakened places

AAA
: Authentication, Authorization, Accounting

Password policies


<br>

---

# Web-attacks

***XSS*** (Cross-Site Scripting)
: XSS enables attackers to inject client-side scripts into web pages viewed by other users. XSS enables attackers to bypass access controls such as SOP (Same Origin Policy)

* reflected XSS (non-persistent) - malicious code reflects from server into user's browser
* stored XSS (persistent) - malicious code are stored on webserver and served to users
* dom-based XSS - malicious code does not reach webserver and inserted/executed in user's browser by JS logic

***Content Spoofing***

***Abuse of functionality***

***CSRF*** - Cross-Site Request Forgery

***SSRF*** - Server-Side Request Forgery

***Open redirect***

***Click-hijacking***

<br>

***SQL-injection***

***XXE*** - XML external entity

<br>

Logic-related vulnerabilities:

* Information leakage
* Unprotected web-site API
* Authorization vulnerabilities

<br>

***LFI*** - Local file inclusion

***Path Traversal***

<br>

***DoS*** - Denial-of-Service (resource consuming web-application requests)

***RCE*** - Remote code execution

***server misconfiguration***, ***TLS misconfiguration***

***fingerprinting*** - ???

***HTTP Response Splitting/Smuggling***

***Cache-Poisoning***


<br>

---

# Web-defense

#### Browser-methods

* [Same-Origin-Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) - restricts how a document or script loaded from one origin can interact with a resource from another origin

#### HTTP-headers

* [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
* [`X-Content-Type-Options: nosniff`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
* [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) - indicate whether or not a browser should be allowed to render a page in a `<frame>`, `<iframe>` or `<object>`

    defense from click-hijacking

* Content-Security-Policy - [CSP quick reference guide (5+)](https://content-security-policy.com/)
* HSTS - [Strict-Transport-Security](https://developer.mozilla.org/ru/docs/Web/HTTP/Headers/Strict-Transport-Security) - force web-site to use only HTTPS instead of HTTP

    bypass: MITM and url-change (e.g. `wwww.google.com`)

* HPKP - HTTP [Public-Key-Pinning](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning)

* [HttpOnly cookie](https://www.owasp.org/index.php/HttpOnly)

    bypass:

    * XMLHTTPResponse.getAllResponseHeaders() - for browser < IE7
    * HTTP `TRACE` method (for common web-servers this method is not allowed - ???) (modern web-browser's block XMLHTTPRequest with `TRACE` method)

<br>

---

# Tools

Web-proxies:

* [BurpSuite](https://portswigger.net/burp/freedownload/) - web-proxy (plugin-able)

    Extensions:

    * [backslash-powered-scanner](https://github.com/PortSwigger/backslash-powered-scanner) - scanner
    * [Burp Suite Logger++](https://github.com/nccgroup/BurpSuiteLoggerPlusPlus) - logger
    * [Wsdler](https://github.com/NetSPI/Wsdler) - parses wsdl
    * [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) - authentication check

* [Fiddler](http://www.telerik.com/fiddler) - web-proxy (script-able), Fiddler's capabilities DEFCON [presentation](http://www.defcon–moscow.org/archive/%234%20%5b23.11.2013%5d/2.Web_analyst_Fiddler.pdf)
* [OWASP Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - web-proxy from OWASP community

Webshells:

* [b374k](https://github.com/b374k/b374k) - php web-shell
* [php-webshells](https://github.com/JohnTroony/php-webshells) - collection of php web-shells

Flash:

* [jpex](https://www.free-decompiler.com/flash/download/) - free flash decompiler
* [FlashDevelop](FlashDevelop) – flash code editor
* [flashcookiesview](https://www.nirsoft.net/utils/flash_cookies_view.html) – displays the list of cookie files created by Flash component
* [RABCDAsm](https://github.com/CyberShadow/RABCDAsm) - Robust ABC (ActionScript Bytecode) [Dis-]Assembler

</article>
