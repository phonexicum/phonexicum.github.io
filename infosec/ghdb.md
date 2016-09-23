---
layout: page

title: GHDB

category: infosec
see_my_category_in_header: true

permalink: /infosec/ghdb.html

published: true
---

<article class="markdown-body" markdown="1">

GHDB - Google Hacking Database
: *Google stores a lot of information and crawl sites constantly. This information can be used in pentest interests.*

Huge GHDB base is on [exploit-db.com](https://www.exploit-db.com/google-hacking-database/)

Using manually written queries - is **wrong** idea. <br>
**Lists** and **automated tools** must be used to collect information of interest for further analysis.

## Google key words

***Punctuation and symbols***:

| operator | meaning | examples
| :---: | :--- | :--- |
| `+`   | Search for Google+ pages or blood types     | +Chrome or  AB+
| `@`   | Find social tags                            | @agoogler
| `$`   | Find prices                                 | nikon $400
| `#`   | Find popular hashtags for trending topics   | #throwbackthursday
| `-`   | Exclude web-pages with specified words or site  | Examples: jaguar speed -car or pandas -site:wikipedia.org
| `"`   | When you put a word or phrase in quotes, the results will only include pages with the same words in the same order as the ones inside the quotes | "imagine all the people"
| `.`   | Any symbol |
| `*`   | Any text     | "a * saved is a * earned"
| `..`  | Number range  | camera $50..$100

***Search operators***:

| operator | meaning | examples
| :---: | :--- | :--- |
| site:     | Get results from certain sites or domains    | olympics site:nbc.com and olympics site:.gov
| inurl:    | Get results with specified word in uri (searches after site name) | inurl:news
| intext:   | Search in web-page body | intext:passwd
| intitle:  | Search in web-page title tag | intitle:"index of"
| ext: / filetype: | Search pages with special extension | ext:pdf
||||
| related:  | Find sites that are similar to a web address you already know    | related:time.com
| link:     | Searche sites refering to specified site  | link:wikipedia.com
| OR        | Find pages that might use one of several words   | marathon OR race
| info:     | Get information about a web address, including the cached version of the page, similar pages, and pages that link to the site    | info:google.com
| cache:    | See what a page looks like the last time Google visited the site | cache:washington.edu
| define:   | Show definition of term | define:0day


</article>
