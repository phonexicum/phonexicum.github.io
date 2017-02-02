---
layout: page

title: Web-Crawler

category: phonexicum
see_my_category_in_header: true

permalink: /infosec/webcrawler.html

published: true
---

<article class="markdown-body" markdown="1">

This article contains thoughts about crawler for dynamic sites with AJAX.

***Target***: Crawl web-application functionality (not content)

***Main concept***: Web-crawler layout = web-application state = web-site view for users

# Content

* TOC
{:toc}

# Web-crawler

## Crawler objectives

- Detecting clickables
    - press special html elements (e.g. button)
    - trigger javascript handlers
        - handler per element (e.g. angular)
        - handler per body, taking into account clicked descendant (e.g. jquery)
        - time handlers (setTimeout, setInterval)
    - filling forms

        `The hidden-web behind forms [Raghavan and Garcia-Molina 2001; de Carvalho and Silva 2004; Lage et al. 2004; Ntoulas et al. 2005; Barbosa and Freire 2007; Dasgupta et al. 2007; Madhavan et al. 2008].`

- Detecting patterns
    - web-site patterns (e.g. liquid marking)
    - similar web-pages (e.g. magazine articles)

    <br>

    - do not lose unique actions

- Detecting accidental logout
    - Logout after clickable
    - Logout by time period

- Detecting unsuccessfull actions (e.g. 500, 4xx, ...)

## Crawler problems

- action on one web-page can result in changes on other web-page (even for other user)
- action on one web-page can change its semantics without noticable changes (e.g. button "yes" -> button "no")
- action on web-page can change layout a lot, but not make any HTTP requests
- existance of cross-dependencies between two or more different web-site functionality layouts
- the same clickable can change web-site in various manner each time it is clicked

- web-site can store its state not only on the server-side, but on client side too (e.g. internal storage)

## Web-site assumptions

- web-application must not change its logic during crawling
- role-based access model
- web-application works with REST api through HTTP, no web-sockets <br>    
    only POST requests changes web-application state
- clickables influence web-appliction layout immiditely
- strong connectivity of web-application state graph
- determinism of web-application actions

## Web-crawler

### Crawler sub-features

- choose clickables from last changed elements in web-site layout (allows to get shortest traces of correllated actions)

### Crawler ideas

- the idea of using "filters" can be used before extracting web-page patterns (e.g. replace different time representions, etc.) [2]

- web-crawler can be decentralized, because a lot of crawling concerns finding out current web-application state without actually trigering actions

- some web-application actions does not depend on current state, therefore can be crawled separately (e.g. menu buttons and settings options)

- using some predictor based on success of previous predictions. Pridictor goal is to maximize finding new web-application states

#### Bad ideas

- make operator crawl web-application by hand, and afterward crawl web-site automatically, but make limited amount of actions

    *Bad idea, because even after one action, not made by human, web-application can get into new state and there will be no known trace to return to previous states*

- expect actions in web-application organize as hypercube, meaning that actions order does not matter (*in practice this assumption is too severe*)

    For hypercube of arbitrary dimension there is algorithms for making optimal traces for covering all nodes and edges

- web-application can be divided into pieces and analyzed separately

    *This is very web-application specific, and anyway remains parts of web-applications that looks just like web-application and still can be very complex*

### Crawler metrics

* `number of unique discovered states and discovered state switches` ***per*** `overall number of states looked through`

### Crawler time costs

- networking
- web-page loads and reloads

## Crawler related algorithms

- detecting similar web-pages
    
    The algorithm is extremely simple, it just removes the values from url parameters and it sorts them alphabetically; for example http://www.test.local/a/?c=1&a=2&b=3 becomes http://www.test.local/a/?a=&b=&c= . A good idea would be the use of the SimHash algorithm but lots of tests are needed.

- detecting web-templates

    ??? - Use algorithm for comparing hierarchical data. Algorithm that is based on finding minimal edit sequence can be modified to find maximum similar sub-trees that can be treated as templates. - ***I did not managed to adapt this idea for my crawler needs.***



- Levenshtein distance
- Dijkstra's algorithm - for searching in web-model paths

## Just theory

Web-application actions can be classified as:

* self-loop transitions - does not change web-application state
* state-independent transitions - move web-application into specific state irrespective to previous state
* state-dependent transitions - next web-application state depends on previous state
* nondeterministic transitions - move web-application into always *new* state

Anyway there is no possibility to crawl web-application not based on patterns, which enables user to create new unstructured content.

## Existing crawlers

| web-crawler | comments |
| :---: | :--- |
| CrawlJax | Web-crawler targeted on crawling AJAX web-applications (clickables must be listed), trying to generate state-flow graph of whole web-application. Not really applicable for dynamic sites (when content can be autogenerated), mainly static sites with asynchronous javascript. |

http://www.htcap.org/ - ajax веб-краулер, запоминающий все операции в sqlite.

# Resources

**Web-crawlers**:

*Crawljax*:

1. [1] *Mesbah A., Bozdag E., Van Deursen A. Crawling Ajax by inferring user interface state changes //Web Engineering, 2008. ICWE'08. Eighth International Conference on. – IEEE, 2008. – С. 122-134.*

1. [2] *Mesbah A., Van Deursen A., Lenselink S. Crawling Ajax-based web applications through dynamic analysis of user interface state changes //ACM Transactions on the Web (TWEB). – 2012. – Т. 6. – №. 1. – С. 3.*

# Not usefull resources

1. *Chawathe S. S. et al. Change detection in hierarchically structured information //ACM SIGMOD Record. – ACM, 1996. – Т. 25. – №. 2. – С. 493-504.*

    ***Note***: In this paper method are targeted on detecting insert, delete and especially *move* operations in hierarchicaly structured data. That is not what is really needed for web-crawler, because liquid-like templates will not move relative position of sub-templates between sessions.

    ***Goal***: Find minimal sequence of changes (insert, delete, move, align) to transform tree T1 to tree T2.
    
    ***Algorithm***: It is supposed that trees are partly similar and initial matching can be easily created, afterward tree differences will be removed one-by-one in breadth-first node passing.


_. *Zhang K., Shasha D. Simple fast algorithms for the editing distance between trees and related problems //SIAM journal on computing. – 1989. – Т. 18. – №. 6. – С. 1245-1262.*

**Comparing hierarchical information**:

1. ***Basic idea***: Generate edit graph for two sequences needed to be compared. Shortest path from top-left corner to bottom-right, will reflect minimul edit sequence (insert, delete, update) between given sequences. This algorithm can be easily adapted for comparing trees: rooted, ordered and labeled trees.

    * Article with description of algorithm for basic idea:

        *Chawathe S. S. et al. Comparing hierarchical data in external memory //VLDB. – 1999. – Т. 99. – С. 90-101.*
    
    * Articles with some improvements of algorithm for basic idea:

        1. *K. Vieira, A. Silva, N. Pinto, E. Moura, J. Cavalcanti, and J. Freire. A fast and robust method for web page template detection and removal. In Proc. 15th CIKM, pages 256–267, 2006.*

            ***Note***: Inter alia in this article authors propose to find templates on a small set of web-pages and only after this operation find templates in all other resources. This operation can be repeated several times for different templates and different subset of initial web-pages.

        1. *Myers E. W. An O(ND) difference algorithm and its variations //Algorithmica. – 1986. – Т. 1. – №. 1-4. – С. 251-266.*

            ***Note***: Shortest path mentioned in basic idea can be found using Dijkstra's algorithm with regard to graph structure to be more optimal. In this article it is shown in details.

    <br>
    ***Idea application***: Based on stated idea there is a lot of algorithms finding templates in web and xml. Using algorithm of finding minimal edit sequences for trees or in other words *TED - Tree Edit Distance*, they try to find approximate template (training phase before detection) and finaly classify and extract templates from other web-pages.

    <br>
    Some **template detection** articles based on **data mining**:

    1. *Chakrabarti D., Kumar R., Punera K. Page-level template detection via isotonic smoothing //Proceedings of the 16th international conference on World Wide Web. – ACM, 2007. – С. 61-70.*

        ***Note***: This article has good "Related work" paragraph describing next 6 articles

        ***Note***: Template detection are based on data mining and algorithm training is based on web-pages from the overall web.

    1. *S. Debnath, P. Mitra, N. Pal, and C. L. Giles. Automatic identification of informative sections of web pages. TKDE, 17(9):1233–1246, 2005.*
    1. *H.-Y. Kao, J.-M. Ho, and M.-S. Chen. WISDOM: Web intrapage informative structure mining based on document object model. TKDE, 17(5):614–627, 2005.*
    1. *R. Song, H. Liu, J.-R. Wen, and W.-Y. Ma. Learning block importance models for web pages. In Proc. 13th WWW, pages 203–211, 2004.*
    1. *L. Yi and B. Liu. Web page cleaning for web mining through feature weighting. In Proc. 18th IJCAI, pages 43–50, 2003.*
    1. *L. Yi, B. Liu, and X. Li. Eliminating noisy information in web pages for data mining. In Proc. 9th KDD, pages 296–305, 2003.*
    1. *Z. Bar-Yossef and S. Rajagopalan. Template detection via data mining and its applications. In Proc. 11th WWW, pages 580–591, 2002.*


*J. Tidwell, Designing interfaces.* - book about various web-patterns, used by web-designers.

</article>
