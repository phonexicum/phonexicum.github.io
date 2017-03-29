---
layout: page

title: Encodings

category: infosec_infolists
see_my_category_in_header: true

permalink: /infolists/encodings.html
---

<article class="markdown-body" markdown="1">

## Content

* TOC
{:toc}


## Definitions

Symbol encoding
: establishes rule how symbols\pictures correlate with arithmetic numbers.
    
    (e.g. unicode)

Character encoding
: establishes rule how numbers (signifying some character) will be encoded in bytes (and written somewhere) and vice versa.

    (e.g. UTF-8, UTF-16, ...)

Exists a lot of abnormal encodings (e.g. cp1251, ...), which are messing up two concepts, enclosing both of them: symbol encoding and character encoding.

<br>

## Different encode types

URL encode
: *(url must be represented by ascii symbols 0 - 126)*

    <br>
    Hello World **-->** Hello%20%57%6f%72%6c%64 *(normal ascii symbols can be represented without encode by choice)* <br>
    ` ` **-->** `+` or %20 <br>
    not ascii symbols: ü **-->** %C3%BC *(utf-8 hex representation)*

<br>

HTML entities
: Any symbol can be encoded in decimal `&#123;` or in hex `&#x123;`
    
    Encoded symbols will be not interpreted by browser as a special symbols.

<div class="spoiler"><div class="spoiler-title">
    <i>examples</i>:
</div><div class="spoiler-text" markdown="1">

| ' ' | non-breaking space   | `&nbsp;`  | `&#160;`  |
| <   | less than            | `&lt;`    | `&#60;`   |
| >   | greater than         | `&gt;`    | `&#62;`   |
| &   | ampersand            | `&amp;`   | `&#38;`   |
| ¢   | cent                 | `&cent;`  | `&#162;`  |
| £   | pound                | `&pound;` | `&#163;`  |
| ¥   | yen                  | `&yen;`   | `&#165;`  |
| €   | euro                 | `&euro;`  | `&#8364;` |
| ©   | copyright            | `&copy;`  | `&#169;`  |
| ®   | registered trademark | `&reg;`   | `&#174;`  |
|     | etc.                 |           |           |

</div>
</div>

<br>

## Encoding tricks

- Encodings latin1, gbk and character escaping

    In latin1 *string*=`%BF%27`=`¿'`

    After escaping symbol `%27`=`'` with `%5C`=`\` *string*=`%BF%5C%27`

    In gbk encoding *string*=`%BF%5C%27`=`縗'`

    <br>

    *If mysql `SET NAMES gbk;` was set, then this encoding trick will help to bypass `mysql_real_escape_string` php function.*

<br>

## Special characters

unicode replacement symbol - "\ufffd"

<table>
<tbody>
<tr>
<td valign="top" markdown="1">

- space immitation *(hex)*

    <br>
    
    | %20  | space               |
    | /**/ | comment             |
    | %09  | tabulation          |
    | %0A  | new line            |
    | %0B  | vertical tabulation |
    | %0C  | new page            |
    | %0D  | carriage return     |
    | %A0  | non-breaking space  |

    <br>
    using utf-8 encoding (encode one-byte symbol using 2 bytes):

    in different systems \xC0 and \xe0 can be not recognized as utf-8 service byte

        \xC0\x49, \xC0\x4A, \xC0\x4B, \xC0\x4C, \xC0\x4D
        \xC0\x89, \xC0\x8A, \xC0\x8B, \xC0\x8C, \xC0\x8D
        \xC0\xC9, \xC0\xCA, \xC0\xCB, \xC0\xCC, \xC0\xCD
        \xC0\xE0, \xC0\x60
        \xE0\x00\x09, \xE0\x40\x09, \xE0\x80\x09

</td>
<td markdown="1">

- ascii special characters *(dec)*

    <br>
    
    |' '| 32  || + | 43  || @ | 64  |
    | ! | 33  || , | 44  || [ | 91  |
    | " | 34  || - | 45  || \ | 92  |
    | # | 35  || . | 46  || ] | 93  |
    | $ | 36  || / | 47  || ^ | 94  |
    | % | 37  || : | 58  || _ | 95  |
    | & | 38  || ; | 59  || ` | 96  |
    | ' | 39  || < | 60  || { | 123 |
    | ( | 40  || = | 61  || \|| 124 |
    | ) | 41  || > | 62  || } | 125 |
    | * | 42  || ? | 63  || ~ | 126 |    

</td>
</tr>
<td colspan="2" markdown="1">

- ascii control characters *(dec)*

    | NUL | 00  | null character      | VT  | 11  | vertical tab         | SYN | 22  | synchronize            |
    | SOH | 01  | start of header     | FF  | 12  | form feed            | ETB | 23  | end transmission block |
    | STX | 02  | start of text       | CR  | 13  | carriage return      | CAN | 24  | cancel                 |
    | ETX | 03  | end of text         | SO  | 14  | shift out            | EM  | 25  | end of medium          |
    | EOT | 04  | end of transmission | SI  | 15  | shift in             | SUB | 26  | substitute             |
    | ENQ | 05  | enquiry             | DLE | 16  | data link escape     | ESC | 27  | escape                 |
    | ACK | 06  | acknowledge         | DC1 | 17  | device control 1     | FS  | 28  | file separator         |
    | BEL | 07  | bell (ring)         | DC2 | 18  | device control 2     | GS  | 29  | group separator        |
    | BS  | 08  | backspace           | DC3 | 19  | device control 3     | RS  | 30  | record separator       |
    | HT  | 09  | horizontal tab      | DC4 | 20  | device control 4     | US  | 31  | unit separator         |
    | LF  | 10  | line feed           | NAK | 21  | negative acknowledge | DEL | 127 | delete (rubout)        |

</td>
</tbody>
</table>

</article>
