---
layout: post
title: "'Secret Notes 1-2' writeup (google ctf)"
date: 2017-06-25 09:00:00 -0700
categories: ctf writeup
published: true
author: phonexicum
---

<article class="markdown-body" markdown="1">

Secret Notes tasks were sort of sequentially solvable, decisions came step by step. But sometimes I go past the plan.

Here I will explain how challenge could have been solved step by step, and were I made some shortcuts (or longcuts, depends of point of view).

<br>
Table of Contents:

* TOC
{:toc}

---

# Secret Notes

## Problem spec

* We got service on [https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/](https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/), where user can register
* We got source of some android application [NotesApp.apk]({{ "/resources/posts/NotesApp.apk" | prepend: site.baseurl }})
* We got hint: **"Hint: pyc"**

## Examine android application

After apk decompilation (I prefer [dex2jar](https://sourceforge.net/projects/dex2jar/) and [jd-gui](https://github.com/java-decompiler/jd-gui/releases)), under *`com/google/notesapp`* we can found classes responsible for main application functional.
    
After easy look in `MainActivity` and `DatabaseManager` classes without going into details can be seen:

* Application stores its data into android's sqlite database `/data/data/com.google.notesapp/databases/notes.db`

    <br>
    <div markdown="1">
``` java
public class NotesDBHelper extends SQLiteOpenHelper
{
    public static final String DATABASE_NAME = "notes.db";
    ...
```
    </div>

* Application requests not only server's *`/register`* uri, but also server's *`/private`* uri for uploading and downloading its database (base64 encoded)

    <br>
    Access to *`/private`* uri is done with HTTP method *GET* or *POST* (first parameter of `StringRequest` constructor) under class methods `downloadDb` and `uploadDb` accordingly

    <div markdown="1">
``` java
    ...
    localRequestQueue.add(new StringRequest(1, str + "/private", new Response.Listener()new Response.ErrorListener
    {
      public void onResponse(String paramAnonymousString)
      {
        Toast.makeText(MainActivity.this, "DB uploaded!!!", 0).show();
      }
    }
    ...
```
    </div>

    <div markdown="1">
``` java
    ...
    localRequestQueue.add(new StringRequest(0, str + "/private", new Response.Listener()new Response.ErrorListener
    {
      public void onResponse(String paramAnonymousString)
      {
        try
        {
          FileOutputStream localFileOutputStream = new FileOutputStream(new File("/data/data/com.google.notesapp/databases/notes.db"));
          localFileOutputStream.write(Base64.decode(paramAnonymousString.getBytes(), 0));
          localFileOutputStream.flush();
          localFileOutputStream.close();
          jdField_this.populateList();
          Toast.makeText(MainActivity.this, "DB downloaded!!!", 0).show();
          return;
        }
    ...
```
    </div>


<br>
After this observations and running application on virtual android device (application's platformBuildVersionCode="24") here is ***general picture***:

* Client can register with some username single time (because we have only register form, but no login form), gets his cookie (authentication credentials), and writes some notes in android's application with capability to upload and download database with stored notes.

    <br>
    ***Assumption***:

    Attacker has to **guess credentials** for some specified user and download his database. It is expected that database contains some sensitive data (flag).


<br>

## Proprietory cryptography is evil

After looking into *`/register`* user's HTTP request and response (unnecessary headers have been ommited) there is some features to be spotted.
<br> Lets look closer into HTTP request and response (unnecessary headers have been ommited) for registering user with login `hhhhhhh`

* HTTP request:

    <div markdown="1">
```
    POST /register HTTP/1.1
    Host: notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com
    Content-Type: application/x-www-formurlencoded
    Referer: https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/
    Content-Length: 23
    Connection: keep-alive

    username=68686868686868
```
    </div>

* HTTP response:

    <div markdown="1">
```
    HTTP/1.1 200 OK
    Content-Type: text/html; charset=utf-8
    X-Served-By: index.py
    Content-Type: text/plain
    Set-Cookie: auth=68686868686868-9e656cf1cd9e669
    Content-Length: 30

    68686868686868-9e656cf1cd9e669
```
    </div>

<br>
There is some features to be spotted:

* response contains header `X-Served-By: index.py`, probably this is what task's ***hint*** was about. After requesting file [https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/index.pyc](https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/index.pyc) we can get compiled python source file, which can be successfully decompiled (e.g. I used [uncompyle2](https://github.com/wibiti/uncompyle2)) (here is uncompyled [source file]({{ "/resources/posts/NotesApp-index.py" | prepend: site.baseurl }}))

    * At once you can notice some special user registered at server start: `locked_id = '436f7267316c3076657239393c332121'`. Okey lets remember it for the future.

    * Closer look at source file can reveal, that web-server use some `ZXHash` from another python module `hasher` for generating cookies. We can download that file too! Just in the same manner as we downloaded `index.py`.
    
        ([https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/hasher.pyc](https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/hasher.pyc)) (here it is uncompyled [source file]({{ "/resources/posts/NotesApp-hasher.py" | prepend: site.baseurl }}))

    * After familiarizing yourself with the source code of hasher you can notice such reliable word as `md5` and such terrifying signs as `pow` and binary operations, but for those who notice the last line of code it is clear that everything was ruined:

        <div markdown="1">
``` python
    e = # number calculated above
    return hex((b1 ^ b2 ^ e) % m)[2:-1]
```
        </div>

        Explanations:

        * user's username is divided into 4 sequential parts (treated as hex numbers): `b4`, `b3`, `b2`, `b1`. <br> Each part is 64 bits long (8 bytes) (username can not be longer than 32 characters, or web-server will return error). Padding is 0x00 bytes (to fill short usernames to 32 characters).
        * first two parts from username are used for generating hash with the help of `md5` and raising number to the power 
        * however second pair are just ***xored byte by byte*** with the hash from previous step (hash is stored in `e` variable).
        
            This allows to generate some collisions: e.g. `xxxxxxxxxxxxxxxx` and `xxxxxxxxxxxxxxxx00` (first 16 bytes are random but equal) will result in the same hash.

            <br>
            But because there is a lot of attackers, login `xxxxxxxxxxxxxxxx00` can be already registered and web-server will response with `403 Forbidden` `User already Exists`.

            Well, we can register username `xxxxxx0000000000``0000yy`, and get cookie for it. And because we know the value `yy`, we can xor back those bytes in resulted hash and get hash for `xxxxxx0000000000` which is identical to hash for `xxxxxx`.
    
    So we can ***generate valid cookie*** for ***any*** registered ***user***.

<br>

* Well I just explained how it must have been done, but author got and idea of cracking strange-looking cookie as soon as he seen it, not noticing header `X-Served-By: index.py`.

    * After several minutes author noticed identical results for `xxxxxx` and `xxxxxx00` and `xxxxxx0000` and ... ... , that looked suspicious, but changing any numeral `x` resulted in considerable hash change.

    * After several more minutes author started to genuinely hate server's message `User already Exists` and started to use really long username => author found a limit of 32 bytes.

    * Okey lets work with 31-byte usernames, and finally author found:
    
        <div markdown="1">
```
    111111111111111111111111111111111111111111111111111111111111110-6ff79772df252b2
    111111111111111111111111111111111111111111111111111111111111111-6ff79772df252a2
    111111111111111111111111111111111111111111111111111111111111112-6ff79772df25292
    111111111111111111111111111111111111111111111111111111111111113-6ff79772df25282
    111111111111111111111111111111111111111111111111111111111111114-6ff79772df252f2
    111111111111111111111111111111111111111111111111111111111111115-6ff79772df252e2
    111111111111111111111111111111111111111111111111111111111111116-6ff79772df252d2
    111111111111111111111111111111111111111111111111111111111111117-6ff79772df252c2
    111111111111111111111111111111111111111111111111111111111111118-6ff79772df25232
    111111111111111111111111111111111111111111111111111111111111119-6ff79772df25222
    11111111111111111111111111111111111111111111111111111111111111a-6ff79772df25212
    11111111111111111111111111111111111111111111111111111111111111b-6ff79772df25202
    11111111111111111111111111111111111111111111111111111111111111c-6ff79772df25272
    11111111111111111111111111111111111111111111111111111111111111d-6ff79772df25262
    11111111111111111111111111111111111111111111111111111111111111e-6ff79772df25252
    11111111111111111111111111111111111111111111111111111111111111f-6ff79772df25242
```
        </div>
    
        Wow! It looks like a ***xor***. Good error / backdoor to break that server's hash.

    * After several more tries author understand that last half of username are used just for xoring hash gotten from first username's half. It leads us to the ability to ***generate valid cookie*** for ***any*** registered ***user*** just as it was explained above.

        (*I did not even knew about existance of `hasher.pyc`, found it only while writing writeup :)*)

    <br>

    * Now author thinked about getting target username, whos database has to be stolen.
    
        Usernames like `admin`, etc. has no luck.
        
        Finally it was decided, that the targeted username is very strange-looking and hardcoded in the task, therefore it is time to get some sources.

        * *Remember about hint*. The hint says `pyc`, so lets try do download `index.pyc`. => And it finally worked!
            
            Targeted login was indeed strange-looking: `locked_id = '436f7267316c3076657239393c332121'`

<br>
Now it is time to recover the cookie of victim-user:
    
```
auth=436f7267316c3076657239393c332121000002-32e77028f277ba31
=>
auth=436f7267316c3076657239393c332121-32e77228f277ba31
```

## Database

After previous adventures we can finally craft HTTP request to *`/private`* with cookie `auth=436f7267316c3076657239393c332121-32e77228f277ba31` and get secret [database]({{ "/resources/posts/NotesApp-sqlite-with-flag.db" | prepend: site.baseurl }})

Database contains table `FLAG` with content ***`ctf{with_crypt0_d0nt_ro11_with_it}`***.

<br>

---

# Secret Notes 2

## Problem spec

* Google say: `There is a DIFFerent flag, can you find it?`.

=> Okey lets dig deeper into `Diff`, `DiffSet`, `Notes`, `NoteSet` tables of our database.

<br>

## Db analysis

### `Notes` and `NoteSet` db tables

Here is table's contence:

```
sqlite> .dump Notes
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE Notes (Name STRING(255) PRIMARY KEY, Deleted BOOLEAN);
    INSERT INTO "Notes" VALUES('Groceries',0);
    INSERT INTO "Notes" VALUES('Plans to Hack the World',1);
    INSERT INTO "Notes" VALUES('Some Problems After our Last Stop',0);
    INSERT INTO "Notes" VALUES('Trouble Up Ahead',1);
    COMMIT;
sqlite> .dump NoteSet
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE NoteSet (ID INTEGER PRIMARY KEY, NAME STRING, SHOWN BOOLEAN, Diffs INT);
    INSERT INTO "NoteSet" VALUES(1,'Trouble with the Machine',1,23);
    INSERT INTO "NoteSet" VALUES(2,'About that Job',0,17);
    INSERT INTO "NoteSet" VALUES(3,'flag.txt',0,36);
    COMMIT;
```

#### Upload crafted db

* We can change all values of `SHOWN` column in `NoteSet` to `1` (*true*). And upload base64-encoded new database with *POST* method to *`/private`* uri (under ***different*** user, because we do not want to ruin ctf task by accident).

* Now ask android device to download database from cloud (which we have just uploaded by hand after registering new user) and look through available notes.

* Unfortunately the note with `flag.txt` header has next content: `Your flag is no longer here. `.

pittyfull :(


<br>

### `Diff` and `DiffSet` db tables

`Diff` certainly contains something interesting:

```
sqlite> .dump Diff
    ...
    INSERT INTO "Diff" VALUES(251,1,12,'nd ',67);
    INSERT INTO "Diff" VALUES(252,0,0,'ctf{puZZ1e_',67);
    INSERT INTO "Diff" VALUES(253,1,40,'nds the uZZ1e_As_old_as_The finale',68);
    ...
```

*Real flag can be read from this three lines!, but only luckiest guys could have managed to guess it ... ... and I was not lucky :(*


<br>

Lets look at the table's header:

```
sqlite> .dump Diff
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE Diff (ID INTEGER PRIMARY KEY, Insertion BOOLEAN, IDX INTEGER, Diff STRING(255), DiffSet ID);
    INSERT INTO "Diff" VALUES(1,1,0,'I need',2);
    ...
```

```
sqlite> .dump DiffSet
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE DiffSet (ID INTEGER PRIMARY KEY, Note STRING(255));
    INSERT INTO "DiffSet" VALUES(1,'Groceries');
    ...
    INSERT INTO "DiffSet" VALUES(37,'flag.txt');
    INSERT INTO "DiffSet" VALUES(38,'flag.txt');
    ...
```

Now it is time to guess the meaning:

* `ID` from `Diff` - is used for numeration and also used in `DiffSet` table to point out that this `Diff` row must be used to construct text for note with the name pointed in the `Note` column of `DiffSet` table.

Assumption: by executing secret meaning of instructions in `Diff` table we can construct final **text** of each note.

* `Insertion` from `Diff` - identifies if the text from column `Diff` must be inserted after `IDX` index in *temporal* **text** *variable* or if the text must be found in **text** after index `IDX` and be deleted.

    Small code snippet in python executed instructions from database (read and parsed previously from plaintext output) and printed resulted **text** after each step:

<div class="spoiler"><div class="spoiler-title">
    <i>Read me (there is some story from task's author here)</i>
</div><div class="spoiler-text" markdown="1">

```
98 cat flag 
99 cat flag one flag two flag 
100 cat flag one flag two flag red flag blue flag 
101 cat flag one flag two flag red flag blue flag blue flag 
102 cat flag one flag two flag red flag flag blue flag 
103 cat flag one flag two flag red flags red flag blue flag 
104 cat flag one flag two flag red flare songs red flag blue flag 
105 cat flag one flag two flag red are songs red flag blue flag 
106 cat flag one flag two flag re are songs red flag blue flag 
107 cat flag one flag two flag in the games of madness there are songs red flag blue flag 
108 cat flag one flag two flag in the games of madness there are songs, songs of fighters,  red flag blue flag 
109 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors,  red flag blue flag 
110 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of swords.  red flag blue flag 
111 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of swords. But the only song we care about is that of the red flag blue flag 
112 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of swords. But the only song we care about is that of the one blue flagred flag blue flag 
113 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of swords. But the only song we care about is that of the one blue flag 
114 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of swords. But the only song we care about is that of the one true flagblue flag 
115 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of swords. But the only song we care about is that of the one true flag 
116 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is that of the one true flag 
117 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is that of the one true flare about is that of the one true flag 
118 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is that of the one true fly song we care about is that of the one true flag 
119 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is that of the only song we care about is that of the one true flag 
120 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is that only song we care about is that of the one true flag 
121 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is that But the only song we care about is that of the one true flag 
122 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is that. But the only song we care about is that of the one true flag 
123 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is thall men fight. But the only song we care about is that of the one true flag 
124 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about is all men fight. But the only song we care about is that of the one true flag 
125 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about isides, all men fight. But the only song we care about is that of the one true flag 
126 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care about sides, all men fight. But the only song we care about is that of the one true flag 
127 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song we care aboutheir sides, all men fight. But the only song we care about is that of the one true flag 
128 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only song their sides, all men fight. But the only song we care about is that of the one true flag 
129 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only so their sides, all men fight. But the only song we care about is that of the one true flag 
130 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. But the only strapped to their sides, all men fight. But the only song we care about is that of the one true flag 
131 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. swords. strapped to their sides, all men fight. But the only song we care about is that of the one true flag 
132 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. s strapped to their sides, all men fight. But the only song we care about is that of the one true flag 
133 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. Swords strapped to their sides, all men fight. But the only song we care about is that of the one true flag 
134 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight. But the only song we care about is that of the one true flagmen fight. But the only song we care about is that of the one true flag 
135 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight. But the only song we care about is that of the one true flag 
136 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight. for the glory of the final flag. But the only song we care about is that of the one true flag 
137 cat flag one flag two flag in the games of madness there are songs, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
138 cat flag one flag two flag in the games of madness there are son. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
139 cat flag one flag two flag in the games of madness there are sof men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
140 cat flag one flag two flag in the games of madness there are s, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
141 cat flag one flag two flag in the games of madness there ars, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
142 cat flag one flag two flag in the games of madness there aviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
143 cat flag one flag two flag in the games of madnessaviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
144 cat flag one flag two flag in the games of madnes, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
145 cat flag one flag two flag in the games of madners, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
146 cat flag one flag two flag in the games of madngs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
147 cat flag one flag two flag in the games ongs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
148 cat flag one flag two flag in the games songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
149 cat flag one flag two flag in the games, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
150 cat flag one flag two flag in the gs, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
151 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag 
152 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag} 
153 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that of the one true flag} 
154 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about is that oflag} 
155 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care about flag} 
156 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the only song we care aboutrue flag} 
157 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the true flag} 
158 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. But the one true flag} 
159 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. Buthe one true flag} 
160 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final flag. the one true flag} 
161 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final f the one true flag} 
162 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final PIZZA. But the only song we care about is that of the one true flag} 
163 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final PIZZA. A prize so great only 1 may achieve it. But the only song we care about is that of the one true flag} 
164 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people fight for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
165 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. Swords strapped to their sides, all people for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
166 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {of saviors, of men. for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
167 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {saviors, of men. for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
168 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
169 cat flag one flag two flag in the calls to madness there are songs, songs of fighters, glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
170 cat flag one flag two flag in the calls to madness there are songs, songs of fighte glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
171 cat flag one flag two flag in the calls to madness there are songs, songs of fighthe glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
172 cat flag one flag two flag in the calls to madness there are songs, songs of the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
173 cat flag one flag two flag in the calls to madness there are songs, songs ofor the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
174 cat flag one flag two flag in the calls to madness there for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
175 cat flag one flag two flag in the calls to madness th for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
176 cat flag one flag two flag in the ch for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
177 cat flag one flag two flag in the {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
178 cat flag one flag two flag in thers, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
179 cat flag one flag two flag in ters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
180 cat flag one flag two flag in fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
181 cat flag one flag two f fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
182 cat flag one flag twof fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
183 cat flag one flag of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
184 cat flag one flags of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
185 cat flag ongs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
186 cat flag songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
187 cat flags, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
188 cat flare songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
189 cat are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
190 cathere are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
191 there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. But the only song we care about is that of the one true flag} 
192 there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. I&m sure one true flag}But the only song we care about is that of the one true flag} 
193 there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight for it. I&m sure one true flag} 
194 there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
195 there are are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
196 there all to madness there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
197 there call to madness there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
198 the call to madness there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
199 In the call to madness there are songs, songs of fighters, {saviors, of men. People love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
200 In the call to madness there are songs, songs of fighters, {ple love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
201 call to madness there are songs, songs of fighters, {ple love much for the glory of the final PIZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
202 call to madness there are songs, songs of fighters, {ple love muZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
203 call to madness there are songs, songs of fighters, {puZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
204 call to madness there are songs, songs of fighters, {puZZA. A prize so great only 1 may achieve it. Even _Aslan_ would fig} 
205 call to madness there are songs, songs of fighters, {puZZA. A prize so great only 1 mag} 
206 call to madness there are songs, songs of fighters, {puZZA. A prize so great onlag} 
207 call to madness there are songs, songs of fighters, {puZZA. A prize so great one true flag} 
208 call to madness there are songs, songs of fighters, {puZZA. A prize so great it. I&m sure one true flag} 
209 call to madness there are songs, songs of fighters, {puZZA. A prize so gr it. I&m sure one true flag} 
210 call to madness there are songs, songs of fighters, {puZZA. A prize so ght _massively_ for it. I&m sure one true flag} 
211 call to madness there are songs, songs of fighters, {puZZA. A prize so fight _massively_ for it. I&m sure one true flag} 
212 call to madness there are songs, songs of fighters, {puZZA. A prize sould fight _massively_ for it. I&m sure one true flag} 
213 call to madness there are songs, songs of fighters, {puZZA. A prize slan_ would fight _massively_ for it. I&m sure one true flag} 
214 call to madness there are songs, songs of fighters, {puZZAslan_ would fight _massively_ for it. I&m sure one true flag} 
215 call to madness there are songs, songs of fighters, {puZZ1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
216 call to madngs, songs of fighters, {puZZ1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
217 call tongs, songs of fighters, {puZZ1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
218 call there are songs, songs of fighters, {puZZ1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
219 cthere are songs, songs of fighters, {puZZ1 may achieve it. Even _Aslan_ would fight _massively_ for it. I&m sure one true flag} 
220 cthere are songs, songs of fighters, {puZZ1 may achieve it. Even _Aslan_ would fig} 
221 cthere are songs, songs of fighters, {puZZ1 may ag} 
222 cthere are songs, songs of fighters, {puZZ1 may for it. I&m sure one true flag} 
223 cthere are songs, songs of fighters, {puZZ1 may_ for it. I&m sure one true flag} 
224 cthere are songs, songs of fighters, {puZZ1 massively_ for it. I&m sure one true flag} 
225 cthere are songs, songs of fighters, {puZZ1 would fight _massively_ for it. I&m sure one true flag} 
226 cthere are songs, songs of fighters, {puZZ1e_Aslan_ would fight _massively_ for it. I&m sure one true flag} 
227 cthere are songs, songs of fighters, {puZZ1e_Asld fight _massively_ for it. I&m sure one true flag} 
228 cthere are songs, songs of fighters, {puld fight _massively_ for it. I&m sure one true flag} 
229 cthere are songs, sould fight _massively_ for it. I&m sure one true flag} 
230 cthere are songs, s_ould fight _massively_ for it. I&m sure one true flag} 
231 cthere are songs, {puZZ1e_As_ould fight _massively_ for it. I&m sure one true flag} 
232 cthere are s, {puZZ1e_As_ould fight _massively_ for it. I&m sure one true flag} 
233 cthers, {puZZ1e_As_ould fight _massively_ for it. I&m sure one true flag} 
234 cthters, {puZZ1e_As_ould fight _massively_ for it. I&m sure one true flag} 
235 ctfighters, {puZZ1e_As_ould fight _massively_ for it. I&m sure one true flag} 
236 ctfighters, {puZZ1e_As_ould_massively_ for it. I&m sure one true flag} 
237 ctfighters, {puZZ1e_As_old_massively_ for it. I&m sure one true flag} 
238 ctfighters, {puZZ1e_As_old_massively_ I&m sure one true flag} 
239 ctfighters, {puZZ1e_As_old_massively_t. I&m sure one true flag} 
240 ctfighters, {puZZ1e_As_old_mas_t. I&m sure one true flag} 
241 ctfighters, {puZZ1e_As_old_as_t. I&m sure one true flag} 
242 ctfighters, {puZZ1e_As_old_as_t. I&m sure} 
243 ctfighters, {puZZ1e_As_old_as_t. I&me} 
244 ctfighters, {puZZ1e_As_old_as_t. Ime} 
245 ctfighters, {puZZ1e_As_old_as_tIme} 
246 ctf{puZZ1e_As_old_as_tIme} 
247 ctf{puZZ1e_As_old_as_The finale.tIme} 
248 ctf{puZZ1e_As_old_as_The finale. 
249 ctf{puZZ1e_As_o thusf{puZZ1e_As_old_as_The finale. 
250 ctf{puZZ1e_Aso thusf{puZZ1e_As_old_as_The finale. 
251 ctf{puZZ1e_And so thusf{puZZ1e_As_old_as_The finale. 
252 And so thusf{puZZ1e_As_old_as_The finale. 
253 And so thusf{puZZ1e_As_old_as_The finalends the uZZ1e_As_old_as_The finale. 
254 And so thusf{puZZ1e_As_old_as_The ends the uZZ1e_As_old_as_The finale. 
255 And so thus ends the uZZ1e_As_old_as_The finale. 
256 And so thus ends the uZZ1e_As_As_old_as_The finale. 
257 And so thus ends the uZZ1e_Astory we have 1old_As_old_as_The finale. 
258 And so thus ends the story we have 1old_As_old_as_The finale. 
259 And so thus ends the story we have told together. as_The finale.1old_As_old_as_The finale. 
260 And so thus ends the story we have told together. as_The finale. 
261 And so thus ends the story we have told together. as_The fis is the finale. 
262 And so thus ends the story we have told together. as_This is the finale. 
263 And so thus ends the story we have told together. This is the finale. 
264 And so thus ends the story we have told together. This is the finale. Your flag is not here.  
265 And so thus ends the story we have told together. This is the finale. Your flag is not longer here.  
266 And so thus ends the story we have told together. This is the finale. Your flag is no longer here.  
267 Your flag is no longer here. 
```

</div>
</div>

<br>
From output can be easily seen that the flag is ***`ctf{puZZ1e_As_old_as_tIme}`*** (line with identifier = 246)


<br>

### The other way

If you didn't wanted to write python scripts, you could have removed rows 67-73 from table `DiffSet` corresponding for last **text** transformations, and after loading database into android application the note `flag.txt` will contain real flag.

Unfortunately, this approach demands to bruteforce the number of rows (xx-73) to be removed from table `DiffSet`.

<br>

## How it should have been

All my story was based on good guessing of table's columns meaning, however scientific approach was next: Read android application's source java code, because `DatabaseManager` class contains appropriate processing of given database and come to the same conclusions about database structure.

#### The other way

Just a theoretical proposal:

* Uncompyle android's apk to smali and insert into `getDiffs` method of class `DatabaseManager` logging of current note's text for after each step of **text** reconstruction.
* Upload database into cloud
* Download database and open note `flag.txt`
* Check android's logcat for the same strings I have published above, one of them will be the flag.



<br>

---

# Hardening the task

At the end I would like to comment that the task could have been hardened by removing access to `hasher.pyc` and obfuscting database column names (to force participants to read android's application source code).

Also hint was redundant for the task, because of HTTP header existance (or HTTP header was redundant, because of hint existance).

Task mainly presents ***wrong authentication management*** vulnerability, which is widespread amoung web-services.

<br>

---

# Thanks google


I liked google's ctf and its tasks, for their realistic nature.
Thanks google a lot :)

</article>
