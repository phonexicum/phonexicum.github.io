---
layout: page

title: osint-personal

category: infosec
see_my_category_in_header: true

permalink: /infosec/osint-personal.html

published: true
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

---

OSINT
: open-source intelligence ([OSINT - wikipedia](https://en.wikipedia.org/wiki/Open-source_intelligence))

Technical OSINT article: *[OSINT]({{ "/infosec/osint.html" | prepend: site.baseurl }})*

[How much google/microsoft/facebook/... spies on us (with links)](https://mobile.twitter.com/iamdylancurran/status/977559925680467968?s=21)

---

# Searching on persons

## wide-purpose search

* [pipl.com](https://pipl.com/) [inteligator.com](http://www.inteligator.com/) [peoplesearchnow.com](https://www.peoplesearchnow.com/) [privateeye.com](https://www.privateeye.com/)
* [marketvisual.com](http://www.marketvisual.com) - search between heads of top-management and company's names
* [www.strategator.com](http://www.strategator.com) (*looks broken*) - aggregation of information about companies

## search through social networks

* [social-searcher.com](https://www.social-searcher.com/) - search last posts in many social networks (facebook, instagram, vimeo, reddit, ...) by a person
* [www.socialmention.com](http://www.socialmention.com/) - search for hashtages related to person, and post mentioning person
* [www.echosec.net](https://www.echosec.net/) - search for a social media post by location

## search through pictures

* [worldc.am](http://worldc.am) - search instagram photos by location
* [yomapic](https://play.google.com/store/apps/details?id=com.yomapic) (android app) - search intagram photos by location

## other technics

* [cluuz.com](http://cluuz.com) - search like google, but generates list of related tags
* facebook/instagram/google+/youtube/icq/ other social networks
    <br> [linked in](https://developer.linkedin.com) can give you a lot of information about 1st and 2nd connections
* google dorks ([ghdb.html]({{ "/infolists/ghdb.html" | prepend: site.baseurl }})), twitter extended search (e.g. `from:@tim_cook since: 2015-12-25 until:2016-01-07`, `near:perm`, `near:56.35,47.03`), [google images search](https://www.google.ru/imghp)

## Russia specific

* [yandex.ru/people](https://yandex.ru/people) - better for searching russian people
* [проверка по списку недействительных российских паспортов](http://services.fms.gov.ru/info-service.htm?sid=2000)
* [ФССП](http://fssprus.ru/iss/ip/) - проверка долгов через региональную службу судебных приставов
* [мвд, региональный розыск](https://xn--d1aumdd.xn--b1aew.xn--p1ai/information/Vnimanie_rozisk/rozisk)
* [база диссертаций](http://www.dissercat.com/s)
* [база дипломов](http://frdocheck.obrnadzor.gov.ru)

# Search by telephone number

* [phonenumber.to](http://phonenumber.to/)
* ***Russia specific***:

    * [www.roum.ru/bases/people.html](http://www.roum.ru/bases/people.html) - autosearch in search-engines by telephone number
    * [nomer.io](https://nomer.io/) - good however paid
    * [gsm-inform.ru](http://gsm-inform.ru/info/) - определение региона по мобильному телефону

<!-- !!!

# Unknown

* [www.quandl.com](http://www.quandl.com) - search through millions of databases (finance, economical, social)
* [visual.ly](http://visual.ly) - infographic searcher + visualisation
* [www.ciradar.com](http://www.ciradar.com/)

-->

# Russia specific:

## Поиск машин:

* [nomerorg.company](http://nomerorg.company/), [nomerorg.one](http://nomerorg.one), [nomerorg.xyz](http://nomerorg.xyz) - база ГИБДД
* @AvinfoBot - telegram bot
* [гибдд проверка автомобиля](https://xn--90adear.xn--p1ai/check/auto/?vin)

# Поиск через VK

* [vkfaces.com](https://vkfaces.com/)
* [findface.ru](https://findface.ru/) - search by photos in vk.com
* [yasiv.com/vk](http://yasiv.com/vk) - search by connections - граф социальных связей - можно добавлять людей, и оттягивать их окружения, в середке будут оставаться узлы, которые связаны со всеми другими и так искать связи\пересечения
* [SnRadar](http://snradar.azurewebsites.net) - search photos in target location via "Vkontakte" (russian social network)

## Поиск по юр. лицам, поиск контрагентов

* [egrul](https://egrul.nalog.ru/) - единый реестр юридических лиц и индивидуальных предпринимателей РФ
* [rusprofile.ru](http://www.rusprofile.ru/)
* [zachestnyibiznes.ru](https://zachestnyibiznes.ru/)
* [kartoteka.ru](https://www.kartoteka.ru/) - актуальная информация о компаниях, учредителях, руководителях и взаимосвязях между ними, включая сведения о залогах движимого имущества
* [rusbport.ru](http://rusbport.ru/)
* [www.spark-interfax.ru](http://www.spark-interfax.ru/)
* [focus.kontur.ru](https://focus.kontur.ru/)

## Финансовый сектор

* [banki.ru](https://www.banki.ru/)
* [rbc.ru](https://www.rbc.ru/)
* [www.ist-budget.ru](http://www.ist-budget.ru/) - сайт гос. закупок и тендеров
* [bitzakaz.ru](http://bitzakaz.ru) - поиск тендеров и гос. заказов
* [multitender.ru](http://multitender.ru/) - данные рынка государственных и коммерческих закупок

# Базы данных украденные из разных мест

* [dc.ru-board.com](http://dc.ru-board.com) - *закрыли*
* [phreaker.pro](https://phreaker.pro/forum/forums/%D0%9E%D0%B1%D1%89%D0%B8%D0%B9-%D1%80%D0%B0%D0%B7%D0%B4%D0%B5%D0%BB.121/)
* [haveibeenpwned.com](https://haveibeenpwned.com/) - check if your account has been leaked
* [dumpedlqezarfife.onion.lu](http://dumpedlqezarfife.onion.lu/)

# Родители, прародители, ...

* [rusperson.com](http://www.rusperson.com) (search only through google dork `site:` in google)

# Поиск через медиа

* [public.ru](http://public.ru) - медиапоиск и анализ
* [agregator.pro](http://agregator.pro) - aggregator of media and news, used by media-analysts for analyse news feeds
*   Other's monitoring systems

    * [kribrum](http://kribrum.ru/) ([kribrum infowatch](https://infowatch.com/products/kribrum#))
    * [avalanche online](https://start.avalancheonline.ru/landing)

    <div class="spoiler"><div class="spoiler-title">
    <i>probably not really usefull for a pentester:</i>
    </div><div class="spoiler-text" markdown="1">

    <!-- !!! what is all this ? !!!  -->

    * [granoproject.org](http://granoproject.org/) - *Grano* is an open source tool for journalists and researchers who want to track networks of political or economic interest. It helps understand the most relevant relationships in your investigations, and to merge data from different sources.
    * [watchthatpage.com](http://watchthatpage.com) - resource collects data automatically from monitored resources (service is free)
    * [falcon.io](http://falcon.io) - smth like Raportive for web (returns data about person from varous social profiles and open web)
    * [price.apishops.com](http://price.apishops.com) - automatic monitoring of price formation for targeted goods group for various magazines
    * [www.recordedfuture.com](https://www.recordedfuture.com/) - data analysis and visualisation
    * [saplo.com](http://saplo.com)
    * [infostream.com.ua](http://infostream.com.ua)

    * Competitive intelligence:

        * [newspapermap.com](http://newspapermap.com) - 
        * [www.connotate.com](http://www.connotate.com/solutions) - competitive intelligence
        * [rivaliq.com](https://www.rivaliq.com) - effective instrument for competitive intelligence (конкурентная разведка) (mainly european and american markets)
        * [advse.ru](https://advse.ru/) - называется: "Узнай всё про своих конкурентов"
        * [www.clearci.com](http://www.clearci.com)
        * [www.recipdonor.com](http://www.recipdonor.com)
        * [www.spyfu.com](http://www.spyfu.com/)
    </div>
    </div>

<br>


</article>
