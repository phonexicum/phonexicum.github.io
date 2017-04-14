// Dynamic padding depending on size of fixed header
$(document).ready(function() {
    var headerOffset = document.getElementById("header").offsetHeight;
    $('.page-content').css({
        'padding:':headerOffset+"px"
    });
});

// Process spoilers
$(document).ready(function() {
    $('.spoiler-title').click(function(){
        var spoiler = $(this).closest(".spoiler");
        if (spoiler.hasClass("spoiler-open")) {
            $("iframe", spoiler).attr("src", function(index, old_value) {
                return old_value;
            });
        }
        $("> .spoiler-text", spoiler).slideToggle();
        spoiler.toggleClass("spoiler-open");
    });
    // HTML sample:
    // <div class="spoiler">
    // <div class="spoiler-title">TITLE</div>
    // <div class="spoiler-text" markdown="1">
    // TEXT
    // </div></div>

    // Scroll to an anchor link on a page with an offset to adjust for a fixed header
    $("a[id^='markdown-toc'][href^='#']").on('click', function(e) {
        // prevent default anchor click behavior
        e.preventDefault();

        var offsetSize = $("#header").innerHeight();
        $("html, body").animate({scrollTop:$(this.hash).offset().top-offsetSize -20 }, 0);
        //  $('html, body').animate({scrollTop: $(this.hash).offset().top - 60}, 300, function(){});
    });
});

// Scroll to an anchor link on a DIFFERENT page with an offset to adjust for a fixed header
$(document).ready(function() {
    if (window.location.hash !== ""){
        var offsetSize = $("#header").innerHeight();
        $("html, body").animate({scrollTop:$(window.location.hash).offset().top-offsetSize -20 }, 0);
    }
});
