// Spoiler processing

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
});
