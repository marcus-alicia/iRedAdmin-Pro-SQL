/*
 * Plugin Name: QuickFilter
 * Author: Collin Henderson (collin@syropia.net)
 * Version: 1.0
 * © 2012, http://syropia.net
 * You are welcome to freely use and modify this script in your personal and commercial products. Please don't sell it or release it as your own work. Thanks!
*/
(function($){
$.extend($.expr[':'], {missing: function (elem, index, match) {
    return (elem.textContent || elem.innerText || "").toLowerCase().indexOf(match[3]) == -1;
}});
$.extend($.expr[':'], {exists: function(elem, i, match, array){
    return (elem.textContent || elem.innerText || '').toLowerCase().indexOf((match[3] || "").toLowerCase()) >= 0;
}});
$.extend($.fn,{
    quickfilter: function(el){
         return this.each(function(){
            var _this = $(this);
            var query = _this.val().toLowerCase();
            _this.keyup(function () {
                query = $(this).val().toLowerCase();
                if(query.replace(/\s/g,"") != ""){
                    $(el+':exists("' + query.toString() + '")').show();
                    $(el+':missing("' + query.toString() + '")').hide();
                }
                else {
                    $(el).show();
                }
            });
        });
    }
});
})(jQuery);