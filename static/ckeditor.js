// CKEditor 4.25.1 CDN loader
(function(){
  var script = document.createElement('script');
  script.src = 'https://cdn.ckeditor.com/4.25.1/standard/ckeditor.js';
  script.onload = function() {
    // Optionally, you can initialize CKEditor here if not auto-initialized by Flask-CKEditor
  };
  document.head.appendChild(script);
})();
