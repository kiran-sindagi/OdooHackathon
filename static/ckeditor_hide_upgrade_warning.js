// Hide CKEditor insecure version warning bar
(function() {
  var style = document.createElement('style');
  style.innerHTML = '.cke_notification_warning { display: none !important; }';
  document.head.appendChild(style);
})();
