// Break out of a parent frame. frame-ancestors is ignored in a meta Content-Security-Policy,
// and this static host does not send X-Frame-Options. The script is external because
// script-src is 'self' and blocks inline scripts. connect-src stays https: so RDAP
// redirects to registry hosts keep working.
// A host in front of u51.org (for example Cloudflare) can still send
// X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'.
(function () {
  if (window.top === window.self) return;
  var root = document.documentElement;
  root.setAttribute('data-framed', '');
  root.hidden = true;
  try {
    window.top.location.replace(window.location.href);
  } catch (e) {
    // Sandboxed frame, or the browser blocked the navigation. The page stays hidden.
  }
})();
