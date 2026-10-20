// Runs before first paint to avoid a flash of the wrong theme. Follows the OS only until the person chooses.
(function () {
  var t = null;
  try { t = localStorage.getItem('ctk-theme'); } catch (e) {}
  if (t !== 'dark' && t !== 'light') t = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
})();
