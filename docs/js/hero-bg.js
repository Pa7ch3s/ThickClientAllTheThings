/* Exploit Nation :: the animated EN mark as a site-wide fixed background,
   same mechanism as matrix.js -- appended to <body> once on initial load,
   not embedded in page content. navigation.instant only swaps the content
   area on page-to-page navigation; anything attached directly to <body>
   (this, matrix.js's canvas) survives that swap untouched, so it stays
   visible fixed in place across every page and every scroll position,
   instead of scrolling away with whichever page happened to embed it. */
(function () {
  if (document.getElementById('en-hero-bg')) return; // instant-nav re-runs scripts? guard anyway

  // Resolve the site's own root from this script's own URL rather than a
  // hardcoded path -- extra_javascript files always live at "<root>/js/...",
  // so this works regardless of the repo's subpath (already renamed once:
  // ExploitNation -> exploitnation) or which page depth it's loaded from.
  var self = document.currentScript;
  var base = self ? self.src.replace(/js\/hero-bg\.js.*$/, '') : '';

  var picture = document.createElement('picture');
  picture.id = 'en-hero-bg';
  picture.setAttribute('aria-hidden', 'true');
  picture.innerHTML =
    '<source media="(prefers-reduced-motion: reduce)" srcset="' + base + 'assets/logo.png">' +
    '<source srcset="' + base + 'assets/en-hero.webp" type="image/webp">' +
    '<img src="' + base + 'assets/en-hero.apng" alt="">';
  (document.body || document.documentElement).appendChild(picture);
})();
