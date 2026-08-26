/* Exploit Nation :: falling matrix code background */
(function () {
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var canvas = document.createElement('canvas');
  canvas.id = 'en-matrix';
  (document.body || document.documentElement).appendChild(canvas);
  var ctx = canvas.getContext('2d');
  var fs = 14, cols = 0, drops = [];
  var glyphs = 'アカサタナハマヤラワ0123456789ABCDEF<>/{}[]#$%*+=;:'.split('');

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / fs) + 1;
    drops = [];
    for (var i = 0; i < cols; i++) drops[i] = Math.random() * -120;
  }
  resize();
  window.addEventListener('resize', resize);

  function draw() {
    ctx.fillStyle = 'rgba(5,8,7,0.10)';        // trail fade
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = fs + 'px "JetBrains Mono", ui-monospace, monospace';
    for (var i = 0; i < cols; i++) {
      var ch = glyphs[Math.floor(Math.random() * glyphs.length)];
      var x = i * fs, y = drops[i] * fs;
      ctx.fillStyle = Math.random() > 0.986 ? '#c8ffd6' : 'rgba(57,255,94,0.55)'; // bright head
      ctx.fillText(ch, x, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i] += Math.random() > 0.5 ? 1 : 0.9;
    }
  }

  var last = 0;
  function loop(ts) {
    if (ts - last > 55) { draw(); last = ts; }   // ~18fps, calm
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
})();
