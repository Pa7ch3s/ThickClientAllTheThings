/* Exploit Nation :: sparks + energy pulses firing off the hero mark to
   fill the stage around it. Lives inside page content (unlike matrix.js's
   <body>-level canvas), so navigation.instant's client-side swaps
   replace/discard it on every page change. document$ is Material's
   "re-run after each content swap" hook — subscribe instead of a
   one-shot DOMContentLoaded so the effect comes back every time the
   homepage becomes active again, and stops cleanly (no leaked rAF loop)
   when it doesn't. */
(function () {
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function init() {
    var stage = document.querySelector('.en-hero-stage');
    var canvas = document.getElementById('en-hero-fx');
    if (!stage || !canvas || reduceMotion) return;

    var ctx = canvas.getContext('2d');
    var w, h, cx, cy, edgeR, particles = [], rings = [], frame = 0;

    function resize() {
      var rect = stage.getBoundingClientRect();
      w = canvas.width = rect.width;
      h = canvas.height = rect.height;
      cx = w / 2; cy = h / 2;
      edgeR = Math.min(w, h) / 2 - 6; // how far sparks can travel before the stage runs out
    }
    resize();
    window.addEventListener('resize', resize);

    function spawnSpark(bolt) {
      var angle = Math.random() * Math.PI * 2;
      var startR = edgeR * (0.36 + Math.random() * 0.1); // leave the mark's own silhouette clear
      var travel = edgeR - startR;
      var life = bolt ? 22 + Math.random() * 10 : 35 + Math.random() * 30;
      particles.push({
        angle: angle,
        r: startR,
        speed: travel / life * (bolt ? 1.15 : 0.9 + Math.random() * 0.5),
        life: 0,
        maxLife: life,
        size: bolt ? 2.3 : 1.6 + Math.random() * 2,
        bolt: bolt,
        px: cx + Math.cos(angle) * startR, // previous point, for bolt trails
        py: cy + Math.sin(angle) * startR,
      });
    }

    function spawnRing() {
      rings.push({ r: edgeR * 0.4, life: 0, maxLife: 70 });
    }

    function draw() {
      if (!document.body.contains(canvas)) return; // page navigated away; let this loop die
      ctx.clearRect(0, 0, w, h);
      frame++;
      if (frame % 3 === 0 && particles.length < 110) spawnSpark(false);
      if (frame % 28 === 0) spawnSpark(true);
      if (frame % 130 === 0) spawnRing();

      for (var i = rings.length - 1; i >= 0; i--) {
        var rg = rings[i];
        rg.life++;
        var rt = rg.life / rg.maxLife;
        if (rt >= 1) { rings.splice(i, 1); continue; }
        ctx.beginPath();
        ctx.arc(cx, cy, rg.r + rt * (edgeR - rg.r), 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(57,255,94,' + ((1 - rt) * 0.28) + ')';
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }

      for (var j = particles.length - 1; j >= 0; j--) {
        var p = particles[j];
        p.life++;
        var t = p.life / p.maxLife;
        if (t >= 1) { particles.splice(j, 1); continue; }
        p.r += p.speed;
        var x = cx + Math.cos(p.angle) * p.r;
        var y = cy + Math.sin(p.angle) * p.r;
        var alpha = t < 0.12 ? t / 0.12 : 1 - (t - 0.12) / 0.88;

        if (p.bolt) {
          ctx.beginPath();
          ctx.moveTo(p.px, p.py);
          ctx.lineTo(x, y);
          ctx.strokeStyle = 'rgba(200,255,214,' + (alpha * 0.95) + ')';
          ctx.lineWidth = p.size;
          ctx.shadowColor = 'rgba(120,255,160,.9)';
          ctx.shadowBlur = 8;
          ctx.stroke();
        } else {
          ctx.beginPath();
          ctx.arc(x, y, p.size, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(57,255,94,' + (alpha * 0.9) + ')';
          ctx.shadowColor = 'rgba(57,255,94,.95)';
          ctx.shadowBlur = 6;
          ctx.fill();
        }
        p.px = x; p.py = y;
      }
      requestAnimationFrame(draw);
    }
    requestAnimationFrame(draw);
  }

  if (window.document$) {
    document$.subscribe(init);
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }
})();
