"""
Build an animated APNG of the Exploit Nation mark: pulsing glow + sparks/
bolts firing outward + periodic digital-glitch bursts on the mark itself
(RGB channel split + displaced scanline bands), composited so the mark's
own artwork is painted last every frame (using its real alpha as a mask)
-- structurally guaranteeing sparks can never paint over the crisp linework,
instead of relying on radius math or z-index (both of which failed before).
"""
import math
import os
import random
import numpy as np
from PIL import Image, ImageDraw, ImageFilter

random.seed(7)
PREVIEW = os.environ.get("PREVIEW") == "1"

SRC = "logo.png"
SS = 2                  # supersample factor for anti-aliasing
CANVAS = 480 * SS
FRAMES = 20 if PREVIEW else 60   # preview: fewer frames, still spans a full cycle
FPS = 15
DURATION_MS = round(1000 / FPS)

ACID = (57, 255, 94)
ACID_HOT = (200, 255, 214)

mark = Image.open(SRC).convert("RGBA")
mark_scale = 0.40  # mark occupies 40% of canvas width -- leaves room around it
mw = int(CANVAS * mark_scale)
mh = int(mw * mark.height / mark.width)
mark = mark.resize((mw, mh), Image.LANCZOS)
mark_pos = ((CANVAS - mw) // 2, (CANVAS - mh) // 2)
mark_r = math.hypot(mw, mh) / 2  # half-diagonal: real spawn-clear radius

cx, cy = CANVAS / 2, CANVAS / 2
edge_r = CANVAS / 2 - 10 * SS

# ---- particle sim: precompute every particle's full lifetime up front so
# the loop is deterministic and we can stagger spawn times across FRAMES ----
particles = []
t = 0
while t < FRAMES:
    is_bolt = random.random() < 0.12
    life = random.randint(14, 22) if is_bolt else random.randint(28, 60)
    angle = random.uniform(0, math.tau)
    start_r = mark_r * random.uniform(1.08, 1.22)
    travel = edge_r - start_r
    speed = travel / life * (random.uniform(1.05, 1.3) if is_bolt else random.uniform(0.75, 1.15))
    particles.append({
        "spawn": t, "life": life, "angle": angle, "start_r": start_r,
        "speed": speed, "bolt": is_bolt,
        "size": (2.2 if is_bolt else random.uniform(1.3, 2.6)) * SS,
    })
    t += random.uniform(1.4, 3.2)

def glitch_mark(img, seed):
    """RGB channel split + a few displaced scanline bands, applied to the
    mark's own RGBA pixels. Bands roll all 4 channels together (including
    alpha), so displaced strips carry their own torn silhouette edge --
    real corruption, not a filter laid over the top."""
    rnd = random.Random(seed)
    arr = np.array(img)
    out = arr.copy()
    h, _w = arr.shape[:2]

    dx = rnd.randint(2, 5) * SS
    out[:, :, 0] = np.roll(arr[:, :, 0], dx, axis=1)   # R
    out[:, :, 2] = np.roll(arr[:, :, 2], -dx, axis=1)  # B

    for _ in range(rnd.randint(2, 4)):
        band_h = rnd.randint(int(3 * SS), int(10 * SS))
        y0 = rnd.randint(0, max(1, h - band_h))
        shift = rnd.randint(-14, 14) * SS
        out[y0:y0 + band_h] = np.roll(out[y0:y0 + band_h], shift, axis=1)

    return Image.fromarray(out, "RGBA")

# two glitch bursts per loop, a handful of frames each; some frames inside
# a burst still show the clean mark (checked below) for a stutter/flicker
# feel instead of a smooth transform
GLITCH_STARTS = [0.15, 0.62]
GLITCH_LEN = max(3, round(FRAMES * 0.07))

def in_glitch_window(f):
    return any(round(frac * FRAMES) <= f < round(frac * FRAMES) + GLITCH_LEN
               for frac in GLITCH_STARTS)

def particle_state(p, frame):
    age = frame - p["spawn"]
    # allow wraparound so the loop has continuous spawning near the seam
    age %= FRAMES
    if age < 0 or age > p["life"]:
        return None
    r = p["start_r"] + p["speed"] * age
    t = age / p["life"]
    alpha = t / 0.15 if t < 0.15 else max(0.0, 1 - (t - 0.15) / 0.85)
    x = cx + math.cos(p["angle"]) * r
    y = cy + math.sin(p["angle"]) * r
    return x, y, alpha, p

frames_out = []
for f in range(FRAMES):
    canvas = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))

    # 1) breathing glow tucked mostly behind the mark -- a soft halo peeking
    #    at its edges, NOT a wash covering the stage (first attempt used
    #    glow_r up to 1.45x mark_r with blur sigma ~0.35x that radius, which
    #    flooded almost the whole canvas in solid green and buried the
    #    sparks -- verified visually, not assumed)
    glow_t = (math.sin(f / FRAMES * math.tau) + 1) / 2  # 0..1
    glow_r = mark_r * (0.58 + glow_t * 0.08)
    glow = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse([cx - glow_r, cy - glow_r, cx + glow_r, cy + glow_r],
               fill=ACID + (int(30 + glow_t * 30),))
    glow = glow.filter(ImageFilter.GaussianBlur(14 * SS))
    canvas = Image.alpha_composite(canvas, glow)

    # 2) sparks + bolts -- drawn BEFORE the mark, so step 5 (mark on top)
    #    physically cannot be covered by them
    spark_layer = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    sd = ImageDraw.Draw(spark_layer)
    for p in particles:
        state = particle_state(p, f)
        if not state:
            continue
        x, y, a, meta = state
        if a <= 0.02:
            continue
        if meta["bolt"]:
            # short trailing streak along the direction of travel
            tail = 10 * SS
            x0 = x - math.cos(meta["angle"]) * tail
            y0 = y - math.sin(meta["angle"]) * tail
            sd.line([x0, y0, x, y], fill=ACID_HOT + (int(a * 235),), width=max(1, int(meta["size"])))
        else:
            r = meta["size"]
            sd.ellipse([x - r, y - r, x + r, y + r], fill=ACID + (int(a * 190),))
    spark_layer = spark_layer.filter(ImageFilter.GaussianBlur(1.1 * SS))
    canvas = Image.alpha_composite(canvas, spark_layer)

    # 3) sharp bright cores on top of the blurred glow (readability)
    core_layer = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    cd = ImageDraw.Draw(core_layer)
    for p in particles:
        state = particle_state(p, f)
        if not state:
            continue
        x, y, a, meta = state
        if a <= 0.05 or meta["bolt"]:
            continue
        r = meta["size"] * 0.45
        cd.ellipse([x - r, y - r, x + r, y + r], fill=ACID_HOT + (int(a * 220),))
    canvas = Image.alpha_composite(canvas, core_layer)

    # 4) the mark itself, painted last -- its own alpha is the mask, so
    #    nothing from steps 1-3 can ever show through its opaque linework.
    #    During a glitch burst, most frames still show the clean mark
    #    (~30% chance of a glitched frame) so it reads as a stutter.
    frame_mark = mark
    if in_glitch_window(f) and random.Random(f * 97 + 3).random() < 0.6:
        frame_mark = glitch_mark(mark, f)
    canvas.paste(frame_mark, mark_pos, frame_mark)

    canvas = canvas.resize((CANVAS // SS, CANVAS // SS), Image.LANCZOS)
    frames_out.append(canvas)

if PREVIEW:
    # a handful of stills spanning the cycle, no slow video-format encode
    sample_idxs = sorted(set([0, 4, 5, 12, 13, len(frames_out) // 2, len(frames_out) - 1]))
    for i in sample_idxs:
        frames_out[i].save(f"preview-{i}.png")
    print("wrote preview stills:", sample_idxs)
else:
    frames_out[0].save(
        "en-hero.apng", format="PNG", save_all=True, append_images=frames_out[1:],
        duration=DURATION_MS, loop=0, disposal=2, optimize=True, compress_level=9,
    )
    print("wrote en-hero.apng")

    frames_out[0].save(
        "en-hero.webp", format="WEBP", save_all=True, append_images=frames_out[1:],
        duration=DURATION_MS, loop=0, quality=82, method=4,
    )
    print("wrote en-hero.webp")
