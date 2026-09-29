/* Animated geographic reference. No network, IP mapping, or telemetry calls. */
(() => {
  const canvas = document.getElementById('reference-globe');
  if (!canvas || !window.MEGALODON_LAND_MASK) return;
  const context = canvas.getContext('2d');
  if (!context) return;
  const binary = atob(window.MEGALODON_LAND_MASK);
  if (binary.length !== 32400) return;
  const mask = Uint8Array.from(binary, character => character.charCodeAt(0));
  const size = 420, center = 210, radius = 182, rad = Math.PI / 180;
  const lat0 = 20 * rad;
  let lon0 = -20 * rad;
  const image = context.createImageData(size, size);
  const sphere = [];
  const sin0 = Math.sin(lat0), cos0 = Math.cos(lat0);
  for (let y = center - radius; y <= center + radius; y++) {
    const north = (center - y) / radius;
    for (let x = center - radius; x <= center + radius; x++) {
      const east = (x - center) / radius, distance = east * east + north * north;
      if (distance > 1) continue;
      const forward = Math.sqrt(1 - distance);
      const latitude = Math.asin(north * cos0 + forward * sin0);
      const offset = Math.atan2(east, forward * cos0 - north * sin0) / (2 * Math.PI) + .5;
      const landY = Math.max(0, Math.min(359, Math.floor((.5 - latitude / Math.PI) * 360)));
      const light = Math.max(0, -.28 * east + .37 * north + .88 * forward);
      sphere.push({index: (y * size + x) * 4, offset, landY,
        shade: .51 + .47 * light + .10 * forward,
        alpha: Math.min(255, Math.round(255 * Math.min(1, (1 - distance) * 95)))});
    }
  }

  function project(latitude, longitude) {
    const phi = latitude * rad;
    const delta = ((longitude - lon0 / rad + 540) % 360 - 180) * rad;
    const depth = Math.sin(lat0) * Math.sin(phi) + Math.cos(lat0) * Math.cos(phi) * Math.cos(delta);
    return { visible: depth >= 0,
      x: center + radius * Math.cos(phi) * Math.sin(delta),
      y: center - radius * (Math.cos(lat0) * Math.sin(phi) - Math.sin(lat0) * Math.cos(phi) * Math.cos(delta)) };
  }
  function drawGrid(points) {
    context.beginPath();
    let pen = false;
    for (const [lat, lon] of points) {
      const p = project(lat, lon);
      if (!p.visible) { pen = false; continue; }
      if (pen) context.lineTo(p.x, p.y);
      else context.moveTo(p.x, p.y);
      pen = true;
    }
    context.stroke();
  }
  function draw() {
    const pixels = image.data;
    pixels.fill(0);
    const turn = lon0 / (2 * Math.PI);
    for (const point of sphere) {
      let horizontal = turn + point.offset;
      horizontal -= Math.floor(horizontal);
      const landX = Math.min(719, Math.floor(horizontal * 720));
      const bit = point.landY * 720 + landX;
      const isLand = (mask[bit >> 3] & (1 << (bit & 7))) !== 0;
      const index = point.index;
      pixels[index] = (isLand ? 72 : 16) * point.shade;
      pixels[index + 1] = (isLand ? 135 : 81) * point.shade;
      pixels[index + 2] = (isLand ? 113 : 116) * point.shade;
      pixels[index + 3] = point.alpha;
    }
    context.putImageData(image, 0, 0);
    const atmosphere = context.createRadialGradient(center, center, radius - 13, center, center, radius + 24);
    atmosphere.addColorStop(0, 'rgba(112,205,218,0)');
    atmosphere.addColorStop(.42, 'rgba(112,205,218,.13)');
    atmosphere.addColorStop(.75, 'rgba(112,205,218,.21)');
    atmosphere.addColorStop(1, 'rgba(112,205,218,0)');
    context.fillStyle = atmosphere;
    context.fillRect(0, 0, size, size);
    context.save();
    context.beginPath();
    context.arc(center, center, radius, 0, Math.PI * 2);
    context.clip();
    context.strokeStyle = 'rgba(185,231,226,.23)';
    context.lineWidth = 1;
    for (let lat = -60; lat <= 60; lat += 30)
      drawGrid(Array.from({length: 145}, (_, i) => [lat, -180 + i * 2.5]));
    for (let lon = -180; lon < 180; lon += 30)
      drawGrid(Array.from({length: 73}, (_, i) => [-90 + i * 2.5, lon]));
    context.restore();
    context.beginPath();
    context.arc(center, center, radius, 0, Math.PI * 2);
    context.strokeStyle = 'rgba(160,226,225,.75)';
    context.lineWidth = 1.5;
    context.stroke();
  }
  const motionButton = document.getElementById('globe-motion');
  const motionPreference = typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  let paused = Boolean(motionPreference?.matches), lastFrame = null, lastDraw = 0;
  function syncButton() {
    if (!motionButton) return;
    motionButton.disabled = Boolean(motionPreference?.matches);
    motionButton.setAttribute('aria-pressed', String(!paused));
    motionButton.setAttribute('aria-label', paused ? 'Resume globe rotation' : 'Pause globe rotation');
    motionButton.textContent = motionButton.disabled ? 'Motion reduced' : paused ? 'Resume motion' : 'Pause motion';
  }
  document.getElementById('globe-west')?.addEventListener('click', () => { lon0 -= 30 * rad; draw(); });
  document.getElementById('globe-east')?.addEventListener('click', () => { lon0 += 30 * rad; draw(); });
  motionButton?.addEventListener('click', () => { paused = !paused; lastFrame = null; syncButton(); });
  motionPreference?.addEventListener?.('change', event => {
    paused = event.matches;
    lastFrame = null;
    syncButton();
  });
  document.addEventListener('visibilitychange', () => { lastFrame = null; });
  syncButton();
  draw();
  if (typeof window.requestAnimationFrame !== 'function') return;
  function animate(now) {
    window.requestAnimationFrame(animate);
    const view = canvas.closest?.('[data-view-panel]');
    if (paused || document.hidden || view?.hidden) { lastFrame = null; return; }
    if (lastFrame === null) { lastFrame = now; return; }
    const elapsed = Math.min(80, Math.max(0, now - lastFrame));
    lastFrame = now;
    lon0 = (lon0 + elapsed * .009 * rad) % (2 * Math.PI);
    if (now - lastDraw < 32) return;
    lastDraw = now;
    draw();
  }
  window.requestAnimationFrame(animate);
})();
