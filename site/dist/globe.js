/* Static geographic reference. No network, IP mapping, or telemetry calls. */
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
    const sin0 = Math.sin(lat0), cos0 = Math.cos(lat0);
    for (let y = center - radius; y <= center + radius; y++) {
      const north = (center - y) / radius;
      for (let x = center - radius; x <= center + radius; x++) {
        const east = (x - center) / radius, distance = east * east + north * north;
        if (distance > 1) continue;
        const forward = Math.sqrt(1 - distance);
        const latitude = Math.asin(north * cos0 + forward * sin0);
        const longitude = lon0 + Math.atan2(east, forward * cos0 - north * sin0);
        let horizontal = longitude / (2 * Math.PI) + .5;
        horizontal -= Math.floor(horizontal);
        const landX = Math.min(719, Math.floor(horizontal * 720));
        const landY = Math.max(0, Math.min(359, Math.floor((.5 - latitude / Math.PI) * 360)));
        const bit = landY * 720 + landX;
        const isLand = (mask[bit >> 3] & (1 << (bit & 7))) !== 0;
        const light = Math.max(0, -.28 * east + .37 * north + .88 * forward);
        const shade = .51 + .47 * light + .10 * forward;
        const index = (y * size + x) * 4;
        pixels[index] = (isLand ? 72 : 16) * shade;
        pixels[index + 1] = (isLand ? 135 : 81) * shade;
        pixels[index + 2] = (isLand ? 113 : 116) * shade;
        pixels[index + 3] = Math.min(255, Math.round(255 * Math.min(1, (1 - distance) * 95)));
      }
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
  document.getElementById('globe-west')?.addEventListener('click', () => { lon0 -= 30 * rad; draw(); });
  document.getElementById('globe-east')?.addEventListener('click', () => { lon0 += 30 * rad; draw(); });
  draw();
})();
