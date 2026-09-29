const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function mountGlobe(reduced = false) {
  const buttons = new Map();
  for (const id of ['globe-west', 'globe-east', 'globe-motion']) {
    buttons.set(id, {handlers: {}, addEventListener(name, handler) { this.handlers[name] = handler; },
      setAttribute(name, value) { this[name] = value; }, disabled: false, textContent: ''});
  }
  let paints = 0;
  const context = {
    createImageData: () => ({data: new Uint8ClampedArray(420 * 420 * 4)}),
    putImageData: () => { paints++; },
    createRadialGradient: () => ({addColorStop() {}}),
    fillRect() {}, save() {}, restore() {}, beginPath() {}, arc() {},
    clip() {}, stroke() {}, moveTo() {}, lineTo() {}
  };
  const canvas = {getContext: () => context, closest: () => ({hidden: false})};
  const document = {hidden: false, getElementById: id => id === 'reference-globe' ? canvas : buttons.get(id),
    addEventListener() {}};
  const frames = [];
  const mask = Buffer.alloc(32400);
  mask.forEach((_, i) => { mask[i] = (i * 37) & 255; });
  const window = {MEGALODON_LAND_MASK: mask.toString('base64'),
    matchMedia: () => ({matches: reduced, addEventListener() {}}),
    requestAnimationFrame: callback => { frames.push(callback); }};
  vm.runInNewContext(fs.readFileSync(require.resolve('../dist/globe.js'), 'utf8'),
    {document, window, atob: value => Buffer.from(value, 'base64').toString('binary'),
      Uint8Array, Uint8ClampedArray, Math});
  return {buttons, document, frames, paints: () => paints,
    frame(now) { assert.ok(frames.length); frames.shift()(now); }};
}

test('globe animates while visible and respects pause and manual rotation', () => {
  const globe = mountGlobe();
  assert.equal(globe.paints(), 1);
  globe.frame(0);
  globe.frame(40);
  assert.equal(globe.paints(), 2);
  globe.buttons.get('globe-motion').handlers.click();
  globe.frame(80);
  assert.equal(globe.paints(), 2);
  globe.buttons.get('globe-east').handlers.click();
  assert.equal(globe.paints(), 3);
  globe.document.hidden = true;
  globe.frame(120);
  assert.equal(globe.paints(), 3);
});

test('reduced motion starts with a still globe and keeps manual controls', () => {
  const globe = mountGlobe(true);
  globe.frame(0);
  globe.frame(40);
  assert.equal(globe.paints(), 1);
  assert.equal(globe.buttons.get('globe-motion').disabled, true);
  globe.buttons.get('globe-west').handlers.click();
  assert.equal(globe.paints(), 2);
});
