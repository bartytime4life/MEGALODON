"""Keep read-only review DOM stable across local status polling."""

REFRESH_JS = r'''
function stableReview(render) {
  return function(panel, ...args) {
    if (!panel || !panel.ownerDocument || typeof panel.insertBefore !== 'function') return render(panel, ...args);
    const next = panel.ownerDocument.createElement('div');
    render(next, ...args);
    const focused = panel.ownerDocument.activeElement;
    // Only validated, read-only review content belongs here. Action controls
    // retain their own listeners and authorization lifecycle outside this tree.
    const key = node => node.nodeType === 1 ? node.id || node.dataset.refreshKey || node.dataset.source || '' : '';
    const same = (a, b) => a && a.nodeType === b.nodeType && a.nodeName === b.nodeName && key(a) === key(b);
    function update(parent, incoming) {
      const previous = Array.from(parent.childNodes), used = new Set();
      const keyed = new Map(previous.filter(node => key(node)).map(node => [key(node), node]));
      for (const [index, fresh] of incoming.entries()) {
        const identity = key(fresh), old = identity ? keyed.get(identity) : previous[index];
        const current = same(old, fresh) && !used.has(old) ? old : fresh;
        used.add(current);
        if (current !== fresh) {
          if (fresh.nodeType === 3) {
            if (current.nodeValue !== fresh.nodeValue) current.nodeValue = fresh.nodeValue;
          } else if (fresh.nodeType === 1) {
            for (const attribute of Array.from(current.attributes)) {
              if (current.nodeName === 'DETAILS' && attribute.name === 'open') continue;
              if (!fresh.hasAttribute(attribute.name)) current.removeAttribute(attribute.name);
            }
            for (const attribute of Array.from(fresh.attributes)) {
              if (current.nodeName === 'DETAILS' && attribute.name === 'open') continue;
              if (current.getAttribute(attribute.name) !== attribute.value) current.setAttribute(attribute.name, attribute.value);
            }
            update(current, Array.from(fresh.childNodes));
          }
        }
        if (parent.childNodes[index] !== current) parent.insertBefore(current, parent.childNodes[index] || null);
      }
      while (parent.childNodes.length > incoming.length) parent.removeChild(parent.lastChild);
    }
    update(panel, Array.from(next.childNodes));
    if (focused && panel.contains(focused) && panel.ownerDocument.activeElement !== focused) focused.focus?.({preventScroll:true});
  };
}
'''
