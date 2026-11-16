"""Static router guidance; selection changes presentation only."""
from html import escape

from .router_compatibility import (
    CHECKED_ON, COLLECTION_MODES, DEFAULT_MODE_ID, DEFAULT_PROFILE_ID, PROFILES,
)


def _options(items, default):
    return ''.join(f'<option value="{escape(item.id, quote=True)}"'
                   f'{" selected" if item.id == default else ""}>{escape(item.name)}</option>'
                   for item in items)


def _profile(profile):
    identifier = escape(profile.id, quote=True)
    sources = ''.join(
        f'<li><a href="{escape(source.url, quote=True)}" target="_blank" '
        f'rel="noopener noreferrer">{escape(source.title)}</a></li>'
        for source in profile.sources)
    caveats = ''.join(f'<li>{escape(value)}</li>' for value in profile.caveats)
    return (f'<section class="router-guide-panel" data-router-profile="{identifier}" '
            f'aria-labelledby="router-profile-{identifier}-title"'
            f'{"" if profile.id == DEFAULT_PROFILE_ID else " hidden"}>'
            f'<h6 id="router-profile-{identifier}-title">{escape(profile.name)}</h6>'
            f'<p class="support-config-note">{escape(profile.category)}</p>'
            f'<dl><dt>Collection options</dt><dd>{escape(profile.collection)}</dd>'
            f'<dt>Vendor features to review</dt><dd>{escape(profile.vendor_features)}</dd></dl>'
            f'<ul>{caveats}</ul><details><summary>Publisher sources</summary><ul>{sources}</ul></details></section>')


def _mode(mode):
    identifier = escape(mode.id, quote=True)
    return (f'<section class="router-guide-panel" data-router-mode="{identifier}" '
            f'aria-labelledby="router-mode-{identifier}-title"'
            f'{"" if mode.id == DEFAULT_MODE_ID else " hidden"}>'
            f'<h6 id="router-mode-{identifier}-title">{escape(mode.name)}</h6>'
            f'<dl><dt>What can be visible</dt><dd>{escape(mode.visibility)}</dd>'
            f'<dt>Coverage limits</dt><dd>{escape(mode.limitations)}</dd>'
            f'<dt>Preparation</dt><dd>{escape(mode.preparation)}</dd></dl></section>')


ROUTER_COMPATIBILITY_HTML = (
    '<section id="router-compatibility" aria-labelledby="router-compatibility-title">'
    '<h5 id="router-compatibility-title">Router and capture placement guide</h5>'
    '<p>Choose a router family and a capture placement to review collection options. '
    'This guide does not configure your router or verify monitoring coverage. '
    'Choices last only while this page is open.</p>'
    f'<p class="support-config-note">Publisher references checked {escape(CHECKED_ON)}. '
    'Features depend on the exact model and firmware.</p>'
    '<div class="router-guide-choices"><div><label for="router-guide-profile">Router family</label>'
    f'<select id="router-guide-profile" data-default="{escape(DEFAULT_PROFILE_ID, quote=True)}">'
    + _options(PROFILES, DEFAULT_PROFILE_ID) + '</select></div>'
    '<div><label for="router-guide-mode">Capture placement</label>'
    f'<select id="router-guide-mode" data-default="{escape(DEFAULT_MODE_ID, quote=True)}">'
    + _options(COLLECTION_MODES, DEFAULT_MODE_ID) + '</select></div></div>'
    '<div class="router-guide-panels"><div>' + ''.join(map(_profile, PROFILES)) + '</div><div>'
    + ''.join(map(_mode, COLLECTION_MODES)) + '</div></div>'
    '<p class="support-config-note">The HUD capture and bounded Zeek sampler use non-promiscuous capture '
    '(<code>-p</code>). Mirrored traffic needs a separately prepared promiscuous sensor and tested local '
    'ingestion. Selecting a profile or interface here does not prepare that sensor.</p>'
    '</section>'
)


ROUTER_COMPATIBILITY_CSS = r'''
#router-compatibility { margin:0 0 28px; padding:0 0 22px; border-bottom:1px solid #294451; }
#router-compatibility [hidden] { display:none!important; }
#router-compatibility .router-guide-choices,#router-compatibility .router-guide-panels { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:22px; }
#router-compatibility .router-guide-choices { margin:16px 0 20px; }
#router-compatibility select { width:100%; max-width:none; }
#router-compatibility h6 { margin:0 0 8px; font-size:.9rem; }
#router-compatibility dl { margin:12px 0; }
#router-compatibility dt { margin-top:12px; font-size:.8rem; font-weight:650; color:#d6e9ef; }
#router-compatibility dd { margin:4px 0 0; font-size:.84rem; line-height:1.6; color:#bdcfd9; }
#router-compatibility ul { padding-left:20px; }
#router-compatibility li { margin:7px 0; font-size:.82rem; line-height:1.6; color:#bdcfd9; }
#router-compatibility a { overflow-wrap:anywhere; }
@media(max-width:650px) { #router-compatibility .router-guide-choices,#router-compatibility .router-guide-panels { grid-template-columns:1fr; gap:16px; } }
'''


ROUTER_COMPATIBILITY_JS = r'''
(() => {
  const root=document.getElementById('router-compatibility');
  if(!root||typeof root.querySelectorAll!=='function')return;
  function bind(identifier,attribute,key){
    const select=document.getElementById(identifier);if(!select)return;
    const panels=[...root.querySelectorAll('['+attribute+']')];
    function display(){
      const selected=panels.some(panel=>panel.dataset[key]===select.value)?select.value:select.dataset.default;
      select.value=selected;
      panels.forEach(panel=>{panel.hidden=panel.dataset[key]!==selected;});
    }
    select.addEventListener('change',display);
    display();
  }
  bind('router-guide-profile','data-router-profile','routerProfile');
  bind('router-guide-mode','data-router-mode','routerMode');
})();
'''
