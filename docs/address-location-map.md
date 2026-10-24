# Local map context for an observed address

Select a peer in the HUD connection roster and choose **Show recorded region**.
The control reads that retained endpoint's local location metadata. Selection
alone does not read location context or load the map engine. The existing globe
and traffic investigation remain available independently.

The map displays the location supplied by the loaded offline database, its source,
the database build/download dates when recorded, and the observation snapshot's
time and capture state. A failed or stopped capture can retain usable context.
Coordinates describe an estimated network endpoint, which may be a VPN exit or
proxy. Original source, person identity and physical street address remain unknown.
The database loaded at the snapshot may not describe where an IP was during an
older exchange.

When the source provides a positive accuracy radius, a dashed geodesic boundary
shows that ground distance around its estimated coordinate. This does not establish
a confidence level or prove the endpoint is inside it. A missing, zero, invalid
or unsupported radius stays unknown; no default radius invents precision. The
boundary uses a spherical 6371.0088 km Earth with 128 segments and splits at the
antimeridian. Very large radii remain large. Mercator clips polar portions;
coordinates above 85.05112878 degrees latitude retain a textual fallback.

Private, reserved, shared and mapped IPv6 addresses receive no public-IP map
position, including when the globe has this PC's internet-exit anchor. Missing
location data shows **Location unknown** and still allows a location-context
export. Traffic evidence remains available in Address investigation.
An address assigned to the selected local interface also cannot inherit that
shared exit position, even when the local address is globally routable. Its
export records the explicit `local_exit_anchor` role with no endpoint position.
The live-connections and operations APIs expose that same role explicitly; only
`observed_network_endpoint` coordinates can become an endpoint map export.

**Save location context** downloads `megalodon-address-location.json`. It preserves
unknown values, source dates, radius and capture state, and is outside automatic
evidence cleanup. It is separate from the existing v1 traffic investigation note.
Changing selection clears the prior position/export and ignores late responses.

## Local assets and request boundaries

MapLibre GL JS **6.15.0** is bundled with its BSD-3-Clause license. The original npm
tarball was checked against its published SHA-512 integrity value. Exact vendored
file sizes and SHA-256 hashes are in
[`manifest.json`](../megalodon/assets/address-map/manifest.json).
Large static files are stored with deterministic gzip compression to remain
within the existing installed-recovery package-size bound. The local asset reader
caps both stored and decoded input at 2 MiB; the original decoded identities and
compressed identities are recorded separately. No recovery size bound is raised.
The [MapLibre documentation](https://maplibre.org/maplibre-gl-js/docs/) describes
its same-origin worker setting; this integration serves the worker locally.

The map bundles Natural Earth 1:110m reference outlines from the same pinned
source commit used by the existing globe. Land is preserved verbatim; country
and state/province files retain only unchanged geometry. Source URLs, Git blob
identities and source/derived digests are recorded in the manifest. These are
fixed illustrative outlines, not a current street basemap. Natural Earth data is
[public domain](https://www.naturalearthdata.com/about/terms-of-use/).
The pinned state-line layer supplies US internal state boundaries; it does not
provide worldwide state/province coverage. Other regions retain the bundled
country and coastline context. Boundary coverage is separate from IP-location
and traffic coverage.

No external tile, font, image, IP lookup or reverse-geocoding service is used.
The renderer receives coordinates, radius and snapshot time through an
origin-checked local message; it does not receive the peer IP. Bundled assets are
loaded only after an explicit read returns a usable position. No data acquisition
or database refresh is triggered by the read.

The main HUD keeps its existing CSP, including `worker-src 'none'`. Only the
dedicated `/address-map` document allows a same-origin worker and same-origin
embedding; it keeps scripts, styles and connections same-origin and images,
fonts, child frames, forms and plugins disabled. It requires the same Host/session
checks as the HUD. The API also requires the explicit-read header, a canonical
numeric address in the retained endpoint set and an 8 KiB response bound. Map
assets are served from a fixed name allowlist with a 2 MiB per-file limit.

Zoom buttons, keyboard panning and the metric scale provide local navigation.
Map movements use immediate updates, and source/coordinate/uncertainty text stays
available if WebGL fails. The map changes neither capture access nor response
authority.
