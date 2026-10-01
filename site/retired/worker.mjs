// The retired hosted address has no UI and never redirects to localhost.
// The installed launcher opens the local HUD directly.
export default {
  fetch() {
    return new Response(null, {
      status: 410,
      headers: {
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex, nofollow",
      },
    });
  },
};
