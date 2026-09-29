"""Static, same-origin sign-in presentation for the loopback dashboard."""

SIGNIN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Sign in · MEGALODON</title>
  <link rel="stylesheet" href="/assets/sign-in.css">
  <script src="/assets/sign-in.js" defer></script>
</head>
<body>
  <main class="page">
    <div class="brand" aria-label="MEGALODON"><span class="mark" aria-hidden="true">M</span><span>MEGALODON</span></div>
    <section class="card" aria-labelledby="title">
      <p class="eyebrow">Local dashboard</p>
      <h1 id="title">Welcome back</h1>
      <p class="intro">Enter your HUD password to view the telemetry stored on this computer.</p>
      <form id="sign-in-form" method="post" action="/sign-in" autocomplete="on">
        <label for="password">HUD password</label>
        <div class="password-row">
          <input id="password" name="password" type="password" autocomplete="current-password" required maxlength="64" autofocus>
          <button id="show-password" type="button" aria-label="Show password" aria-pressed="false">Show</button>
        </div>
        <p id="message" class="message" role="status" aria-live="polite">Use the password shown in the terminal that started this HUD, or your configured password.</p>
        <button id="submit" class="submit" type="submit">Sign in</button>
      </form>
    </section>
    <p class="footnote">This page is available only on this computer. Signing in does not start capture or change the host.</p>
  </main>
</body>
</html>
"""

SIGNIN_CSS = """
:root { color-scheme:dark; font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
* { box-sizing:border-box; }
body { min-height:100vh; margin:0; color:#e9f7f9; background:radial-gradient(circle at 50% 20%,#14333d 0,#071820 48%,#041117 100%); }
.page { min-height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:30px; padding:28px 18px; }
.brand { display:flex; align-items:center; gap:11px; width:min(100%,420px); color:#b9dce0; font-size:.8rem; font-weight:800; letter-spacing:.17em; }
.mark { display:grid; place-items:center; width:34px; height:34px; border:1px solid #5ad4d4; border-radius:10px; color:#75e6df; font-size:1.15rem; letter-spacing:0; }
.card { width:min(100%,420px); padding:34px; border:1px solid #31515b; border-radius:18px; background:#0d242d; box-shadow:0 24px 80px #0006; }
.eyebrow { margin:0 0 12px; color:#7ddbd6; font-size:.75rem; font-weight:800; letter-spacing:.14em; text-transform:uppercase; }
h1 { margin:0; font-size:2rem; letter-spacing:-.035em; }
.intro { margin:10px 0 28px; color:#b8cdd1; line-height:1.55; }
label { display:block; margin-bottom:9px; font-size:.9rem; font-weight:700; }
.password-row { display:flex; border:1px solid #53737a; border-radius:10px; background:#06171e; }
.password-row:focus-within { outline:2px solid #73ded9; outline-offset:2px; }
input { min-width:0; flex:1; padding:13px 14px; border:0; outline:0; background:transparent; color:#fff; font:inherit; }
.password-row button { border:0; border-left:1px solid #31515b; padding:0 14px; background:transparent; color:#aee4e1; cursor:pointer; }
.message { min-height:42px; margin:12px 0 20px; color:#a9c4c9; font-size:.82rem; line-height:1.5; }
.message.error { color:#ffb7a8; }
.submit { width:100%; min-height:46px; border:0; border-radius:10px; background:#80e5db; color:#052029; font:inherit; font-weight:800; cursor:pointer; }
.submit:hover { background:#b0f4ed; }
.submit:disabled { cursor:wait; opacity:.65; }
.footnote { width:min(100%,420px); margin:0; color:#91acb2; text-align:center; font-size:.78rem; line-height:1.5; }
@media(max-width:480px) { .card { padding:25px 21px; } }
"""

SIGNIN_JS = """
const form = document.getElementById('sign-in-form');
const password = document.getElementById('password');
const message = document.getElementById('message');
const submit = document.getElementById('submit');
const show = document.getElementById('show-password');
show.addEventListener('click', () => {
  const visible = password.type === 'password';
  password.type = visible ? 'text' : 'password';
  show.textContent = visible ? 'Hide' : 'Show';
  show.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
  show.setAttribute('aria-pressed', String(visible));
  password.focus();
});
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!password.value) return;
  submit.disabled = true;
  message.classList.remove('error');
  message.textContent = 'Signing in…';
  try {
    const response = await fetch('/sign-in', {
      method:'POST', credentials:'same-origin', cache:'no-store',
      headers:{'Content-Type':'application/json','X-Megalodon-Sign-In':'1'},
      body:JSON.stringify({password:password.value})
    });
    if (response.ok) {
      password.value = '';
      location.replace('/');
      return;
    }
    message.textContent = response.status === 429 ? 'Too many attempts. Wait a moment and try again.' : 'That password did not work. Check the HUD terminal or your configured password.';
  } catch (_) {
    message.textContent = 'The local HUD is unavailable. Check that it is still running.';
  }
  password.value = '';
  password.focus();
  message.classList.add('error');
  submit.disabled = false;
});
"""
