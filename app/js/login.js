// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/js/backend/login_oauth.js).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/**
 * Login page script — OAUTH variant (surface, appsec, watch).
 * Suite mode → redirect to Pilot; standalone → OAuth buttons
 * (Entra / Google / OIDC) revealed according to the backend config, plus an
 * optional token form.
 *
 * Compiled to login_oauth.js; the build script copies it as
 * app/js/login.js for the modules concerned (see ts-build.sh).
 * See login.ts for the factorisation note.
 */
(function () {
    "use strict";
    var currentPath = window.location.pathname.replace(/login\.html.*$/, "");
    // Check if already logged in
    fetch("auth/me", { credentials: "same-origin" })
        .then(function (r) { if (r.ok) {
        window.location.href = "./";
        return;
    } return _showLogin(); })
        .catch(function () { _showLogin(); });
    function _showLogin() {
        return fetch("auth/providers").then(function (r) { return r.json(); }).then(function (data) {
            if (!data.auth_enabled) {
                window.location.href = "./";
                return;
            }
            if (data.central) {
                // Suite mode: delegate to the central Pilot login page
                window.location.href = "/login.html?redirect=" + encodeURIComponent(currentPath);
                return;
            }
            if (data.standalone) {
                _renderStandalone(data);
                return;
            }
        }).catch(function () { window.location.href = "./"; });
    }
    function _renderStandalone(data) {
        var anyOAuth = data.entra || data.google || data.oidc;
        var buttons = document.getElementById("login-buttons");
        if (!buttons)
            return;
        // OAuth buttons already exist in login.html but are hidden; reveal
        // only the providers the backend reports as configured.
        if (data.entra) {
            var e = document.getElementById("btn-entra");
            if (e)
                e.style.display = "";
        }
        if (data.google) {
            var g = document.getElementById("btn-google");
            if (g)
                g.style.display = "";
        }
        if (data.oidc) {
            var o = document.getElementById("btn-oidc");
            if (o)
                o.style.display = "";
            var lbl = document.getElementById("btn-oidc-label");
            if (lbl && data.oidc_label)
                lbl.textContent = data.oidc_label;
        }
        // Token login: show as a secondary option when AUTH_TOKEN is set.
        if (data.token) {
            _appendTokenForm(buttons, !!anyOAuth);
        }
        else if (!anyOAuth) {
            var subtitle = document.querySelector(".login-subtitle");
            if (subtitle)
                subtitle.textContent = "No login provider configured";
        }
    }
    function _appendTokenForm(container, hasOAuth) {
        var wrap = document.createElement("div");
        wrap.style.marginTop = hasOAuth ? "16px" : "0";
        if (hasOAuth) {
            wrap.innerHTML =
                '<div style="display:flex;align-items:center;gap:8px;margin:12px 0;font-size:0.78em;color:#6b7280;text-transform:uppercase;letter-spacing:.5px">' +
                    '<div style="flex:1;height:1px;background:#e5e7eb"></div>' +
                    '<span>or</span>' +
                    '<div style="flex:1;height:1px;background:#e5e7eb"></div>' +
                    '</div>';
        }
        wrap.insertAdjacentHTML("beforeend", '<input type="email" id="token-email" placeholder="Email" autocomplete="email" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:6px;margin-bottom:8px;font-size:0.9em;box-sizing:border-box">' +
            '<input type="password" id="token-input" placeholder="Token" autocomplete="current-password" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:6px;margin-bottom:12px;font-size:0.9em;box-sizing:border-box">' +
            '<button id="token-submit" style="width:100%;padding:10px;background:#2563eb;color:white;border:none;border-radius:6px;font-size:0.9em;cursor:pointer;font-weight:600">Sign in with token</button>');
        container.appendChild(wrap);
        var errEl = document.getElementById("login-error");
        document.getElementById("token-submit").onclick = function () {
            var email = document.getElementById("token-email").value.trim();
            var token = document.getElementById("token-input").value;
            if (!token)
                return;
            fetch("auth/login/token", {
                method: "POST", credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: token, email: email || "admin@local" })
            }).then(function (r) {
                if (r.ok) {
                    window.location.href = "./";
                }
                else {
                    if (errEl) {
                        errEl.style.display = "block";
                        errEl.textContent = "Invalid token";
                    }
                }
            }).catch(function () {
                if (errEl) {
                    errEl.style.display = "block";
                    errEl.textContent = "Connection error";
                }
            });
        };
        document.getElementById("token-input").onkeydown = function (e) {
            if (e.key === "Enter")
                document.getElementById("token-submit").click();
        };
    }
})();
