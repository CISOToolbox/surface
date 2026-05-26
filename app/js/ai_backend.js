/**
 * CISO Toolbox — AI Backend Overrides
 *
 * On any deployment that has a backend, ALL provider interaction goes
 * through the server: key storage (PUT /api/ai/keys), validation
 * (POST /api/ai/validate-key) and completion (POST /api/ai/complete).
 * The browser only ever talks to same-origin, so the module CSP can
 * stay strict (connect-src 'self') — no direct calls to AI providers.
 *
 * Two sub-modes:
 *  - managed (AI_MANAGED_BY_PILOT): keys pushed by Pilot, settings drawer
 *    shows a toggle only.
 *  - standalone-backend: the user enters their own key in the drawer;
 *    it is stored and used server-side.
 *
 * Load AFTER ai_common.js + ct_settings.js. Backend apps only (never
 * loaded in the browser-local opensource builds).
 */
(function() {
    "use strict";

    var cfg = window.AI_APP_CONFIG || {};

    // Backend deployments support all four providers — the server-side
    // proxy (/api/ai/complete) handles Anthropic, OpenAI, Bedrock (SigV4)
    // and a custom OpenAI-compatible endpoint. Credentials are stored and
    // used server-side; the browser only ever talks to same-origin.
    window._AI_PROVIDER_ALLOWLIST = ["anthropic", "openai", "bedrock", "custom"];

    function _pfx() { return (cfg.storagePrefix || "ct") + "_ai_"; }

    // ═══════════════════════════════════════════════════════════════════
    // RUNTIME PROBE
    // ═══════════════════════════════════════════════════════════════════

    window._aiRuntime = {
        managed: false, can_use: false, provider: "anthropic", model: "",
        anthropic_configured: false, openai_configured: false, loaded: false
    };

    window._aiFetchRuntime = async function() {
        try {
            var r = await fetch("api/ai/runtime", { credentials: "same-origin" });
            if (r.status === 401) return window._aiRuntime;
            if (!r.ok) { window._aiRuntime.loaded = true; return window._aiRuntime; }
            var j = await r.json();
            window._aiRuntime = Object.assign(window._aiRuntime, j, { loaded: true });
        } catch (e) {
            window._aiRuntime.loaded = true;
        }
        // Re-render once the probe is in so AI buttons appear when enabled.
        if (window._aiIsEnabled && window._aiIsEnabled()) {
            if (typeof renderAll === "function") setTimeout(renderAll, 100);
            else if (typeof renderPanel === "function") setTimeout(renderPanel, 100);
        }
        return window._aiRuntime;
    };

    // ═══════════════════════════════════════════════════════════════════
    // OVERRIDE: key accessors — the key lives server-side, never in the
    // browser. _aiGetApiKey returns a non-empty placeholder only so legacy
    // `if (!_aiGetApiKey()) return` guards don't misfire.
    // ═══════════════════════════════════════════════════════════════════

    window._aiGetApiKey = function() {
        var rt = window._aiRuntime || {};
        if (rt.managed) return rt.can_use ? "managed-by-pilot" : "";
        return "";  // standalone-backend: never expose the key to the page
    };

    window._aiIsEnabled = function() {
        var rt = window._aiRuntime || {};
        var enabled = localStorage.getItem(_pfx() + "enabled") === "true";
        if (rt.managed) return enabled && !!rt.can_use;
        // standalone-backend: enabled AND a key is configured server-side
        var provider = window._aiGetProvider ? window._aiGetProvider() : "anthropic";
        return enabled && !!rt[provider + "_configured"];
    };

    // ═══════════════════════════════════════════════════════════════════
    // OVERRIDE: _aiCallAPI — always routes through the server-side proxy
    // ═══════════════════════════════════════════════════════════════════

    window._aiCallAPI = async function(systemPrompt, userPrompt) {
        var ctx = window._aiGetContext ? window._aiGetContext() : "";
        if (ctx) {
            systemPrompt += "\n\n--- METHODOLOGY INSTRUCTIONS (provided by the user) ---\n" + ctx;
        }
        var rt = window._aiRuntime || {};
        if (rt.managed && !rt.can_use) throw new Error(t("ai.invalid_key") || "AI access not granted");
        var provider = rt.managed ? (rt.provider || "anthropic")
                                  : (window._aiGetProvider ? window._aiGetProvider() : "anthropic");
        var model = rt.managed ? (rt.model || "claude-sonnet-4-6")
                               : (window._aiGetModel ? window._aiGetModel() : "");
        var r;
        try {
            r = await fetch("api/ai/complete", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ system: systemPrompt, user: userPrompt, provider: provider, model: model })
            });
        } catch (e) {
            throw new Error("Network: " + e.message);
        }
        if (r.status === 403) throw new Error(t("ai.invalid_key") || "AI access not granted");
        if (!r.ok) {
            var errTxt = await r.text();
            throw new Error("API " + r.status + ": " + errTxt.substring(0, 200));
        }
        var jr = await r.json();
        return jr.text || "";
    };

    // ═══════════════════════════════════════════════════════════════════
    // OVERRIDE: key storage + validation — server-side.
    //  _pushConfig: PUT /api/ai/keys with the full credential set for the
    //  selected provider. Bedrock additionally carries the secret access
    //  key + region; custom carries the endpoint URL + key + model. An
    //  empty apiKey is never sent for anthropic/openai/bedrock so a
    //  config-only push (provider/model/region change) does not wipe a
    //  stored key.
    // ═══════════════════════════════════════════════════════════════════

    function _pushConfig(provider, apiKey, model) {
        var body = { provider: provider };
        if (model) body.model = model;
        if (apiKey) body[provider] = apiKey;
        if (provider === "bedrock") {
            if (window._aiGetSecretKey) body.ai_secret_bedrock = window._aiGetSecretKey();
            if (window._aiGetRegion) body.ai_region_bedrock = window._aiGetRegion();
        }
        if (provider === "custom") {
            if (window._aiGetEndpoint) body.ai_custom_endpoint = window._aiGetEndpoint();
            body.ai_custom_key = apiKey || "";
            if (model) body.ai_custom_model = model;
        }
        return fetch("api/ai/keys", {
            method: "PUT",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
    }

    window._aiValidateKey = async function(provider, apiKey, model) {
        try {
            var pr = await _pushConfig(provider, apiKey, model);
            if (!pr.ok) return false;
            var vr = await fetch("api/ai/validate-key?provider=" + encodeURIComponent(provider), {
                method: "POST", credentials: "same-origin"
            });
            if (!vr.ok) return false;
            var vj = await vr.json();
            await window._aiFetchRuntime();   // refresh *_configured flags
            return !!vj.valid;
        } catch (e) {
            return false;
        }
    };

    window._aiSetApiKey = function(apiKey) {
        var provider = window._aiGetProvider ? window._aiGetProvider() : "anthropic";
        _pushConfig(provider, apiKey, window._aiGetModel ? window._aiGetModel() : "")
            .then(function() { if (window._aiFetchRuntime) window._aiFetchRuntime(); })
            .catch(function() {});
    };
    window._aiClearApiKey = function() {
        var provider = window._aiGetProvider ? window._aiGetProvider() : "anthropic";
        var body = { provider: provider };
        body[provider] = "";
        if (provider === "custom") body.ai_custom_endpoint = "";
        if (provider === "bedrock") body.ai_secret_bedrock = "";
        fetch("api/ai/keys", {
            method: "PUT", credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        }).then(function() {
            if (window._aiFetchRuntime) window._aiFetchRuntime();
        }).catch(function() {});
    };

    // Push the non-key config (provider / model / Bedrock region / custom
    // endpoint) without touching a stored key. ct_settings.js calls this
    // at the end of every settings save, so a custom LLM with no key, or a
    // toggle-only save, still reaches the server.
    window._aiPersistConfig = function() {
        var provider = window._aiGetProvider ? window._aiGetProvider() : "anthropic";
        _pushConfig(provider, "", window._aiGetModel ? window._aiGetModel() : "")
            .then(function() { if (window._aiFetchRuntime) window._aiFetchRuntime(); })
            .catch(function() {});
    };

    // ═══════════════════════════════════════════════════════════════════
    // OVERRIDE: openSettings — managed mode shows a toggle only.
    // In standalone-backend mode the normal ct_settings.js drawer is used
    // (its save handler routes through the overridden primitives above).
    // ═══════════════════════════════════════════════════════════════════

    var _origOpenSettings = window.openSettings;
    window.openSettings = function() {
        if (!(window._aiRuntime && window._aiRuntime.managed)) {
            return _origOpenSettings();
        }
        if (!window._aiRuntime.loaded) {
            window._aiFetchRuntime().then(function() { window.openSettings(); });
            return;
        }
        if (typeof toggleMenu === "function") toggleMenu();
        var pfx = _pfx();
        var aiEnabled = localStorage.getItem(pfx + "enabled") === "true";
        var canUse = !!window._aiRuntime.can_use;

        var panel = window._aiEnsurePanel();
        panel.title.textContent = t("settings.title");

        var h =
            '<div class="settings-section">' +
                '<div class="settings-label">' + t("settings.language") + '</div>' +
                '<div style="display:flex;gap:8px">' +
                    '<button class="settings-lang-btn' + (typeof _locale !== "undefined" && _locale === "fr" ? " active" : "") + '" id="settings-lang-fr">Français</button>' +
                    '<button class="settings-lang-btn' + (typeof _locale !== "undefined" && _locale === "en" ? " active" : "") + '" id="settings-lang-en">English</button>' +
                '</div>' +
            '</div>' +
            '<div class="settings-section">' +
                '<div class="settings-label">' + t("settings.ai_section") + '</div>' +
                '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
                    '<label class="settings-toggle"><input type="checkbox" id="settings-ai-toggle"' + (aiEnabled && canUse ? " checked" : "") + (canUse ? "" : " disabled") + '><span class="settings-toggle-slider"></span></label>' +
                    '<span class="fs-sm">' + t("settings.ai_enable") + '</span>' +
                '</div>' +
                (canUse
                    ? '<p class="fs-xs text-muted" style="margin:4px 0 0">' + esc(t("settings.ai_managed_note") || "Provider, model and API key are managed centrally by your administrator.") + '</p>'
                    : '<p class="fs-xs" style="margin:4px 0 0;color:var(--red)">' + esc(t("settings.ai_no_access") || "AI access has not been granted to your account. Contact your administrator.") + '</p>'
                ) +
            '</div>';

        h += (cfg.settingsExtraHTML ? cfg.settingsExtraHTML() : '');
        h += '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:20px">' +
                '<button class="ai-btn-close" id="settings-cancel">' + t("ai.close") + '</button>' +
                '<button class="ai-btn-accept" id="settings-save">' + t("settings.save") + '</button>' +
            '</div>';

        panel.body.innerHTML = h;
        panel.footer.innerHTML = "";
        window._aiOpenPanel();

        document.getElementById("settings-cancel").onclick = window._aiClosePanel;
        document.getElementById("settings-lang-fr").onclick = function() { switchLang("fr"); window.openSettings(); };
        document.getElementById("settings-lang-en").onclick = function() { switchLang("en"); window.openSettings(); };

        document.getElementById("settings-save").onclick = function() {
            var toggle = document.getElementById("settings-ai-toggle").checked;
            if (toggle && !canUse) return;
            if (toggle && !aiEnabled) {
                if (!confirm(t("settings.ai_privacy_warning"))) return;
            }
            localStorage.setItem(pfx + "enabled", toggle ? "true" : "false");
            window._aiClosePanel();
            if (cfg.onSettingsSaved) cfg.onSettingsSaved();
            else if (typeof renderAll === "function") renderAll();
            showStatus(t("settings.saved"));
        };

        if (cfg.onSettingsRendered) cfg.onSettingsRendered();
    };

    // Probe the runtime now that the overrides are in place.
    window._aiFetchRuntime();

    // ═══════════════════════════════════════════════════════════════════
    // I18N — backend-only keys
    // ═══════════════════════════════════════════════════════════════════

    if (typeof _registerTranslations === "function") {
        _registerTranslations("fr", {
            "settings.ai_managed_note": "Le fournisseur, le modèle et la clé API sont configurés de manière centralisée par votre administrateur.",
            "settings.ai_no_access": "L'accès à l'assistant IA n'a pas été accordé à votre compte. Contactez votre administrateur."
        });
        _registerTranslations("en", {
            "settings.ai_managed_note": "Provider, model and API key are managed centrally by your administrator.",
            "settings.ai_no_access": "AI access has not been granted to your account. Contact your administrator."
        });
    }
})();
