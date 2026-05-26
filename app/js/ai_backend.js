/**
 * CISO Toolbox — AI Backend Overrides
 *
 * Pilot-managed AI mode: runtime probe, proxy calls, managed settings UI.
 * Load AFTER ai_common.js. Used by backend apps only (never in opensource).
 */
(function() {
    "use strict";

    var cfg = window.AI_APP_CONFIG || {};

    // ═══════════════════════════════════════════════════════════════════
    // RUNTIME PROBE
    // ═══════════════════════════════════════════════════════════════════

    window._aiRuntime = { managed: false, can_use: false, provider: "anthropic", model: "", loaded: false };

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
        // Re-render current view so AI buttons appear after probe completes
        if (window._aiRuntime.managed && window._aiRuntime.can_use) {
            if (typeof renderAll === "function") setTimeout(renderAll, 100);
            else if (typeof renderPanel === "function") setTimeout(renderPanel, 100);
        }
        return window._aiRuntime;
    };

    window._aiFetchRuntime();

    // ═══════════════════════════════════════════════════════════════════
    // OVERRIDE: _aiIsEnabled — managed mode checks can_use
    // ═══════════════════════════════════════════════════════════════════

    // Override _aiGetApiKey: in managed mode, return a placeholder
    // so that guards like `if (!_aiGetApiKey()) return` don't block.
    var _origGetApiKey = window._aiGetApiKey;
    window._aiGetApiKey = function() {
        if (window._aiRuntime && window._aiRuntime.managed && window._aiRuntime.can_use) {
            return "managed-by-pilot";
        }
        return _origGetApiKey();
    };

    var _origIsEnabled = window._aiIsEnabled;
    window._aiIsEnabled = function() {
        if (window._aiRuntime && window._aiRuntime.managed) {
            var pfx = (cfg.storagePrefix || "ct") + "_ai_";
            return localStorage.getItem(pfx + "enabled") === "true" && !!window._aiRuntime.can_use;
        }
        return _origIsEnabled();
    };

    // ═══════════════════════════════════════════════════════════════════
    // OVERRIDE: _aiCallAPI — managed mode routes through backend proxy
    // ═══════════════════════════════════════════════════════════════════

    var _origCallAPI = window._aiCallAPI;
    window._aiCallAPI = async function(systemPrompt, userPrompt) {
        if (!(window._aiRuntime && window._aiRuntime.managed)) {
            return _origCallAPI(systemPrompt, userPrompt);
        }
        var ctx = window._aiGetContext ? window._aiGetContext() : "";
        if (ctx) {
            systemPrompt += "\n\n--- METHODOLOGY INSTRUCTIONS (provided by the user) ---\n" + ctx;
        }
        if (!window._aiRuntime.can_use) throw new Error(t("ai.invalid_key") || "AI access not granted");
        var r;
        try {
            r = await fetch("api/ai/complete", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    system: systemPrompt,
                    user: userPrompt,
                    provider: window._aiRuntime.provider || "anthropic",
                    model: window._aiRuntime.model || "claude-sonnet-4-6"
                })
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
    // OVERRIDE: openSettings — managed mode shows toggle only
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
        var pfx = (cfg.storagePrefix || "ct") + "_ai_";
        var aiEnabled = localStorage.getItem(pfx + "enabled") === "true";
        var canUse = !!window._aiRuntime.can_use;

        var panel = window._aiEnsurePanel();
        panel.title.textContent = t("settings.title");

        var h =
            '<div class="settings-section">' +
                '<div class="settings-label">' + t("settings.language") + '</div>' +
                '<div style="display:flex;gap:8px">' +
                    '<button class="settings-lang-btn' + (typeof _locale !== "undefined" && _locale === "fr" ? " active" : "") + '" id="settings-lang-fr">Fran\u00e7ais</button>' +
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

    // ═══════════════════════════════════════════════════════════════════
    // I18N — backend-only keys
    // ═══════════════════════════════════════════════════════════════════

    if (typeof _registerTranslations === "function") {
        _registerTranslations("fr", {
            "settings.ai_managed_note": "Le fournisseur, le mod\u00e8le et la cl\u00e9 API sont configur\u00e9s de mani\u00e8re centralis\u00e9e par votre administrateur.",
            "settings.ai_no_access": "L'acc\u00e8s \u00e0 l'assistant IA n'a pas \u00e9t\u00e9 accord\u00e9 \u00e0 votre compte. Contactez votre administrateur."
        });
        _registerTranslations("en", {
            "settings.ai_managed_note": "Provider, model and API key are managed centrally by your administrator.",
            "settings.ai_no_access": "AI access has not been granted to your account. Contact your administrator."
        });
    }
})();
