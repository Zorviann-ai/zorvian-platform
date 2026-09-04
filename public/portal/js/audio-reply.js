(function () {
  const nativeFetch = window.fetch.bind(window);
  const defaultStatus = "Voice is available. Press the gold disc to speak.";

  function status(message) {
    const el = document.getElementById("voiceStatus");
    if (el) el.textContent = message;
  }

  function currentHost() {
    try {
      return window.CaelomerePresentation?.current?.() || {};
    } catch (_) {
      return {};
    }
  }

  function pickVoice(host) {
    const synth = window.speechSynthesis;
    if (!synth) return null;
    const voices = synth.getVoices ? synth.getVoices() : [];
    const hints = (host.voiceHints || []).map((value) => String(value).toLowerCase());
    const locale = String(host.locale || "en-GB").toLowerCase();
    return (
      voices.find((voice) => {
        const name = String(voice.name || "").toLowerCase();
        const lang = String(voice.lang || "").toLowerCase();
        return hints.some((hint) => name.includes(hint)) || lang === locale;
      }) ||
      voices.find((voice) => String(voice.lang || "").toLowerCase().startsWith(locale.split("-")[0])) ||
      voices[0] ||
      null
    );
  }

  function speakReply(text) {
    const reply = String(text || "").trim();
    if (!reply) return false;
    if (!window.speechSynthesis || typeof window.SpeechSynthesisUtterance !== "function") {
      status("Audio reply is unavailable in this browser. The reply is still shown on screen.");
      return false;
    }

    const host = currentHost();
    const utterance = new window.SpeechSynthesisUtterance(reply);
    utterance.lang = host.locale || "en-GB";
    utterance.rate = host.voiceRate || 0.96;
    utterance.pitch = host.voicePitch || 1;
    const voice = pickVoice(host);
    if (voice) utterance.voice = voice;

    utterance.onstart = () => {
      status(`${host.displayName || "Celeste"} is speaking…`);
    };
    utterance.onend = () => {
      status(defaultStatus);
    };
    utterance.onerror = () => {
      status("Audio reply could not play. The full reply is still shown on screen.");
    };

    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(utterance);
    return true;
  }

  function isSocialAdvisoryRequest(input) {
    const raw = typeof input === "string" ? input : input?.url;
    if (!raw) return false;
    try {
      const url = new URL(raw, window.location.origin);
      return url.origin === window.location.origin && url.pathname === "/api/ai/social";
    } catch (_) {
      return false;
    }
  }

  window.CaelomereVerifiedAudio = Object.freeze({ speakReply });

  window.fetch = async function caelomereVerifiedAudioFetch(input, init) {
    const response = await nativeFetch(input, init);
    if (!isSocialAdvisoryRequest(input) || !response.ok) return response;

    try {
      const data = await response.clone().json();
      const reply = String(data?.reply || "").trim();
      if (reply) queueMicrotask(() => speakReply(reply));
    } catch (_) {
      // Text rendering remains authoritative if audio parsing is unavailable.
    }
    return response;
  };
})();
