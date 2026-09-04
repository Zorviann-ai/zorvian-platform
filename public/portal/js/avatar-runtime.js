(function () {
  const FEMALE_EN_GB = [
    'serena',
    'kate',
    'sonia',
    'hazel',
    'martha',
    'libby',
    'google uk english female',
    'microsoft sonia',
    'microsoft hazel'
  ];

  const MALE_EN_GB = [
    'daniel',
    'ryan',
    'george',
    'google uk english male',
    'microsoft ryan',
    'microsoft george'
  ];

  const state = {
    speaking: false,
    listening: false,
    mouth: null,
    mouthImage: null,
    root: null,
    portrait: null,
    nativeSpeak: null
  };

  function host() {
    try {
      return window.CaelomerePresentation?.current?.() || {
        id: 'celeste',
        displayName: 'Celeste',
        presentation: 'female',
        locale: 'en-GB'
      };
    } catch (_) {
      return { id: 'celeste', displayName: 'Celeste', presentation: 'female', locale: 'en-GB' };
    }
  }

  function voiceNamesFor(h) {
    return h.presentation === 'male' ? MALE_EN_GB : FEMALE_EN_GB;
  }

  function pickApprovedVoice(h) {
    const synth = window.speechSynthesis;
    if (!synth || typeof synth.getVoices !== 'function') return null;
    const approved = voiceNamesFor(h);
    const voices = synth.getVoices() || [];
    return voices.find((voice) => {
      const name = String(voice.name || '').toLowerCase();
      const lang = String(voice.lang || '').toLowerCase();
      return lang === 'en-gb' && approved.some((allowed) => name.includes(allowed));
    }) || voices.find((voice) => {
      const name = String(voice.name || '').toLowerCase();
      return approved.some((allowed) => name.includes(allowed));
    }) || null;
  }

  function setStatus(message) {
    const el = document.getElementById('voiceStatus');
    if (el) el.textContent = message;
  }

  function setSpeaking(active) {
    state.speaking = Boolean(active);
    document.documentElement.classList.toggle('avatar-speaking', state.speaking);
    if (state.root) state.root.classList.toggle('is-speaking', state.speaking);
    window.dispatchEvent(new CustomEvent('caelomere:avatar-speaking', { detail: { active: state.speaking } }));
  }

  function syncPortraitSource() {
    if (!state.portrait || !state.mouthImage) return;
    if (state.mouthImage.src !== state.portrait.src) state.mouthImage.src = state.portrait.src;
  }

  function buildAvatarLayer() {
    state.root = document.getElementById('celeste');
    state.portrait = document.getElementById('hostPortrait');
    const frame = state.portrait?.closest('.celeste__portrait');
    if (!state.root || !state.portrait || !frame) return;

    state.root.classList.add('avatar-live');
    state.root.setAttribute('data-avatar-mode', 'animated');

    const mouth = document.createElement('div');
    mouth.className = 'avatar-mouth-layer';
    mouth.setAttribute('aria-hidden', 'true');
    const mouthImage = document.createElement('img');
    mouthImage.className = 'avatar-mouth-image';
    mouthImage.src = state.portrait.src;
    mouthImage.alt = '';
    mouth.appendChild(mouthImage);
    frame.appendChild(mouth);

    const aura = document.createElement('div');
    aura.className = 'avatar-presence-aura';
    aura.setAttribute('aria-hidden', 'true');
    frame.appendChild(aura);

    state.mouth = mouth;
    state.mouthImage = mouthImage;

    const observer = new MutationObserver(syncPortraitSource);
    observer.observe(state.portrait, { attributes: true, attributeFilter: ['src'] });
  }

  function installSpeechGuard() {
    const synth = window.speechSynthesis;
    if (!synth || typeof synth.speak !== 'function') return;
    state.nativeSpeak = synth.speak.bind(synth);

    synth.speak = function guardedSpeak(utterance) {
      const h = host();
      const approvedVoice = pickApprovedVoice(h);
      if (!approvedVoice) {
        setSpeaking(false);
        setStatus(`${h.displayName || 'Celeste'} voice is unavailable on this device. The full reply remains on screen.`);
        window.dispatchEvent(new CustomEvent('caelomere:voice-unavailable', { detail: { host: h.id || 'celeste' } }));
        return;
      }

      utterance.voice = approvedVoice;
      utterance.lang = 'en-GB';
      const previousStart = utterance.onstart;
      const previousEnd = utterance.onend;
      const previousError = utterance.onerror;

      utterance.onstart = function (event) {
        setSpeaking(true);
        if (typeof previousStart === 'function') previousStart.call(this, event);
      };
      utterance.onend = function (event) {
        setSpeaking(false);
        if (typeof previousEnd === 'function') previousEnd.call(this, event);
      };
      utterance.onerror = function (event) {
        setSpeaking(false);
        if (typeof previousError === 'function') previousError.call(this, event);
      };

      state.nativeSpeak(utterance);
    };
  }

  function speak(text) {
    const reply = String(text || '').trim();
    if (!reply || !window.speechSynthesis || typeof window.SpeechSynthesisUtterance !== 'function') {
      if (reply) setStatus('Voice is unavailable on this device. The full reply remains on screen.');
      return false;
    }
    const h = host();
    const utterance = new SpeechSynthesisUtterance(reply);
    utterance.lang = 'en-GB';
    utterance.rate = h.voiceRate || 0.96;
    utterance.pitch = h.voicePitch || 1.02;
    utterance.onstart = () => setStatus(`${h.displayName || 'Celeste'} is speaking…`);
    utterance.onend = () => setStatus('Voice is available. Press the gold disc to speak.');
    utterance.onerror = () => setStatus('Audio reply could not play. The full reply is still shown on screen.');
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(utterance);
    return true;
  }

  window.CaelomereAvatar = Object.freeze({
    speak,
    pickApprovedVoice,
    setSpeaking,
    femaleVoiceAllowlist: Object.freeze([...FEMALE_EN_GB])
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildAvatarLayer, { once: true });
  } else {
    buildAvatarLayer();
  }
  installSpeechGuard();
})();
