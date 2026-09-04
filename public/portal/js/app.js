(function () {
  const spokenLine = document.getElementById("spokenLine");
  const form = document.getElementById("requestForm");
  const input = document.getElementById("requestInput");
  const voiceBtn = document.getElementById("voiceBtn");
  const voiceStatus = document.getElementById("voiceStatus");
  const workspace = document.getElementById("workspace");
  const workspaceTitle = document.getElementById("workspaceTitle");
  const workspaceLede = document.getElementById("workspaceLede");
  const workspaceBody = document.getElementById("workspaceBody");
  const workspaceKicker = document.getElementById("workspaceKicker");
  const hostPortrait = document.getElementById("hostPortrait");
  const hostNameEl = document.getElementById("hostName");
  const presentationToggle = document.getElementById("presentationToggle");
  const presentationPanel = document.getElementById("presentationPanel");
  const hostList = document.getElementById("hostList");
  const celesteRoot = document.getElementById("celeste");

  const presentation = window.CaelomerePresentation;
  let host = presentation.current();
  let sessionUser = null;
  let sessionState = "unknown";

  function partOfDay() {
    const hour = new Date().getHours();
    return hour < 12 ? "morning" : hour < 18 ? "afternoon" : "evening";
  }

  function greetingFor(h) {
    const given = String(sessionUser?.user?.name || "").trim().split(/\s+/)[0];
    const ask = given
      ? `What would you like us to work on today, ${given}?`
      : `What would you like us to work on today?`;
    return `Good ${partOfDay()}. I’m ${h.spokenName}.\n${ask}`;
  }

  function applyHost(h, announce) {
    host = h;
    hostPortrait.src = h.portrait;
    hostPortrait.alt = h.displayName;
    hostNameEl.textContent = h.displayName;
    celesteRoot.setAttribute("aria-label", h.displayName);
    if (workspaceKicker) workspaceKicker.textContent = h.displayName;
    input.placeholder = window.innerWidth < 820
      ? `Type a request…`
      : `Speak with ${h.displayName}, or type a request…`;
    voiceBtn.title = `Speak with ${h.displayName}`;
    document.querySelector('label[for="requestInput"]').textContent =
      `Speak or type a request for ${h.displayName}`;
    if (recognition) recognition.lang = h.locale || "en-GB";
    document.querySelectorAll(".host-option").forEach((btn) => {
      btn.setAttribute("aria-pressed", btn.dataset.hostId === h.id ? "true" : "false");
    });
    spokenLine.innerHTML = greetingFor(h).replace("\n", "<br>");
    if (announce) setLine(greetingFor(h), true);
  }

  const workspaces = {
    social: {
      title: "Social Media",
      lede: "Nothing leaves in the organisation’s name until you have seen it.",
      reply: () => `Of course.\nI’ll keep this beside us.`,
      html: `
        <div class="passage">
          <p>Thursday’s note on the new service window is ready for your eye.</p>
          <p>Friday’s client story is waiting on the photograph you approved.</p>
          <p>Next week is only a placeholder. Nothing is scheduled to leave.</p>
        </div>
        <p class="passage__quiet">LinkedIn · Instagram · the company page — demonstration only.</p>`
    },
    crm: {
      title: "Commercial Command",
      lede: "The conversations that actually need a person.",
      reply: () => `I’ll bring the commercial workspace forward.`,
      html: `
        <div class="passage">
          <p class="passage__label">Quiet for three days</p>
          <p>Northridge Holdings — quotation in review.</p>
          <p>Ellesmere Clinic — introductory call arranged.</p>
        </div>`
    },
    calendar: {
      title: "Calendar",
      lede: "What the day actually holds.",
      reply: () => `Here is the calendar. I’ll keep it beside us.`,
      html: `
        <div class="passage">
          <p>11:00 briefing. 14:30 client call. Nothing else is locked.</p>
        </div>`
    },
    documents: {
      title: "Documents",
      lede: "Papers kept in one calm place.",
      reply: () => `I’ve opened Documents. Tell me which paper you need.`,
      html: `
        <div class="passage">
          <p>Engagement letter. Terms pack. Board note. Demonstration files only.</p>
        </div>`
    },
    legal: {
      title: "Legal",
      lede: "Surrounding work. Judgment remains yours.",
      reply: () => `Legal is open.`,
      html: `
        <div class="passage">
          <p>Two files have a deadline inside ten days. Demonstration data.</p>
        </div>`
    },
    accounting: {
      title: "Accounting",
      lede: "Numbers connected to the work that created them.",
      reply: () => `I’ll open Accounting. Payments still wait for a person.`,
      html: `
        <div class="passage">
          <p>Four invoices are overdue in this demonstration set.</p>
        </div>`
    },
    studio: {
      title: "Studio",
      lede: "Visual and narrative work, kept continuous.",
      reply: () => `Studio is ready. What would you like to shape?`,
      html: `
        <div class="passage">
          <p>One presentation and a short film treatment — mock items only.</p>
        </div>`
    },
    reception: {
      title: "Reception",
      lede: "What arrived, and what has not yet been promised.",
      reply: () => `Reception is with us.`,
      html: `
        <div class="passage">
          <p>Three enquiries held for review this morning.</p>
        </div>`
    }
  };

  function matchWorkspace(text) {
    const t = text.toLowerCase();
    if (/social|instagram|linkedin|post|content calendar/.test(t)) return "social";
    if (/crm|sales|pipeline|lead|customer|client list/.test(t)) return "crm";
    if (/calendar|diary|schedule|appointment|meeting/.test(t)) return "calendar";
    if (/document|paper|letter|file|admin/.test(t)) return "documents";
    if (/legal|solicitor|contract|matter/.test(t)) return "legal";
    if (/account|invoice|bookkeep|finance|vat/.test(t)) return "accounting";
    if (/studio|visual|video|presentation|design/.test(t)) return "studio";
    if (/reception|secretary|front desk|call|phone/.test(t)) return "reception";
    if (/home|back|close|thank you|thanks|that's all|thats all/.test(t)) return "home";
    return null;
  }

  function pickVoice(h) {
    const voices = window.speechSynthesis ? window.speechSynthesis.getVoices() : [];
    const hints = (h.voiceHints || []).map((s) => s.toLowerCase());
    return (
      voices.find((v) => hints.some((hint) => v.name.toLowerCase().includes(hint) || v.lang.toLowerCase().includes(h.locale.toLowerCase()))) ||
      voices[0] ||
      null
    );
  }

  function speak(text) {
    if (!window.speechSynthesis) return;
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(text);
    u.rate = host.voiceRate || 0.96;
    u.pitch = host.voicePitch || 1;
    u.lang = host.locale || "en-GB";
    const voice = pickVoice(host);
    if (voice) u.voice = voice;
    window.speechSynthesis.speak(u);
  }

  function setLine(text, withVoice) {
    spokenLine.style.opacity = "0";
    setTimeout(() => {
      spokenLine.innerHTML = String(text).replace("\n", "<br>");
      spokenLine.style.opacity = "1";
    }, 220);
    if (withVoice) speak(text);
  }

  spokenLine.style.transition = "opacity .35s ease";

  function openWorkspace(key) {
    const ws = workspaces[key];
    if (!ws) return;
    workspace.hidden = false;
    workspaceTitle.textContent = ws.title;
    workspaceLede.textContent = ws.lede;
    workspaceBody.innerHTML = ws.html;
    workspaceKicker.textContent = host.displayName;
    requestAnimationFrame(() => document.body.classList.add("is-open"));
    setLine(ws.reply(), true);
  }

  function closeWorkspace() {
    document.body.classList.remove("is-open");
    setLine(`I’m here. What would you like us to work on?`, true);
    setTimeout(() => {
      if (!document.body.classList.contains("is-open")) {
        workspace.hidden = true;
        workspaceBody.innerHTML = "";
      }
    }, 900);
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function passagesFromReply(reply) {
    const parts = String(reply || "")
      .split(/\n{2,}/)
      .map((part) => part.trim())
      .filter(Boolean);
    if (!parts.length) return "<p>I have the workspace here. Tell me what needs attention.</p>";
    return parts
      .map((part) => `<p>${escapeHtml(part).replace(/\n/g, "<br>")}</p>`)
      .join("");
  }

  async function askSocialAdvisory(utterance) {
    if (sessionState !== "verified" || !sessionUser) return null;
    const response = await fetch("/api/ai/social", {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ message: utterance })
    });
    if (response.status === 401) {
      window.location.replace("/");
      return null;
    }
    if (!response.ok) throw new Error("advisory_unavailable");
    const data = await response.json();
    return String(data.reply || "").trim();
  }

  async function openSocialAdvisory(utterance) {
    const spoken = utterance || "Help me with social media.";
    workspace.hidden = false;
    workspaceTitle.textContent = "Social Media";
    workspaceLede.textContent = "Nothing leaves in the organisation’s name until you have seen it.";
    workspaceKicker.textContent = host.displayName;
    workspaceBody.innerHTML = '<div class="passage"><p>A moment.</p></div>';
    requestAnimationFrame(() => document.body.classList.add("is-open"));
    setLine("Of course.\nI’ll keep this beside us.", true);
    try {
      const reply = await askSocialAdvisory(spoken);
      if (reply == null) return;
      if (!reply) {
        workspaceBody.innerHTML =
          '<div class="passage"><p>I have the workspace here. Tell me what you would like to look at first.</p></div>';
        return;
      }
      workspaceBody.innerHTML = `<div class="passage">${passagesFromReply(reply)}</div>`;
    } catch (_) {
      setLine(
        "I have Social Media beside us, but I could not reach the advisory service just now. You can type again when you are ready.",
        true
      );
      workspaceBody.innerHTML =
        '<div class="passage"><p>The advisory reply is not available at this moment. Nothing has been published.</p></div>';
    }
  }

  async function handleRequest(raw) {
    if (sessionState !== "verified") {
      const session = await loadSession();
      if (!session) return;
    }
    const text = (raw || "").trim();
    if (!text) return;
    const key = matchWorkspace(text);
    if (key === "home") {
      closeWorkspace();
      return;
    }
    if (key === "social") {
      await openSocialAdvisory(text);
      return;
    }
    if (key) {
      openWorkspace(key);
      return;
    }
    setLine(
      `I can open Social Media, the commercial workspace, Calendar, Documents, Legal, Accounting, Studio or Reception. Tell me which you’d like, or say you’d like to return here.`,
      true
    );
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const value = input.value;
    input.value = "";
    handleRequest(value);
  });

  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  let recognition = null;
  let listening = false;

  if (SpeechRecognition) {
    recognition = new SpeechRecognition();
    recognition.lang = host.locale || "en-GB";
    recognition.interimResults = false;
    recognition.continuous = false;

    recognition.onstart = () => {
      listening = true;
      voiceBtn.classList.add("is-listening");
      voiceBtn.setAttribute("aria-pressed", "true");
      voiceStatus.textContent = "Listening…";
    };
    recognition.onend = () => {
      listening = false;
      voiceBtn.classList.remove("is-listening");
      voiceBtn.setAttribute("aria-pressed", "false");
      voiceStatus.textContent = "Voice is available. Press the gold disc to speak.";
    };
    recognition.onerror = () => {
      voiceStatus.textContent = "Voice could not start in this browser. You can still type.";
    };
    recognition.onresult = (event) => {
      const transcript = event.results[0][0].transcript;
      input.value = transcript;
      handleRequest(transcript);
    };
  } else {
    voiceBtn.classList.add("is-unavailable");
    voiceBtn.setAttribute("aria-disabled", "true");
    voiceBtn.title = "Voice is not available in this browser";
    voiceStatus.textContent = "Voice is not available here. Type a request instead.";
  }

  voiceBtn.addEventListener("click", () => {
    if (!recognition) {
      voiceStatus.textContent = "Voice is not available here. Type a request instead.";
      input.focus();
      return;
    }
    if (listening) {
      recognition.stop();
      return;
    }
    try {
      recognition.start();
    } catch (_) {
      voiceStatus.textContent = "Voice is already starting. Try again in a moment.";
    }
  });

  presentation.catalog.hosts.forEach((h) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "host-option";
    btn.dataset.hostId = h.id;
    btn.textContent = h.displayName;
    btn.addEventListener("click", () => {
      applyHost(presentation.setHost(h.id), true);
      presentationPanel.hidden = true;
    });
    hostList.appendChild(btn);
  });

  presentationToggle.addEventListener("click", () => {
    presentationPanel.hidden = !presentationPanel.hidden;
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && presentationPanel && !presentationPanel.hidden) {
      presentationPanel.hidden = true;
      presentationToggle.focus();
    }
  });

  window.speechSynthesis?.getVoices();
  if (window.speechSynthesis) {
    window.speechSynthesis.onvoiceschanged = () => {};
  }

  function gateComposer(verified) {
    input.disabled = false;
    input.removeAttribute("aria-disabled");
    if (form) form.dataset.sessionState = verified ? "verified" : "unknown";
    if (voiceBtn) {
      voiceBtn.toggleAttribute("disabled", !verified);
    }
  }

  async function loadSession() {
    try {
      const response = await fetch("/api/me", {
        credentials: "include",
        headers: { accept: "application/json" }
      });
      if (!response.ok) throw new Error("session");
      const data = await response.json();
      if (!data || data.authenticated !== true) {
        sessionState = "unauthenticated";
        sessionUser = null;
        window.location.replace("/");
        return null;
      }
      sessionState = "verified";
      sessionUser = data;
      gateComposer(true);
      return data;
    } catch (_) {
      sessionState = "unknown";
      sessionUser = null;
      gateComposer(false);
      setLine(
        "I can’t verify your CAELOMERE session just now. Please try again.",
        false
      );
      return null;
    }
  }

  applyHost(host, false);
  gateComposer(false);

  loadSession().then((session) => {
    if (session) {
      spokenLine.innerHTML = greetingFor(host).replace("\n", "<br>");
      setTimeout(() => speak(greetingFor(host)), 700);
    }
    if (/social/i.test(location.hash) && sessionState === "verified") {
      setTimeout(() => openSocialAdvisory("Help me with social media."), 200);
    }
  });
})();
