(function (global) {
  const STORAGE_KEY = "caelomere.presentation.hostId";

  const catalog = {
    layer: "presentation",
    intelligence: "CAELOMERE",
    defaultHostId: "celeste",
    hosts: [
      {
        id: "celeste",
        displayName: "Celeste",
        spokenName: "Celeste",
        pronouns: "she",
        presentation: "female",
        locale: "en-GB",
        voiceHints: ["female", "samantha", "victoria", "serena", "google uk english female"],
        voicePitch: 1.02,
        voiceRate: 0.96,
        portrait: "assets/hosts/celeste.jpg"
      },
      {
        id: "cassian",
        displayName: "Cassian",
        spokenName: "Cassian",
        pronouns: "he",
        presentation: "male",
        locale: "en-GB",
        voiceHints: ["male", "daniel", "google uk english male", "alex", "david"],
        voicePitch: 0.92,
        voiceRate: 0.95,
        portrait: "assets/hosts/cassian.jpg"
      },
      {
        id: "lin",
        displayName: "Lin",
        spokenName: "Lin",
        pronouns: "she",
        presentation: "female",
        locale: "en-GB",
        voiceHints: ["female", "karen", "moira", "google uk english female", "samantha"],
        voicePitch: 1.0,
        voiceRate: 0.95,
        portrait: "assets/hosts/lin.jpg"
      }
    ]
  };

  function byId(id) {
    return catalog.hosts.find((h) => h.id === id) || catalog.hosts[0];
  }

  function readQueryHost() {
    const q = new URLSearchParams(location.search).get("host");
    return q ? q.toLowerCase() : null;
  }

  function currentId() {
    return readQueryHost() || localStorage.getItem(STORAGE_KEY) || catalog.defaultHostId;
  }

  function setHost(id) {
    const host = byId(id);
    localStorage.setItem(STORAGE_KEY, host.id);
    return host;
  }

  global.CaelomerePresentation = {
    catalog,
    byId,
    currentId,
    setHost,
    current() {
      return byId(currentId());
    }
  };
})(window);
