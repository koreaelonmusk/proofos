/* ProofOS judge console.
 *
 * This file renders recorded evidence and nothing else. It makes no request to
 * any ProofOS service, never reaches a model, and has no code path that could
 * start an execution -- which is what lets the page survive an exhausted quota,
 * a cold start, or a hundred refreshes on a judging laptop.
 *
 * The replay animates real events in their recorded order. It does not invent
 * intermediate states, and every number on screen is read from the bundle.
 */
(function () {
  "use strict";

  var BUNDLE_URL = "proof-bundle.json";
  var STEP_MS = 260;

  var state = { bundle: null, scenario: "recovery", index: 0, timer: null };

  function $(id) { return document.getElementById(id); }

  function text(el, value) { if (el) el.textContent = value; }

  function reducedMotion() {
    return window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function current() { return state.bundle.scenarios[state.scenario]; }

  /* -- classification ---------------------------------------------------- */

  /* An event's visual weight follows what it meant, not how it was named.
     A verdict interrupts the chain; bookkeeping does not. */
  function classOf(ev) {
    if (ev.event === "VERIFIER_DECISION" || ev.event === "EXECUTION_COMPLETE" ||
        ev.event === "MODEL_NONCOMPLIANCE") {
      if (ev.status === "VERIFIED") return "is-decision is-verified";
      return "is-decision is-abstain";
    }
    if (ev.event === "CLAIM_RECEIVED") return "is-claim";
    if (ev.event === "ATTESTATION_ACCEPTED" || ev.event === "COLLECTION_REQUESTED" ||
        ev.event === "COLLECTOR_RESPONSE_RECEIVED") return "is-attest";
    return "";
  }

  function describe(ev) {
    var p = ev.payload || {};
    var bits = [];
    if (ev.agent) bits.push(ev.agent);
    if (p.tool) bits.push(p.tool);
    if (p.attempt) bits.push("attempt " + p.attempt);
    if (p.missing && p.missing.length) bits.push("missing " + p.missing.join(", "));
    if (p.failure && p.failure !== "NONE") bits.push(p.failure);
    if (p.kind) bits.push(p.kind);
    return bits.join("  ·  ");
  }

  /* -- timeline ---------------------------------------------------------- */

  function renderChain() {
    var list = $("chain");
    list.innerHTML = "";
    current().events.forEach(function (ev, i) {
      var li = document.createElement("li");
      li.className = "ev " + classOf(ev);
      if (i >= state.index) li.classList.add("is-pending");
      if (i === state.index - 1) li.classList.add("is-current");

      var line = document.createElement("div");
      line.className = "ev-line";

      var seq = document.createElement("span");
      seq.className = "ev-seq";
      seq.textContent = String(ev.sequence).padStart(2, "0");

      var name = document.createElement("span");
      name.className = "ev-name";
      name.textContent = ev.event + "  " + ev.status;

      line.appendChild(seq);
      line.appendChild(name);
      li.appendChild(line);

      var meta = describe(ev);
      if (meta) {
        var m = document.createElement("div");
        m.className = "ev-meta";
        m.textContent = meta;
        li.appendChild(m);
      }
      list.appendChild(li);
    });
    text($("progress"), state.index + " / " + current().events.length);
  }

  /* -- decision ---------------------------------------------------------- */

  /* The decision shown is the last verdict actually recorded at or before the
     current point. Before any verdict exists the panel says CLAIMED or waits;
     it never anticipates an outcome the run has not reached. */
  function decisionAt(i) {
    var seen = null;
    var events = current().events;
    for (var n = 0; n < i; n++) {
      var ev = events[n];
      if (ev.event === "CLAIM_RECEIVED") seen = { state: "CLAIMED", ev: ev };
      if (ev.event === "VERIFIER_DECISION")
        seen = { state: ev.status, ev: ev };
      if (ev.event === "MODEL_NONCOMPLIANCE")
        seen = { state: "ABSTAIN", ev: ev, noncompliance: true };
    }
    return seen;
  }

  var NOTES = {
    CLAIMED: "The executor states the work is done. Nothing has been checked yet, and " +
             "a claim is not a result.",
    ABSTAIN: "ProofOS refuses completion because the only runtime evidence was produced " +
             "by the agent making the claim.",
    VERIFIED: "Independent observation now satisfies the requirement. The verdict rests " +
              "on a signed observation from another service, not on the claim."
  };

  function renderDecision() {
    var panel = $("decision");
    var d = decisionAt(state.index);
    panel.className = "decision";

    if (!d) {
      panel.classList.add("is-claimed");
      text($("decision-state"), "—");
      text($("decision-sub"), state.index === 0 ? "awaiting replay" : "in progress");
      text($("decision-note"), "Press Replay to step through the recorded execution.");
      return;
    }

    var p = d.ev.payload || {};
    if (d.state === "VERIFIED") panel.classList.add("is-verified-state");
    else if (d.state === "ABSTAIN") panel.classList.add("is-abstain-state");
    else panel.classList.add("is-claimed");

    text($("decision-state"), d.state);

    var sub = d.noncompliance ? "MODEL_NONCOMPLIANCE"
      : (p.failure && p.failure !== "NONE") ? p.failure
      : d.state === "CLAIMED" ? "self-reported" : "requirements met";
    text($("decision-sub"), sub);

    var note = NOTES[d.state] || "";
    if (d.noncompliance) {
      note = "The verifier never called its tool, so there is no verdict to read. " +
             "ProofOS will not substitute the model's prose for one.";
    }
    text($("decision-note"), note);
  }

  /* -- evidence inspector ------------------------------------------------ */

  /* Integrity, trust and requirement are three separate questions and are
     rendered as three separate rows. Collapsing them is the defect this panel
     exists to correct: a sound self-report is still a refused one. */
  function facet(name, value) {
    var row = document.createElement("div");
    row.className = "facet";
    var n = document.createElement("span");
    n.className = "facet-name";
    n.textContent = name;
    var v = document.createElement("span");
    v.className = "facet-val " + (value ? "yes" : "no");
    v.textContent = value ? "YES" : "NO";
    row.appendChild(n);
    row.appendChild(v);
    return row;
  }

  function evidenceCard(item) {
    var card = document.createElement("div");
    card.className = "ev-card " + (item.satisfies_requirement ? "accepted" : "refused");

    var head = document.createElement("div");
    head.className = "ev-card-head";
    var title = document.createElement("div");
    title.className = "ev-card-title";
    title.textContent = item.kind + " evidence";
    var sub = document.createElement("div");
    sub.className = "ev-card-sub";
    sub.textContent = "source " + item.source + "  ·  producer " + item.collector;
    head.appendChild(title);
    head.appendChild(sub);

    var badge = document.createElement("span");
    badge.className = "badge " + (item.satisfies_requirement ? "badge-verified" : "badge-refused");
    badge.textContent = item.satisfies_requirement ? "Accepted" : "Refused";
    badge.style.marginTop = "0.5rem";
    head.appendChild(badge);

    var facets = document.createElement("div");
    facets.className = "facets";
    facets.appendChild(facet("Integrity valid", item.integrity_valid));
    facets.appendChild(facet("Accepted by verifier", item.accepted_by_verifier));
    facets.appendChild(facet("Satisfies requirement", item.satisfies_requirement));

    card.appendChild(head);
    card.appendChild(facets);

    if (item.rejection_reason) {
      var why = document.createElement("div");
      why.className = "reason";
      why.textContent = item.rejection_reason;
      card.appendChild(why);
    }
    return card;
  }

  /* Which evidence set applies depends on which attempt the replay has reached.
     Acceptance is a fact about a decision, not a property stamped on evidence,
     so the panel follows the attempt rather than showing one flat list. */
  function evidenceAt(i) {
    var s = current();
    var attempt = 0;
    for (var n = 0; n < i; n++) {
      var ev = s.events[n];
      var p = ev.payload || {};
      if (ev.event === "VERIFIER_DECISION" && p.attempt) attempt = p.attempt;
    }
    if (!attempt) return null;
    for (var a = 0; a < s.attempts.length; a++) {
      if (s.attempts[a].attempt === attempt) return s.attempts[a];
    }
    return null;
  }

  function renderEvidence() {
    var host = $("evidence");
    host.innerHTML = "";
    var attempt = evidenceAt(state.index);

    if (!attempt) {
      var empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = state.index === 0
        ? "No verification attempt has run yet."
        : "No verifier decision has been reached, so no evidence has been assessed.";
      host.appendChild(empty);
      return;
    }

    var head = document.createElement("div");
    head.className = "label";
    head.textContent = "As assessed at attempt " + attempt.attempt +
      "  ·  " + attempt.decision;
    host.appendChild(head);

    attempt.evidence.forEach(function (item) { host.appendChild(evidenceCard(item)); });
  }

  /* -- replay ------------------------------------------------------------ */

  function render() {
    renderChain();
    renderDecision();
    renderEvidence();
  }

  function stop() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    $("btn-play").textContent = "Replay";
  }

  function play() {
    stop();
    state.index = 0;
    render();
    if (reducedMotion()) { skipToEnd(); return; }
    $("btn-play").textContent = "Pause";
    state.timer = setInterval(function () {
      if (state.index >= current().events.length) { stop(); return; }
      state.index += 1;
      render();
    }, STEP_MS);
  }

  function skipToEnd() {
    stop();
    state.index = current().events.length;
    render();
  }

  /* -- static panels ----------------------------------------------------- */

  function renderProvenance() {
    var s = current();
    var p = s.provenance || {};
    var rows = [
      ["Execution", s.execution_id],
      ["Cloud Run revision", p.api_revision],
      ["Collector revision", p.collector_revision],
      ["Region", p.region],
      ["Source commit", p.source_commit],
      ["Model", s.model],
      ["Journal", s.counts.events + " events"],
      ["Chain", s.chain.chain_ok ? "intact" : "BROKEN"]
    ];
    var host = $("provenance");
    host.innerHTML = "";
    rows.forEach(function (row) {
      if (!row[1]) return;
      var cell = document.createElement("div");
      var dt = document.createElement("dt");
      dt.textContent = row[0];
      var dd = document.createElement("dd");
      dd.textContent = row[1];
      cell.appendChild(dt);
      cell.appendChild(dd);
      host.appendChild(cell);
    });
  }

  function renderScenarioHeader() {
    var s = current();
    text($("scenario-task"), s.task_id + "  —  “" + s.claim + "”");
  }

  function renderAttack() {
    var a = state.bundle.scenarios.adversarial;
    text($("attack-claim"), "“" + a.claim + "”");
    text($("attack-toolcalls"), String(a.counts.verify_tool_calls));
    text($("attack-final"), a.final_status);
    text($("attack-failure"), a.failure_class);
  }

  function renderArchitecture() {
    var p = state.bundle.scenarios.recovery.provenance;
    var obs = state.bundle.scenarios.recovery.cross_service_observation || {};
    text($("arch-api"), [p.api_revision, p.api_service_account].filter(Boolean).join("  ·  "));
    text($("arch-collector"),
      [p.collector_revision, p.collector_service_account].filter(Boolean).join("  ·  "));
    text($("arch-observe"),
      ["anonymous " + (obs.anonymous_probe || "denied"),
       "authenticated " + (obs.authenticated_probe || "allowed")].join("  ·  "));
  }

  function renderBounds() {
    var host = $("bounds");
    host.innerHTML = "";
    (state.bundle.project.known_limitations || []).forEach(function (line, i) {
      var box = document.createElement("div");
      box.className = "bound";
      var h = document.createElement("h3");
      h.textContent = "Boundary " + String(i + 1).padStart(2, "0");
      var p = document.createElement("p");
      p.textContent = line;
      box.appendChild(h);
      box.appendChild(p);
      host.appendChild(box);
    });
  }

  function renderFooter() {
    var b = state.bundle;
    var r = b.scenarios.recovery;
    text($("footer-meta"),
      b.project.test_count + " tests  ·  " + r.provenance.api_revision +
      "  ·  chain " + (r.chain.chain_ok ? "intact" : "broken"));
  }

  function renderHero() {
    text($("hero-claim"), "“" + state.bundle.scenarios.recovery.claim + "”");
  }

  /* -- wiring ------------------------------------------------------------ */

  function selectScenario(name) {
    state.scenario = name;
    stop();
    state.index = 0;
    document.querySelectorAll(".tab").forEach(function (tab) {
      var on = tab.dataset.scenario === name;
      tab.setAttribute("aria-selected", on ? "true" : "false");
    });
    $("console-panels").setAttribute("aria-labelledby", "tab-" + name);
    renderProvenance();
    renderScenarioHeader();
    render();
  }

  function wire() {
    document.querySelectorAll(".tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        selectScenario(tab.dataset.scenario);
      });
    });
    $("btn-play").addEventListener("click", function () {
      if (state.timer) { stop(); } else { play(); }
    });
    $("btn-end").addEventListener("click", skipToEnd);
    document.querySelector('[data-action="replay"]').addEventListener("click", function () {
      selectScenario("recovery");
      window.setTimeout(play, 120);
    });
  }

  function boot(bundle) {
    state.bundle = bundle;
    renderHero();
    renderAttack();
    renderArchitecture();
    renderBounds();
    renderFooter();
    selectScenario("recovery");
    wire();
  }

  if (window.PROOFOS_BUNDLE) {
    boot(window.PROOFOS_BUNDLE);
  } else {
    fetch(BUNDLE_URL)
      .then(function (r) {
        if (!r.ok) throw new Error("bundle " + r.status);
        return r.json();
      })
      .then(boot)
      .catch(function (err) {
        var panel = $("decision");
        if (panel) {
          text($("decision-state"), "NO DATA");
          text($("decision-sub"), "bundle unavailable");
          text($("decision-note"),
            "The recorded evidence could not be loaded (" + err.message +
            "). This page renders nothing it cannot read from a bundle, so it " +
            "shows nothing rather than something invented.");
        }
      });
  }
})();
