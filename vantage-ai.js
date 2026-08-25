(function () {
  "use strict";

  const METRIC_LABELS = {
    claridad: "Claridad",
    confianza: "Confianza",
    conversion: "Conversión",
    experienciaMovil: "Experiencia móvil",
  };
  const METRIC_ORDER = ["claridad", "confianza", "conversion", "experienciaMovil"];

  const escHTML = (s) =>
    String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  function initVantageAI() {
    const form = document.querySelector("[data-ai-form]");
    if (!form) return;

    const input = document.querySelector("[data-ai-input]");
    const statusEl = document.querySelector("[data-ai-status]");
    const statusItems = statusEl ? Array.from(statusEl.querySelectorAll("li")) : [];
    const errorEl = document.querySelector("[data-ai-error]");
    const resultEl = document.querySelector("[data-ai-result]");
    const metricsEl = document.querySelector("[data-ai-metrics]");
    const opportunityEl = document.querySelector("[data-ai-opportunity]");
    const prioritiesEl = document.querySelector("[data-ai-priorities]");
    const submitBtn = form.querySelector('button[type="submit"]');

    let stepTimer = null;

    function resetView() {
      errorEl.hidden = true;
      errorEl.textContent = "";
      resultEl.hidden = true;
      resultEl.classList.remove("is-visible");
      metricsEl.innerHTML = "";
      prioritiesEl.innerHTML = "";
      opportunityEl.textContent = "";
    }

    function startStatusSteps() {
      statusEl.hidden = false;
      statusItems.forEach((li) => li.classList.remove("is-done"));
      let i = 0;
      stepTimer = setInterval(() => {
        if (i < statusItems.length) {
          statusItems[i].classList.add("is-done");
          i++;
        } else {
          clearInterval(stepTimer);
        }
      }, 600);
    }

    function stopStatusSteps() {
      if (stepTimer) clearInterval(stepTimer);
      statusEl.hidden = true;
    }

    function renderMetric(key, metric) {
      const wrap = document.createElement("div");
      wrap.className = "ai-metric";
      const label = METRIC_LABELS[key] || key;

      if (metric && metric.evaluated && typeof metric.score === "number") {
        const pct = Math.max(0, Math.min(100, metric.score * 10));
        wrap.innerHTML =
          '<div class="ai-metric-head"><h4>' + escHTML(label) + '</h4>' +
          '<span class="ai-metric-score">' + metric.score + "/10 · " + escHTML(metric.level || "") + "</span></div>" +
          '<div class="ai-metric-bar"><span style="width:0%"></span></div>' +
          '<p class="ai-metric-text">' + escHTML(metric.explanation) + "</p>";
        const fill = wrap.querySelector(".ai-metric-bar span");
        requestAnimationFrame(() => {
          requestAnimationFrame(() => { fill.style.width = pct + "%"; });
        });
      } else {
        wrap.innerHTML =
          '<div class="ai-metric-head"><h4>' + escHTML(label) + '</h4>' +
          '<span class="ai-metric-score ai-metric-score--na">No evaluable</span></div>' +
          '<p class="ai-metric-text">' + escHTML((metric && metric.explanation) || "No se ha podido evaluar esta área.") + "</p>";
      }
      return wrap;
    }

    function renderResult(data) {
      const safe = data && typeof data === "object" ? data : {};
      const metrics = safe.metrics && typeof safe.metrics === "object" ? safe.metrics : {};
      const prioridades = Array.isArray(safe.prioridades) ? safe.prioridades : [];

      metricsEl.innerHTML = "";
      METRIC_ORDER.forEach((key) => {
        metricsEl.appendChild(renderMetric(key, metrics[key]));
      });

      opportunityEl.textContent = typeof safe.principalOportunidad === "string" ? safe.principalOportunidad : "";

      prioritiesEl.innerHTML = "";
      prioridades.slice(0, 3).forEach((p, i) => {
        const item = p && typeof p === "object" ? p : {};
        const area = typeof item.area === "string" ? item.area : "";
        const explicacion = typeof item.explicacion === "string" ? item.explicacion : "";
        if (!area && !explicacion) return;
        const li = document.createElement("li");
        li.innerHTML =
          '<span class="ai-priority-num">0' + (i + 1) + "</span>" +
          '<div><h4>' + escHTML(area) + "</h4><p>" + escHTML(explicacion) + "</p></div>";
        prioritiesEl.appendChild(li);
      });

      resultEl.hidden = false;
      requestAnimationFrame(() => resultEl.classList.add("is-visible"));
      resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    function showError(message) {
      errorEl.textContent = message;
      errorEl.hidden = false;
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      const url = (input.value || "").trim();
      if (!url) return;

      resetView();
      submitBtn.disabled = true;
      startStatusSteps();

      try {
        const res = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: url }),
        });
        let data = null;
        try { data = await res.json(); } catch (_) {}

        stopStatusSteps();

        if (!res.ok || !data || data.error) {
          showError((data && data.error) || "No hemos podido analizar esta web ahora mismo. Prueba de nuevo en unos segundos.");
          return;
        }
        try {
          renderResult(data);
        } catch (renderErr) {
          console.warn("[vantageAI] render error", renderErr);
          resultEl.hidden = true;
          showError("Hemos recibido una respuesta inesperada. Prueba de nuevo en unos segundos.");
        }
      } catch (err) {
        stopStatusSteps();
        showError("No hemos podido analizar esta web ahora mismo. Comprueba tu conexión e inténtalo de nuevo.");
        console.warn("[vantageAI]", err);
      } finally {
        submitBtn.disabled = false;
      }
    });
  }

  function boot() {
    try { initVantageAI(); } catch (e) { console.warn("[vantageAI]", e); }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
