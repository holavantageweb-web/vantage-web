(function () {
  "use strict";

  function safe(fn, name) {
    try { fn(); } catch (e) { console.warn("[" + name + "]", e); }
  }

  function initNav() {
    const nav = document.querySelector("[data-nav]");
    if (!nav) return;
    const update = () => nav.classList.toggle("is-scrolled", window.scrollY > 40);
    update();
    window.addEventListener("scroll", update, { passive: true });
  }

  function initMobileMenu() {
    const burger = document.querySelector("[data-nav-burger]");
    const menu = document.querySelector("[data-nav-mobile]");
    if (!burger || !menu) return;

    const close = () => {
      menu.dataset.open = "false";
      menu.setAttribute("aria-hidden", "true");
      burger.setAttribute("aria-expanded", "false");
      burger.textContent = "Menú";
      document.body.style.overflow = "";
    };
    const open = () => {
      menu.dataset.open = "true";
      menu.setAttribute("aria-hidden", "false");
      burger.setAttribute("aria-expanded", "true");
      burger.textContent = "Cerrar";
      document.body.style.overflow = "hidden";
    };

    burger.addEventListener("click", () => {
      if (menu.dataset.open === "true") close(); else open();
    });
    menu.querySelectorAll("a").forEach(a => a.addEventListener("click", close));
  }

  const INTEREST_LABELS = {
    "web": "Una página web",
    "nfc": "Tarjetas NFC",
    "web-nfc": "Web + tarjetas NFC",
    "aun-no": "Aún no lo sé"
  };

  function initContactForm() {
    const form = document.querySelector("[data-contact-form]");
    if (!form) return;
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = form.querySelector("#contact-name").value.trim();
      const email = form.querySelector("#contact-email").value.trim();
      const interestEl = form.querySelector("#contact-interest");
      const interest = interestEl ? INTEREST_LABELS[interestEl.value] || "" : "";
      const message = form.querySelector("#contact-message").value.trim();
      const subject = "Consulta VANTAGE" + (interest ? " (" + interest + ")" : "") + " — " + name;
      const body = "Nombre: " + name + "\nEmail: " + email +
        (interest ? "\nMe interesa: " + interest : "") + "\n\n" + message;
      const mailto =
        "mailto:hola.vantageweb@gmail.com" +
        "?subject=" + encodeURIComponent(subject) +
        "&body=" + encodeURIComponent(body);
      window.location.href = mailto;
    });
  }

  function initInterestLinks() {
    const select = document.querySelector("#contact-interest");
    if (!select) return;
    document.querySelectorAll("[data-interest]").forEach(link => {
      link.addEventListener("click", () => {
        const value = link.getAttribute("data-interest");
        if (INTEREST_LABELS[value]) select.value = value;
      });
    });
  }

  function initCookieBanner() {
    const banner = document.querySelector("[data-cookie-banner]");
    if (!banner) return;
    const STORAGE_KEY = "vantage-cookie-notice-seen";

    let alreadySeen = false;
    try { alreadySeen = !!localStorage.getItem(STORAGE_KEY); } catch (e) {}

    if (!alreadySeen) {
      banner.hidden = false;
      document.body.classList.add("has-cookie-banner");
    }

    const btn = banner.querySelector("[data-cookie-accept]");
    if (btn) {
      btn.addEventListener("click", () => {
        try { localStorage.setItem(STORAGE_KEY, "1"); } catch (e) {}
        banner.hidden = true;
        document.body.classList.remove("has-cookie-banner");
      });
    }
  }

  function initReveals() {
    const els = document.querySelectorAll("[data-reveal]");
    if (!els.length) return;
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add("is-revealed");
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.01, rootMargin: "0px 0px -2% 0px" });
    els.forEach(el => io.observe(el));

    setTimeout(() => {
      document.querySelectorAll("[data-reveal]:not(.is-revealed)").forEach(el => {
        if (el.getBoundingClientRect().top < window.innerHeight) {
          el.classList.add("is-revealed");
        }
      });
    }, 6000);
  }

  function boot() {
    safe(initNav, "initNav");
    safe(initMobileMenu, "initMobileMenu");
    safe(initContactForm, "initContactForm");
    safe(initInterestLinks, "initInterestLinks");
    safe(initCookieBanner, "initCookieBanner");
    safe(initReveals, "initReveals");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
