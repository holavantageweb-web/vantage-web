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

  function initContactForm() {
    const form = document.querySelector("[data-contact-form]");
    if (!form) return;
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = form.querySelector("#contact-name").value.trim();
      const email = form.querySelector("#contact-email").value.trim();
      const message = form.querySelector("#contact-message").value.trim();
      const subject = "Proyecto web — " + name;
      const body = "Nombre: " + name + "\nEmail: " + email + "\n\n" + message;
      const mailto =
        "mailto:hola.vantageweb@gmail.com" +
        "?subject=" + encodeURIComponent(subject) +
        "&body=" + encodeURIComponent(body);
      window.location.href = mailto;
    });
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
    safe(initReveals, "initReveals");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
