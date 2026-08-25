import * as cheerio from "cheerio";
import { z } from "zod";
import dns from "node:dns";

// VANTAGE CHECK no llama a ningún proveedor de IA externo. El diagnóstico
// se calcula con reglas deterministas sobre las señales reales extraídas
// de la página (ver buildDiagnosis más abajo) — cero coste, cero API keys.

// Vercel deploys any file in /api to the Node.js runtime by default —
// no config export needed. package.json has "type": "module", so this
// file uses ESM `export default` (Vercel supports this handler style
// alongside the newer Web Handler `fetch`/`GET`/`POST` export style).

const FETCH_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 1.5 * 1024 * 1024; // 1.5MB
const MAX_TEXT_CHARS = 6000;
const MAX_REDIRECTS = 5;

// Usado para validar nuestra propia respuesta antes de enviarla al frontend
// (protege contra un bug de programación que produzca una forma inesperada,
// no contra una IA — aquí no hay ninguna).
const MetricSchema = z.object({
  evaluated: z.boolean(),
  score: z.number().int().min(0).max(10).nullable(),
  explanation: z.string().min(1),
});

const DiagnosisSchema = z.object({
  metrics: z.object({
    claridad: MetricSchema,
    confianza: MetricSchema,
    conversion: MetricSchema,
    experienciaMovil: MetricSchema,
  }),
  principalOportunidad: z.string().min(1),
  prioridades: z
    .array(
      z.object({
        area: z.string().min(1),
        explicacion: z.string().min(1),
      }),
    )
    .length(3),
});

// --- SSRF protection -------------------------------------------------
// Numeric range checks operate on raw address bytes (never on the
// original text), so decimal/octal/hex-obfuscated IPs and IPv4-mapped
// IPv6 addresses are all normalized away before the check runs.

function parseIPv4Bytes(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const bytes = m.slice(1, 5).map(Number);
  if (bytes.some((b) => b > 255)) return null;
  return bytes;
}

function parseIPv6Bytes(ip) {
  const addr = ip.split("%")[0]; // strip zone id (fe80::1%eth0)
  const halves = addr.split("::");
  if (halves.length > 2) return null;

  const parseGroups = (s) => (s === "" ? [] : s.split(":"));
  const head = parseGroups(halves[0]);
  const tail = halves.length === 2 ? parseGroups(halves[1]) : [];

  // Embedded IPv4 tail (e.g. ::ffff:192.168.1.1) counts as 2 groups.
  let ipv4Tail = null;
  const lastGroupHolder = tail.length ? tail : head;
  const lastGroup = lastGroupHolder[lastGroupHolder.length - 1];
  if (lastGroup && lastGroup.includes(".")) {
    ipv4Tail = parseIPv4Bytes(lastGroup);
    if (!ipv4Tail) return null;
    lastGroupHolder.pop();
  }

  const ipv4GroupCount = ipv4Tail ? 2 : 0;
  const totalGroups = head.length + tail.length + ipv4GroupCount;
  if (halves.length === 1) {
    if (totalGroups !== 8) return null;
  } else if (totalGroups > 8) {
    return null;
  }
  const missing = 8 - totalGroups;
  const groups = halves.length === 2 ? [...head, ...Array(missing).fill("0"), ...tail] : head;

  const bytes = [];
  for (const g of groups) {
    if (g === "") return null;
    const val = parseInt(g, 16);
    if (Number.isNaN(val) || val < 0 || val > 0xffff || !/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    bytes.push((val >> 8) & 0xff, val & 0xff);
  }
  if (ipv4Tail) bytes.push(...ipv4Tail);
  return bytes.length === 16 ? bytes : null;
}

function bytesInPrefix(bytes, prefixBytes, prefixBits) {
  const fullBytes = Math.floor(prefixBits / 8);
  const remBits = prefixBits % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (bytes[i] !== prefixBytes[i]) return false;
  }
  if (remBits > 0) {
    const mask = (0xff << (8 - remBits)) & 0xff;
    if ((bytes[fullBytes] & mask) !== (prefixBytes[fullBytes] & mask)) return false;
  }
  return true;
}

const BLOCKED_IPV4_RANGES = [
  "0.0.0.0/8", // this network
  "10.0.0.0/8", // private
  "100.64.0.0/10", // carrier-grade NAT
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local (incl. cloud metadata 169.254.169.254)
  "172.16.0.0/12", // private
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // documentation (TEST-NET-1)
  "192.168.0.0/16", // private
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // documentation (TEST-NET-2)
  "203.0.113.0/24", // documentation (TEST-NET-3)
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved
  "255.255.255.255/32", // broadcast
].map((cidr) => {
  const [base, bits] = cidr.split("/");
  return { bytes: parseIPv4Bytes(base), bits: Number(bits) };
});

const BLOCKED_IPV6_RANGES = [
  "::1/128", // loopback
  "::/128", // unspecified
  "64:ff9b::/96", // NAT64 (embeds IPv4 — checked separately below too)
  "100::/64", // discard-only
  "fc00::/7", // unique local (private)
  "fe80::/10", // link-local
  "ff00::/8", // multicast
  "2001:db8::/32", // documentation
].map((cidr) => {
  const [base, bits] = cidr.split("/");
  return { bytes: parseIPv6Bytes(base), bits: Number(bits) };
});

function isBlockedIPv4Bytes(bytes) {
  if (!bytes) return true; // couldn't parse -> fail closed
  return BLOCKED_IPV4_RANGES.some((r) => r.bytes && bytesInPrefix(bytes, r.bytes, r.bits));
}

function isBlockedIPv6Bytes(bytes) {
  if (!bytes) return true; // fail closed
  if (BLOCKED_IPV6_RANGES.some((r) => r.bytes && bytesInPrefix(bytes, r.bytes, r.bits))) return true;
  // IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d) addresses:
  // check the embedded IPv4 too, at the byte level (catches every textual
  // representation, not just the dotted-quad form).
  const isMapped = bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  const isCompatible = bytes.slice(0, 12).every((b) => b === 0);
  if (isMapped || isCompatible) return isBlockedIPv4Bytes(bytes.slice(12, 16));
  return false;
}

function isBlockedAddress(address, family) {
  if (family === 4) return isBlockedIPv4Bytes(parseIPv4Bytes(address));
  if (family === 6) return isBlockedIPv6Bytes(parseIPv6Bytes(address));
  return true; // unknown family -> fail closed
}

async function assertPublicHostname(hostname) {
  let records;
  try {
    records = await dns.promises.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error("No se ha podido resolver esa dirección.");
  }
  if (!records.length) throw new Error("No se ha podido resolver esa dirección.");
  for (const { address, family } of records) {
    if (isBlockedAddress(address, family)) {
      throw new Error("Esa dirección no se puede analizar.");
    }
  }
}

function normalizeUrl(raw) {
  let candidate = String(raw || "").trim();
  if (!candidate) return null;
  if (!/^https?:\/\//i.test(candidate)) candidate = "https://" + candidate;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  if (!parsed.hostname) return null;
  return parsed;
}

// Resolves + validates a URL's hostname, throwing a user-safe message if
// it points at a private/loopback/link-local/multicast/reserved address.
async function validateUrlIsPublic(parsed) {
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  await assertPublicHostname(hostname);
}

async function fetchHtml(initialUrl) {
  let current = initialUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await validateUrlIsPublic(current);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(current.toString(), {
        signal: controller.signal,
        redirect: "manual", // never follow a redirect without re-validating it first
        headers: {
          "User-Agent": "VANTAGE-AI-Analyzer/1.0 (+https://vantage.example; website audit tool)",
          Accept: "text/html,application/xhtml+xml",
        },
      });
    } finally {
      clearTimeout(timeout);
    }

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      if (hop === MAX_REDIRECTS) throw new Error("Demasiadas redirecciones.");
      const nextUrl = normalizeUrl(new URL(res.headers.get("location"), current.toString()).toString());
      if (!nextUrl) throw new Error("Redirección no válida.");
      current = nextUrl;
      continue; // loop re-validates the new URL before following it
    }

    if (!res.ok) throw new Error(`La web respondió con estado ${res.status}`);
    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("text/html")) throw new Error("La URL no devuelve una página HTML");

    const timeout2 = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const reader = res.body?.getReader();
      if (!reader) return await res.text();
      let received = 0;
      const chunks = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.length;
        if (received > MAX_BODY_BYTES) {
          controller.abort();
          break;
        }
        chunks.push(value);
      }
      return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf-8");
    } finally {
      clearTimeout(timeout2);
    }
  }

  throw new Error("Demasiadas redirecciones.");
}

function extractSignals(html, pageUrl) {
  const $ = cheerio.load(html);
  $("script, style, noscript, svg").remove();

  const title = $("title").first().text().trim().slice(0, 200);
  const metaDescription = $('meta[name="description"]').attr("content")?.trim().slice(0, 300) || "";
  const hasViewport = $('meta[name="viewport"]').length > 0;

  const headings = [];
  $("h1, h2, h3").each((_, el) => {
    if (headings.length >= 25) return;
    const text = $(el).text().trim().replace(/\s+/g, " ");
    if (text) headings.push(`[${el.tagName.toLowerCase()}] ${text.slice(0, 160)}`);
  });

  const navLinks = [];
  $("nav a, header a").each((_, el) => {
    if (navLinks.length >= 20) return;
    const text = $(el).text().trim().replace(/\s+/g, " ");
    if (text) navLinks.push(text.slice(0, 60));
  });

  const ctaTexts = [];
  $("a, button").each((_, el) => {
    if (ctaTexts.length >= 30) return;
    const text = $(el).text().trim().replace(/\s+/g, " ");
    if (text && text.length <= 60) ctaTexts.push(text);
  });

  const hasForm = $("form").length > 0;
  const hasDirectContact = $('a[href^="mailto:"], a[href^="tel:"], a[href*="wa.me"], a[href*="whatsapp"]').length > 0;

  const images = $("img");
  const imageCount = images.length;
  let imagesWithAlt = 0;
  images.each((_, el) => {
    if ($(el).attr("alt")?.trim()) imagesWithAlt++;
  });

  let bodyText = $("body").text().replace(/\s+/g, " ").trim();
  const wordCount = bodyText ? bodyText.split(" ").length : 0;
  bodyText = bodyText.slice(0, MAX_TEXT_CHARS);

  return {
    url: pageUrl,
    title,
    metaDescription,
    hasViewport,
    headings,
    navLinks: [...new Set(navLinks)],
    ctaTexts: [...new Set(ctaTexts)].slice(0, 20),
    hasForm,
    hasDirectContact,
    imageCount,
    imagesWithAlt,
    wordCount,
    bodyText,
  };
}

// --- Motor de diagnóstico determinista ------------------------------
// Nada de esto llama a un proveedor de IA. Cada puntuación se calcula a
// partir de señales reales extraídas de la página (extractSignals) con
// reglas fijas y transparentes. Cuando no hay señal suficiente para
// sostener una puntuación con garantías, se marca evaluated:false — nunca
// se inventa un número ni se simula comprensión del lenguaje.

const GOAL_LABELS = {
  ecommerce: "una tienda online",
  reservas: "una web pensada para conseguir reservas",
  contacto: "una web pensada para captar contactos",
  servicios: "una web de presentación de servicios",
  portfolio: "un portfolio",
  informativo: "una web principalmente informativa",
  general: "esta web",
};

const GOAL_KEYWORDS = {
  ecommerce: ["comprar", "carrito", "cesta", "añadir al carrito", "tienda", "precio", "envío"],
  reservas: ["reservar", "reserva", "cita previa", "pedir cita", "agenda", "book"],
  contacto: ["contacto", "contactar", "presupuesto", "solicitar información", "escríbenos", "pide información"],
  servicios: ["servicios", "qué ofrecemos", "nuestros servicios"],
  portfolio: ["portfolio", "proyectos", "trabajos", "casos"],
  informativo: ["artículo", "blog", "noticias", "guía", "aprende"],
};

const GOAL_ACTION_KEYWORDS = {
  ecommerce: ["comprar", "carrito", "cesta", "ver producto", "tienda", "añadir"],
  reservas: ["reservar", "reserva", "cita", "agenda", "book"],
  contacto: ["contacto", "contactar", "presupuesto", "solicitar información", "escríbenos"],
  servicios: ["contacto", "contactar", "presupuesto", "solicitar información"],
  portfolio: ["contacto", "contactar", "ver proyecto"],
  informativo: ["leer más", "suscrib", "ver más"],
  general: ["contacto", "contactar", "más información"],
};

function detectGoal(signals) {
  const haystack = [signals.bodyText, signals.ctaTexts.join(" "), signals.navLinks.join(" "), signals.headings.join(" ")]
    .join(" ")
    .toLowerCase();
  let best = "general";
  let bestCount = 0;
  for (const [goal, keywords] of Object.entries(GOAL_KEYWORDS)) {
    const count = keywords.reduce((acc, k) => acc + (haystack.includes(k) ? 1 : 0), 0);
    if (count > bestCount) {
      best = goal;
      bestCount = count;
    }
  }
  return best;
}

function scoreClaridad(signals) {
  const h1Entry = signals.headings.find((h) => h.startsWith("[h1]"));
  const h1Text = h1Entry ? h1Entry.replace(/^\[h1\]\s*/, "") : "";
  const h1Words = h1Text ? h1Text.split(/\s+/).filter(Boolean).length : 0;
  const hasTitle = signals.title.length > 0;

  if (!h1Entry && !hasTitle) {
    return {
      evaluated: false,
      score: null,
      explanation: "La página no tiene un título ni un titular principal detectable, así que no hay base suficiente para valorar si comunica con claridad qué ofrece el negocio.",
    };
  }

  let score = 0;
  const found = [];
  const missing = [];

  if (h1Entry) { found.push(`un titular principal ("${h1Text}")`); score += 3; } else missing.push("un titular principal (H1)");
  if (h1Entry && h1Words >= 4) score += 2;
  else if (h1Entry) missing.push("que ese titular diga algo más concreto (es muy breve)");

  const hasGoodMeta = signals.metaDescription.length >= 50 && signals.metaDescription.length <= 300;
  if (hasGoodMeta) { found.push("una meta descripción completa"); score += 2; } else missing.push("una meta descripción completa");

  if (hasTitle && signals.title.length >= 15) score += 2;

  if (signals.headings.length >= 2) { found.push("titulares secundarios que estructuran el contenido"); score += 1; }
  else missing.push("titulares secundarios que estructuren el contenido");

  score = Math.min(10, score);

  const explanation = missing.length
    ? `${found.length ? `La web tiene ${found.join(" y ")}, pero le falta` : "Falta"} ${missing.join(" y ")} — eso puede ralentizar que alguien entienda rápido qué ofrece el negocio.`
    : `El titular ("${h1Text}"), la meta descripción y los titulares secundarios comunican con claridad qué ofrece la web desde el primer momento.`;

  return { evaluated: true, score, explanation };
}

function scoreConfianza(signals) {
  if (signals.wordCount < 30) {
    return {
      evaluated: false,
      score: null,
      explanation: "Hay muy poco contenido textual visible en la página para valorar con garantías las señales de confianza.",
    };
  }

  let score = 0;
  const found = [];
  const missing = [];

  if (signals.hasDirectContact) { found.push("un contacto directo visible (email, teléfono o WhatsApp)"); score += 3; }
  else missing.push("un contacto directo visible");

  if (signals.hasForm) { found.push("un formulario de contacto"); score += 2; }

  const trustKeywords = ["testimonio", "opinión", "opiniones", "reseña", "reseñas", "garantía", "casos de éxito", "años de experiencia", "certificad"];
  const bodyLower = signals.bodyText.toLowerCase();
  if (trustKeywords.some((k) => bodyLower.includes(k))) { found.push("menciones de testimonios, casos o garantías"); score += 2; }
  else missing.push("testimonios, casos de éxito o menciones de garantía");

  const altRatio = signals.imageCount > 0 ? signals.imagesWithAlt / signals.imageCount : null;
  if (altRatio !== null && altRatio >= 0.5) score += 2;

  if (signals.navLinks.some((l) => /sobre|quienes somos|equipo|nosotros/i.test(l))) { found.push('una sección "sobre nosotros" o similar'); score += 1; }

  score = Math.min(10, score);

  let explanation;
  if (found.length && missing.length) {
    explanation = `La web tiene ${found.join(", ")}, pero le falta ${missing.join(" y ")} — elementos que suelen reducir las dudas antes de contactar.`;
  } else if (found.length) {
    explanation = `La web tiene ${found.join(", ")}, señales que ayudan a generar confianza antes de contactar.`;
  } else {
    explanation = `No se detecta ${missing.join(" ni ")}, lo que puede generar dudas a quien todavía no conoce el negocio.`;
  }

  return { evaluated: true, score, explanation };
}

function scoreConversion(signals, goal) {
  const keywords = GOAL_ACTION_KEYWORDS[goal] || GOAL_ACTION_KEYWORDS.general;
  const ctaLower = signals.ctaTexts.map((c) => c.toLowerCase());
  const matchingCtas = signals.ctaTexts.filter((_, i) => keywords.some((k) => ctaLower[i].includes(k)));

  if (!matchingCtas.length && !signals.hasForm && !signals.hasDirectContact) {
    return {
      evaluated: false,
      score: null,
      explanation: `No se detecta ningún botón, enlace o formulario que invite a dar el siguiente paso, así que no hay base suficiente para valorar la conversión de ${GOAL_LABELS[goal]}.`,
    };
  }

  let score = 0;
  const notes = [];

  if (matchingCtas.length) { score += 4; notes.push(`tiene una llamada a la acción reconocible ("${matchingCtas[0]}")`); }
  else notes.push("no se identifica un botón claro para la acción que esta web debería facilitar");

  if (signals.hasDirectContact) score += 2;
  if (signals.hasForm) score += 2;

  const totalCtas = signals.ctaTexts.length;
  if (matchingCtas.length && totalCtas <= 8) score += 2;
  else if (totalCtas > 15) notes.push(`compite con otros ${totalCtas} enlaces de la página, lo que puede diluir cuál es la acción principal`);

  score = Math.min(10, score);

  return { evaluated: true, score, explanation: `Como ${GOAL_LABELS[goal]}, ${notes.join("; ")}.` };
}

function scoreExperienciaMovil(signals) {
  if (!signals.hasViewport) {
    return {
      evaluated: true,
      score: 3,
      explanation: "La página no incluye la etiqueta técnica de viewport que adapta el contenido a pantallas pequeñas — una señal clara de que probablemente no se ve bien en el móvil.",
    };
  }
  return {
    evaluated: false,
    score: null,
    explanation: "La página sí declara que está adaptada a dispositivos móviles, pero sin ver la web renderizada en un móvil real no se puede confirmar con garantías si el espaciado, los botones y las imágenes funcionan bien en pantallas pequeñas.",
  };
}

const AREA_LABELS = {
  claridad: "Claridad del mensaje",
  confianza: "Confianza",
  conversion: "Siguiente paso",
  experienciaMovil: "Experiencia móvil",
};
const PRIORITY_ORDER = ["conversion", "confianza", "claridad", "experienciaMovil"];

// Tono deliberadamente prudente: observa, no dictamina. Nunca afirma que
// algo "está mal" — usa condicional y generaliza el punto a revisar en vez
// de repetir el detalle exacto ya mostrado en la tarjeta de la métrica.
const OPPORTUNITY_HINTS = {
  claridad: "quizás convendría revisar el mensaje principal, para que se entienda todavía más rápido qué ofrece el negocio",
  confianza: "podría convenir reforzar algo más las señales de confianza, como una vía de contacto visible o algún testimonio",
  conversion: "tal vez ayudaría simplificar el siguiente paso que se le pide a quien visita la web",
  experienciaMovil: "sería recomendable revisar cómo se ve y se usa la web desde el móvil",
};

function buildOpportunity(ranked) {
  const weakestKey = ranked[0][0];
  const strong = ranked
    .filter(([key, m]) => key !== weakestKey && m.score >= 7)
    .map(([key]) => AREA_LABELS[key].toLowerCase());

  let intro;
  if (strong.length === 1) {
    intro = `En general, la web tiene un buen punto en ${strong[0]}.`;
  } else if (strong.length > 1) {
    const strongText = strong.slice(0, -1).join(", ") + " y " + strong[strong.length - 1];
    intro = `En general, la web tiene puntos buenos en ${strongText}.`;
  } else {
    intro = "En general, la web funciona de forma correcta, aunque con margen de mejora.";
  }

  return `${intro} Si hubiera que fijarse en algo, ${OPPORTUNITY_HINTS[weakestKey]}.`;
}

function buildDiagnosis(signals) {
  const goal = detectGoal(signals);
  const metrics = {
    claridad: scoreClaridad(signals),
    confianza: scoreConfianza(signals),
    conversion: scoreConversion(signals, goal),
    experienciaMovil: scoreExperienciaMovil(signals),
  };

  const ranked = Object.entries(metrics)
    .filter(([, m]) => m.evaluated)
    .sort((a, b) => (a[1].score !== b[1].score ? a[1].score - b[1].score : PRIORITY_ORDER.indexOf(a[0]) - PRIORITY_ORDER.indexOf(b[0])));

  const principalOportunidad = ranked.length
    ? buildOpportunity(ranked)
    : "No ha sido posible determinar una oportunidad principal con la información disponible en esta página.";

  const structuralExtras = [];
  if (signals.navLinks.length === 0) {
    structuralExtras.push({ area: "Navegación", explicacion: "No se detectan enlaces de navegación claros, lo que puede dificultar que alguien encuentre el resto del contenido." });
  }
  if (signals.wordCount < 80) {
    structuralExtras.push({ area: "Contenido", explicacion: "La página tiene muy poco texto visible, lo que limita lo que un visitante puede llegar a entender del negocio." });
  }
  if (signals.imageCount > 0 && signals.imagesWithAlt / signals.imageCount < 0.3) {
    structuralExtras.push({ area: "Accesibilidad de imágenes", explicacion: "La mayoría de las imágenes no tienen texto alternativo, lo que afecta a la accesibilidad y al posicionamiento." });
  }

  const prioridades = [...ranked.map(([key, m]) => ({ area: AREA_LABELS[key], explicacion: m.explanation })), ...structuralExtras].slice(0, 3);
  while (prioridades.length < 3) {
    prioridades.push({ area: "Revisión general", explicacion: "No se han detectado más puntos concretos a partir del contenido disponible en la página." });
  }

  return { metrics, principalOportunidad, prioridades };
}

function levelFromScore(score) {
  if (score >= 9) return "Excelente";
  if (score >= 7) return "Buena";
  if (score >= 5) return "Mejorable";
  if (score >= 3) return "Débil";
  return "Crítica";
}

function normalizeMetric(metric) {
  if (!metric || !metric.evaluated || typeof metric.score !== "number") {
    return { evaluated: false, score: null, level: null, explanation: metric?.explanation || "No se ha podido evaluar esta área con la información disponible." };
  }
  const score = Math.max(0, Math.min(10, Math.round(metric.score)));
  return { evaluated: true, score, level: levelFromScore(score), explanation: metric.explanation };
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Método no permitido." });
    return;
  }

  let requestBody;
  try {
    requestBody = req.body;
  } catch {
    res.status(400).json({ error: "La solicitud no tiene un formato válido." });
    return;
  }

  const targetUrl = normalizeUrl(requestBody?.url);
  if (!targetUrl) {
    res.status(400).json({ error: "Introduce una URL pública válida (por ejemplo, https://tuweb.com)." });
    return;
  }

  let html;
  try {
    html = await fetchHtml(targetUrl);
  } catch (err) {
    console.error("[vantage-check] fetch error", err);
    res.status(502).json({ error: "No hemos podido acceder a esa web. Comprueba que la URL es correcta y que la web es pública." });
    return;
  }

  let signals;
  try {
    signals = extractSignals(html, targetUrl.toString());
  } catch (err) {
    console.error("[vantage-check] parse error", err);
    res.status(502).json({ error: "No hemos podido leer el contenido de esa web." });
    return;
  }

  try {
    const diagnosis = buildDiagnosis(signals);
    const validated = DiagnosisSchema.parse(diagnosis);

    res.status(200).json({
      metrics: {
        claridad: normalizeMetric(validated.metrics.claridad),
        confianza: normalizeMetric(validated.metrics.confianza),
        conversion: normalizeMetric(validated.metrics.conversion),
        experienciaMovil: normalizeMetric(validated.metrics.experienciaMovil),
      },
      principalOportunidad: validated.principalOportunidad,
      prioridades: validated.prioridades,
    });
  } catch (err) {
    console.error("[vantage-check] scoring error", err);
    res.status(500).json({ error: "No hemos podido completar el análisis. Prueba de nuevo en unos segundos." });
  }
}
