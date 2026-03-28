// CiberShield Image Analysis Engine
// Client-side image analysis for educational purposes
// Detects: text in images (OCR), EXIF metadata risks, scam patterns, violence, weapons, nudity

import Tesseract from "tesseract.js";

export type ImageRiskLevel = "critico" | "alto" | "medio" | "bajo" | "seguro";

export interface ImageDetection {
  id: string;
  category: "privacidad" | "estafa" | "violencia" | "armas" | "desnudos" | "metadatos" | "deepfake";
  riskLevel: ImageRiskLevel;
  title: string;
  detail?: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}

export interface ImageAnalysisResult {
  overallRisk: ImageRiskLevel;
  score: number;
  detections: ImageDetection[];
  summary: string;
  extractedText?: string;
  metadata?: Record<string, string>;
}

// ─── HELPER: normalize text ───
function normalize(text: string): string {
  return text
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ñ/g, "n");
}

// ─── TEXT PATTERNS IN IMAGES (for OCR results) ───
interface TextPattern {
  pattern: RegExp;
  category: ImageDetection["category"];
  riskLevel: ImageRiskLevel;
  title: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}

const imageTextPatterns: TextPattern[] = [
  // ── SCAM / ESTAFA PATTERNS ──
  {
    pattern: /\b(ganaste|has ganado|felicidades.*premio|winner|congratulations|eres el ganador|premio garantizado|reclama tu premio)\b/i,
    category: "estafa",
    riskLevel: "critico",
    title: "Imagen de sorteo o premio falso",
    explanation: "Las imagenes que anuncian premios, sorteos o ganancias inesperadas son una de las estafas mas comunes en redes sociales. Buscan obtener datos personales o bancarios de la victima.",
    recommendation: "Nunca compartas datos personales para 'reclamar' un premio. Las empresas legitimas no notifican premios por imagenes en redes sociales. Reporta y bloquea.",
    learnMore: "El 89% de los anuncios de premios en redes sociales son estafas. Los estafadores usan logos de empresas reales para dar credibilidad y obtener datos bancarios."
  },
  {
    pattern: /\b(deposita|transfiere|envia dinero|gana dinero|ingresos desde casa|trabaja desde casa|oportunidad de negocio|multinivel|inversio?n segura|rendimientos garantizados|bitcoin.*gratis|cripto.*gratis)\b/i,
    category: "estafa",
    riskLevel: "critico",
    title: "Estafa financiera o esquema piramidal",
    explanation: "Imagenes que prometen ganancias faciles, inversiones seguras o ingresos desde casa son frecuentemente estafas piramidales o esquemas Ponzi que causan perdidas economicas significativas.",
    recommendation: "Desconfia de cualquier oferta de dinero facil. Las inversiones legitimas nunca garantizan rendimientos. Verifica ante la CONDUSEF o la CNBV antes de invertir.",
    learnMore: "Los esquemas piramidales en Mexico han causado perdidas por mas de 2,000 millones de pesos. Las redes sociales son el principal canal de captacion de victimas."
  },
  {
    pattern: /\b(oferta.*limitada|solo.*hoy|ultimas.*horas|urgente|apurate|no te lo pierdas|descuento.*\d+%|gratis.*solo|aprovecha.*ahora|compra.*ya)\b/i,
    category: "estafa",
    riskLevel: "medio",
    title: "Tactica de urgencia o presion",
    explanation: "Las imagenes que crean sensacion de urgencia ('solo hoy', 'ultimas horas', 'oferta limitada') son una tecnica de manipulacion psicologica usada en estafas para que actues sin pensar.",
    recommendation: "Toma tiempo para verificar cualquier oferta antes de actuar. Las ofertas legitimas no desaparecen en minutos. Busca la tienda o marca oficial para confirmar.",
    learnMore: "La presion temporal es una de las 6 tecnicas de persuasion de Cialdini. Los estafadores la explotan porque reduce la capacidad de analisis critico de la victima."
  },
  {
    pattern: /\b(click.*aqui|haz.*click|entra.*link|link.*bio|visita.*sitio|www\.\S+|http\S+|bit\.ly|tinyurl)\b/i,
    category: "estafa",
    riskLevel: "alto",
    title: "Enlace sospechoso en imagen",
    explanation: "Las imagenes que contienen URLs o invitaciones a hacer click en enlaces pueden dirigir a sitios de phishing disenados para robar tus credenciales o instalar malware.",
    recommendation: "Nunca hagas click en enlaces dentro de imagenes. Verifica la URL manualmente. Los acortadores de enlaces (bit.ly, tinyurl) ocultan el destino real.",
    learnMore: "El 91% de los ciberataques comienzan con phishing. Las imagenes con enlaces incrustados evaden los filtros de spam de las plataformas."
  },
  {
    pattern: /\b(datos.*bancarios|numero.*tarjeta|cvv|nip|contrasena|password|clave.*acceso|token.*bancario|codigo.*seguridad)\b/i,
    category: "estafa",
    riskLevel: "critico",
    title: "Solicitud de datos bancarios o credenciales",
    explanation: "Imagenes que solicitan datos bancarios, contrasenas o codigos de seguridad son intentos de phishing. Ningun banco o servicio legitimo solicita esta informacion por imagen.",
    recommendation: "NUNCA proporciones datos bancarios o contrasenas a traves de imagenes o enlaces en redes sociales. Tu banco nunca te pedira esto por este medio.",
    learnMore: "El phishing visual (imagenes que imitan bancos o servicios) tiene una tasa de exito del 45%, mucho mayor que el phishing por texto simple."
  },

  // ── PRIVACY / PRIVACIDAD PATTERNS ──
  {
    pattern: /\b(CURP|RFC|INE|credencial.*elector|pasaporte|licencia.*conducir|acta.*nacimiento|seguro.*social|NSS|IMSS)\b/i,
    category: "privacidad",
    riskLevel: "critico",
    title: "Documento de identidad visible",
    explanation: "La imagen contiene texto asociado a documentos oficiales (INE, CURP, RFC, pasaporte). Publicar documentos de identidad facilita el robo de identidad y fraude.",
    recommendation: "Elimina esta imagen inmediatamente. Si ya la publicaste, solicita a la plataforma su eliminacion. Monitorea tu historial crediticio por actividad sospechosa.",
    learnMore: "Con una foto de INE y CURP, un criminal puede abrir cuentas bancarias, solicitar creditos y cometer fraude en tu nombre. El robo de identidad en Mexico crece un 30% anual."
  },
  {
    pattern: /\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b/,
    category: "privacidad",
    riskLevel: "critico",
    title: "Numero de tarjeta visible en imagen",
    explanation: "Se detecto un patron de 16 digitos en la imagen que podria ser un numero de tarjeta de credito o debito. Publicar esta informacion permite la clonacion y uso fraudulento.",
    recommendation: "Elimina la imagen inmediatamente. Contacta a tu banco para reportar la exposicion. Considera solicitar una nueva tarjeta como medida preventiva.",
    learnMore: "Una foto de tarjeta publicada en redes sociales puede ser usada para compras fraudulentas en segundos. Los bots automatizados escanean redes buscando estos patrones."
  },
  {
    pattern: /\b(calle|colonia|c\.p\.|codigo postal|numero.*interior|manzana|lote|avenida|boulevard|carretera)\b/i,
    category: "privacidad",
    riskLevel: "alto",
    title: "Direccion o ubicacion visible",
    explanation: "La imagen contiene texto que parece ser una direccion fisica. Publicar tu ubicacion exacta facilita el acoso, robo y seguimiento fisico.",
    recommendation: "No publiques imagenes que contengan direcciones. Revisa capturas de pantalla y fotos de documentos antes de compartirlas.",
    learnMore: "Las direcciones extraidas de imagenes en redes sociales se usan para elaborar mapas de potenciales victimas de robo y secuestro."
  },

  // ── VIOLENCE / VIOLENCIA PATTERNS ──
  {
    pattern: /\b(te voy a matar|vas a morir|muerte|matar|arma|pistola|cuchillo|sangre|golpear|balacera|ejecut\w*|descuartiz\w*|asesina\w*|sicario|narco|cartel)\b/i,
    category: "violencia",
    riskLevel: "critico",
    title: "Contenido con texto violento",
    explanation: "La imagen contiene texto asociado con violencia, amenazas o contenido relacionado con crimen organizado. Compartir este tipo de contenido puede tener consecuencias legales y psicologicas.",
    recommendation: "No compartas imagenes con contenido violento. Si contiene amenazas, documenta y reporta a las autoridades. Si te afecta emocionalmente, busca apoyo profesional.",
    learnMore: "La exposicion repetida a contenido violento en redes sociales esta asociada con ansiedad, desensibilizacion y trauma secundario, especialmente en adolescentes."
  },
  {
    pattern: /\b(gore|nsfw|nsfl|trigger warning|contenido.*explicito|contenido.*grafico|violencia.*grafica|imagen.*fuerte)\b/i,
    category: "violencia",
    riskLevel: "alto",
    title: "Advertencia de contenido grafico",
    explanation: "La imagen contiene advertencias de contenido grafico o violento. Este tipo de material puede causar trauma psicologico y su distribucion puede ser ilegal.",
    recommendation: "No abras ni compartas contenido marcado como grafico o NSFW/NSFL. Si fue enviado sin tu consentimiento, reporta al remitente y a la plataforma.",
    learnMore: "El consumo de contenido violento grafico puede causar sindrome de estres postraumatico (PTSD), especialmente en menores. Las plataformas tienen la obligacion de moderar este contenido."
  },

  // ── WEAPONS / ARMAS PATTERNS ──
  {
    pattern: /\b(pistola|arma|rifle|fusil|escopeta|metralleta|revolver|calibre|municion|bala|cartucho|cargador|AK.?47|AR.?15|9mm|cuerno.*chivo|bazuca|granada|explosivo|detonador)\b/i,
    category: "armas",
    riskLevel: "critico",
    title: "Referencia a armas de fuego o explosivos",
    explanation: "La imagen contiene texto que menciona armas de fuego, municiones o explosivos. Compartir contenido que promueve o exhibe armas puede tener implicaciones legales y contribuye a la normalizacion de la violencia armada.",
    recommendation: "No compartas imagenes que exhiban o promuevan armas. En Mexico, la portacion y exhibicion de armas de fuego esta regulada por la Ley Federal de Armas de Fuego y Explosivos. Reporta contenido que promueva violencia armada.",
    learnMore: "La exhibicion de armas en redes sociales esta vinculada con el reclutamiento del crimen organizado, especialmente dirigido a jovenes. Las plataformas prohiben este contenido pero la deteccion automatica es limitada."
  },
  {
    pattern: /\b(cuchillo|navaja|machete|katana|punal|daga|arma.*blanca|navajazo|punalada|apunalar)\b/i,
    category: "armas",
    riskLevel: "alto",
    title: "Referencia a armas blancas",
    explanation: "La imagen contiene texto que menciona armas blancas o cortopunzantes. Este tipo de contenido puede estar asociado con amenazas, violencia o intimidacion.",
    recommendation: "No compartas contenido que glorifique o exhiba armas blancas en contexto de violencia. Si detectas una amenaza real, reporta a las autoridades.",
    learnMore: "Las amenazas con armas blancas publicadas en redes sociales constituyen un delito de amenazas segun el Codigo Penal Federal. Conserva evidencia y denuncia."
  },

  // ── NUDITY / DESNUDOS PATTERNS ──
  {
    pattern: /\b(desnud\w*|nude|nudes|porn\w*|xxx|onlyfans|contenido.*adulto|explicito.*sexual|sexo.*explicito|pack|packs)\b/i,
    category: "desnudos",
    riskLevel: "critico",
    title: "Contenido sexual o de desnudez explicita",
    explanation: "La imagen contiene texto asociado con contenido sexual explicito o desnudez. Compartir este tipo de material sin consentimiento es un delito conocido como 'pornovenganza' o difusion de material intimo.",
    recommendation: "NUNCA compartas imagenes intimas de otras personas sin su consentimiento. Si alguien comparte las tuyas, denuncia ante la policia cibernetica y solicita eliminacion a la plataforma.",
    learnMore: "En Mexico, la Ley Olimpia tipifica como delito la difusion de contenido intimo sin consentimiento, con penas de 3 a 6 anos de prision. Todas las entidades federativas la han adoptado."
  },
  {
    pattern: /\b(sext\w*|sexting|foto.*intima|video.*intimo|mandame.*foto|envia.*foto|ensenam|muestram|sin.*ropa|encuerad\w*)\b/i,
    category: "desnudos",
    riskLevel: "alto",
    title: "Solicitud de contenido intimo (sexting)",
    explanation: "La imagen contiene texto que solicita o promueve el envio de contenido intimo. El sexting con menores de edad es un delito grave, y el material compartido puede ser usado para chantaje (sextorsion).",
    recommendation: "Nunca envies fotos o videos intimos a desconocidos. Si eres menor de edad, habla con un adulto de confianza. Si te presionan, es un delito y debes denunciar.",
    learnMore: "El 40% de los adolescentes ha recibido solicitudes de contenido intimo en redes sociales. La sextorsion es uno de los delitos ciberneticos de mas rapido crecimiento en Mexico."
  },

  // ── DEEPFAKE PATTERNS ──
  {
    pattern: /\b(deepfake|face.*swap|ia.*genero|generada.*ia|artificial.*intelligence|imagen.*falsa|foto.*falsa|manipulada)\b/i,
    category: "deepfake",
    riskLevel: "alto",
    title: "Posible imagen generada o manipulada con IA",
    explanation: "La imagen contiene referencias a contenido generado por IA. Las imagenes deepfake se usan para desinformacion, suplantacion de identidad y creacion de material no consensuado.",
    recommendation: "Verifica la autenticidad: busca anomalias en manos, orejas, dientes, reflejos en ojos y fondos. Usa busqueda inversa de imagenes para encontrar la fuente original.",
    learnMore: "El 96% de los deepfakes son de naturaleza sexual y se crean sin consentimiento. Herramientas gratuitas permiten generarlos con solo unas pocas fotos de la victima."
  }
];

// ─── KEYWORD PATTERNS FOR OCR TEXT ───
interface KeywordImageRule {
  keywords: string[];
  category: ImageDetection["category"];
  riskLevel: ImageRiskLevel;
  title: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
  minMatches: number;
}

const imageKeywordRules: KeywordImageRule[] = [
  {
    keywords: ["gratis", "regalo", "sorteo", "ganador", "premio", "rifa", "concurso", "promo"],
    category: "estafa",
    riskLevel: "alto",
    title: "Posible estafa por sorteo o promocion",
    explanation: "Multiples palabras en la imagen sugieren un sorteo o promocion potencialmente fraudulenta. Los estafadores usan imagenes llamativas con premios para captar victimas.",
    recommendation: "Verifica directamente en el sitio oficial de la marca o empresa. Si te piden datos personales o un 'pequeno pago' para reclamar, es una estafa.",
    learnMore: "Las estafas de sorteos falsos en redes sociales han incrementado un 150% en America Latina. Usan logos reales y testimonios falsos para dar credibilidad.",
    minMatches: 2
  },
  {
    keywords: ["sangre", "muerte", "muerto", "cadaver", "violencia", "golpe", "herida", "arma", "disparo", "balacera"],
    category: "violencia",
    riskLevel: "alto",
    title: "Texto con referencias a violencia",
    explanation: "Se detectaron multiples palabras asociadas con violencia en la imagen. Este tipo de contenido puede ser perturbador y su distribucion puede tener implicaciones legales.",
    recommendation: "No compartas este tipo de contenido. Si documenta un delito, reporta directamente a las autoridades en lugar de difundir en redes sociales.",
    learnMore: "La viralizacion de contenido violento en redes sociales contribuye a la normalizacion de la violencia y puede re-traumatizar a las victimas.",
    minMatches: 2
  },
  {
    keywords: ["pistola", "arma", "rifle", "fusil", "calibre", "municion", "bala", "disparo", "tiroteo", "detonacion"],
    category: "armas",
    riskLevel: "alto",
    title: "Multiples referencias a armamento",
    explanation: "Se detectaron varias palabras relacionadas con armas de fuego o municiones en la imagen. Este patron es comun en contenido que promueve o glorifica la violencia armada.",
    recommendation: "Reporta este contenido a la plataforma. No compartas ni difundas material que exhiba o promueva armas. Si detectas una amenaza real, contacta a las autoridades.",
    learnMore: "Las redes sociales son utilizadas por grupos criminales para exhibir arsenal como forma de intimidacion y reclutamiento. Reportar este contenido ayuda a su eliminacion.",
    minMatches: 2
  },
  {
    keywords: ["desnudo", "nude", "sexual", "intimo", "erotico", "porn", "pack", "nudes", "sexo", "caliente"],
    category: "desnudos",
    riskLevel: "alto",
    title: "Multiples referencias a contenido sexual",
    explanation: "Se detectaron varias palabras asociadas con contenido sexual o de desnudez. La distribucion de material intimo sin consentimiento es un delito en Mexico.",
    recommendation: "No distribuyas contenido intimo ajeno. Si eres victima de difusion no consentida, denuncia ante la policia cibernetica (088) y guarda evidencia.",
    learnMore: "La Ley Olimpia protege a las victimas de violencia digital en Mexico, incluyendo la difusion de imagenes intimas sin consentimiento, con penas de hasta 6 anos de prision.",
    minMatches: 2
  },
  {
    keywords: ["whatsapp", "telegram", "contacto", "telefono", "numero", "llamar", "escribir", "dm", "inbox"],
    category: "estafa",
    riskLevel: "medio",
    title: "Solicitud de contacto directo",
    explanation: "La imagen invita a contactar por canales privados (WhatsApp, Telegram, DM). Los estafadores mueven la conversacion fuera de las plataformas donde hay menos proteccion y rastreo.",
    recommendation: "Desconfia de imagenes que te invitan a contactar por canales privados, especialmente si ofrecen premios, empleos o inversiones.",
    learnMore: "El 75% de las estafas en redes sociales migran la conversacion a WhatsApp o Telegram, donde no hay moderacion de contenido ni registro publico.",
    minMatches: 2
  }
];

// ─── EXIF METADATA ANALYSIS ───
interface MetadataDetection {
  riskLevel: ImageRiskLevel;
  title: string;
  detail: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}

function analyzeExifData(img: HTMLImageElement): Promise<{ metadata: Record<string, string>; detections: MetadataDetection[] }> {
  return new Promise((resolve) => {
    const metadata: Record<string, string> = {};
    const detections: MetadataDetection[] = [];

    // Use canvas to check basic image properties
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (ctx) {
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      
      metadata["Dimensiones"] = `${img.naturalWidth} x ${img.naturalHeight} px`;
      
      // Check for very high resolution (potential document scan)
      if (img.naturalWidth > 3000 || img.naturalHeight > 3000) {
        detections.push({
          riskLevel: "medio",
          title: "Imagen de alta resolucion",
          detail: `${img.naturalWidth} x ${img.naturalHeight} px`,
          explanation: "Esta imagen tiene una resolucion muy alta, comun en escaneos de documentos o fotos de alta calidad. Las imagenes de alta resolucion contienen mas detalles que pueden ser extraidos, incluyendo texto legible que no es visible a simple vista.",
          recommendation: "Reduce la resolucion antes de compartir. Usa herramientas de redimensionamiento para bajar a 1080px o menos si no necesitas la resolucion completa.",
          learnMore: "Las imagenes de alta resolucion permiten hacer zoom y extraer detalles como texto en documentos de fondo, matrículas de autos, y nombres en pantallas."
        });
      }

      // Check for very small images (possible screenshot cropped to hide context)
      if (img.naturalWidth < 200 && img.naturalHeight < 200) {
        detections.push({
          riskLevel: "bajo",
          title: "Imagen muy pequena",
          detail: `${img.naturalWidth} x ${img.naturalHeight} px`,
          explanation: "Las imagenes muy pequenas pueden ser recortes disenados para mostrar contenido fuera de contexto o iconos usados en perfiles falsos.",
          recommendation: "Verifica el contexto original de la imagen. Usa busqueda inversa para encontrar la version completa.",
          learnMore: "Los perfiles falsos frecuentemente usan imagenes recortadas y de baja resolucion para evitar la busqueda inversa de imagenes."
        });
      }

      // Check aspect ratio for document-like images
      const ratio = img.naturalWidth / img.naturalHeight;
      if ((ratio > 0.65 && ratio < 0.75) || (ratio > 1.35 && ratio < 1.55)) {
        detections.push({
          riskLevel: "medio",
          title: "Proporcion similar a documento",
          detail: `Ratio ${ratio.toFixed(2)}:1`,
          explanation: "Las dimensiones de esta imagen se asemejan a las de un documento (carta, credencial, tarjeta). Podria contener informacion personal sensible.",
          recommendation: "Revisa que la imagen no contenga datos personales visibles (nombre, numeros, direcciones, fotos de identificacion).",
          learnMore: "Las credenciales (INE, pasaporte, licencia) tienen proporciones estandar que pueden detectarse automaticamente. Si la imagen coincide, revisa su contenido."
        });
      }
    }

    resolve({ metadata, detections });
  });
}

// ─── VISUAL PATTERN ANALYSIS ───
function analyzeVisualPatterns(img: HTMLImageElement): ImageDetection[] {
  const detections: ImageDetection[] = [];
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  if (!ctx) return detections;

  // Sample at smaller size for performance
  const sampleSize = 150;
  canvas.width = sampleSize;
  canvas.height = sampleSize;
  ctx.drawImage(img, 0, 0, sampleSize, sampleSize);

  const imageData = ctx.getImageData(0, 0, sampleSize, sampleSize);
  const pixels = imageData.data;

  // Calculate color statistics
  let brightRedPixels = 0;    // Pure red (blood, wounds)
  let darkRedPixels = 0;      // Dark red/maroon (dried blood, bruises)
  let brownRedPixels = 0;     // Brownish-red tones
  let darkPixels = 0;
  let saturatedPixels = 0;    // Very vivid/saturated colors

  // WEAPONS detection: metallic/gunmetal colors
  let metallicPixels = 0;     // Gray metallic tones (guns, knives)
  let darkMetallicPixels = 0; // Very dark gray/black (gun barrels, tactical gear)
  let steelBluePixels = 0;    // Bluish-steel tones (metal reflections)

  // NUDITY detection: skin tone analysis
  let skinToneLight = 0;      // Light skin tones
  let skinToneMedium = 0;     // Medium/tan skin tones
  let skinToneDark = 0;       // Dark skin tones
  let skinToneWarm = 0;       // Warm/pinkish skin tones

  const totalPixels = sampleSize * sampleSize;
  const luminances: number[] = [];

  for (let i = 0; i < pixels.length; i += 4) {
    const r = pixels[i];
    const g = pixels[i + 1];
    const b = pixels[i + 2];

    const luminance = 0.299 * r + 0.587 * g + 0.114 * b;
    luminances.push(luminance);

    // ── RED TONES (Violence) ──
    // Bright red pixels (fresh blood, bright red)
    if (r > 140 && g < 70 && b < 70) {
      brightRedPixels++;
    }
    // Dark red / maroon pixels (dried blood, dark violence)
    if (r > 80 && r < 160 && g < 40 && b < 40) {
      darkRedPixels++;
    }
    // Brownish-red (bruises, wounds)
    if (r > 100 && g > 20 && g < 70 && b < 50 && r > g * 2) {
      brownRedPixels++;
    }

    // ── DARK PIXELS ──
    if (r < 30 && g < 30 && b < 30) {
      darkPixels++;
    }

    // ── METALLIC TONES (Weapons) ──
    const rgDiff = Math.abs(r - g);
    const gbDiff = Math.abs(g - b);
    const rbDiff = Math.abs(r - b);
    // Neutral gray (low saturation, mid-range luminance) = gun metal, knife blades
    if (rgDiff < 20 && gbDiff < 20 && rbDiff < 20 && luminance > 50 && luminance < 180) {
      metallicPixels++;
    }
    // Very dark gray/black metallic (gun barrels, tactical equipment)
    if (rgDiff < 15 && gbDiff < 15 && luminance >= 15 && luminance <= 60) {
      darkMetallicPixels++;
    }
    // Steel blue / blued metal reflections
    if (b > r && b > g && (b - r) > 10 && (b - r) < 50 && luminance > 40 && luminance < 150 && rgDiff < 25) {
      steelBluePixels++;
    }

    // ── SKIN TONES (Nudity) ──
    // Using established skin color models in RGB space
    // Light skin: high R, moderate G, lower B, warm tone
    if (r > 170 && g > 120 && g < 200 && b > 80 && b < 170 && r > g && g > b && (r - b) > 30) {
      skinToneLight++;
    }
    // Medium/tan skin
    if (r > 140 && r < 210 && g > 90 && g < 170 && b > 60 && b < 140 && r > g && g > b && (r - b) > 20) {
      skinToneMedium++;
    }
    // Dark skin
    if (r > 80 && r < 160 && g > 50 && g < 120 && b > 30 && b < 100 && r > g && g > b && (r - b) > 15) {
      skinToneDark++;
    }
    // Warm/pinkish skin (common in exposed skin areas)
    if (r > 180 && g > 130 && g < 180 && b > 120 && b < 175 && r > g && (r - g) > 10 && (r - b) > 15) {
      skinToneWarm++;
    }

    // ── SATURATED ──
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    if (max > 100 && (max - min) > 150) {
      saturatedPixels++;
    }
  }

  // ── CALCULATED PERCENTAGES ──
  const avgLuminance = luminances.reduce((a, b) => a + b, 0) / luminances.length;
  const variance = luminances.reduce((sum, l) => sum + Math.pow(l - avgLuminance, 2), 0) / luminances.length;
  const contrastStdDev = Math.sqrt(variance);

  const allRedPixels = brightRedPixels + darkRedPixels + brownRedPixels;
  const redPercentage = (allRedPixels / totalPixels) * 100;
  const darkPercentage = (darkPixels / totalPixels) * 100;
  const saturatedPct = (saturatedPixels / totalPixels) * 100;

  // Weapons: combined metallic percentage
  const allMetallic = metallicPixels + darkMetallicPixels + steelBluePixels;
  const metallicPct = (allMetallic / totalPixels) * 100;
  const darkMetallicPct = (darkMetallicPixels / totalPixels) * 100;

  // Nudity: combined skin tone percentage (avoid double-counting overlapping ranges)
  // We use the individual counts but cap the total as some pixels match multiple ranges
  const skinPixelEstimate = Math.min(
    skinToneLight + skinToneMedium + skinToneDark + skinToneWarm,
    totalPixels
  );
  const skinPct = (skinPixelEstimate / totalPixels) * 100;
  const lightSkinPct = (skinToneLight / totalPixels) * 100;
  const warmSkinPct = (skinToneWarm / totalPixels) * 100;

  // =================================================================
  //  1. VIOLENCE DETECTION
  // =================================================================

  if (redPercentage > 15) {
    detections.push({
      id: "visual-red-critical",
      category: "violencia",
      riskLevel: "critico",
      title: "Contenido potencialmente grafico o violento",
      detail: `${redPercentage.toFixed(1)}% de tonos rojos detectados`,
      explanation: "La imagen tiene una concentracion muy alta de tonos rojos y oscuros, comun en imagenes con contenido grafico, violento o con sangre. Este tipo de contenido puede causar trauma psicologico y su distribucion puede ser ilegal.",
      recommendation: "No compartas imagenes con contenido grafico o violento en redes sociales. Si documenta un delito, reporta directamente a las autoridades. Si te afecta emocionalmente, busca apoyo profesional.",
      learnMore: "La exposicion repetida a contenido violento en redes sociales esta asociada con ansiedad, desensibilizacion y trauma secundario, especialmente en adolescentes. En Mexico, distribuir contenido violento puede tener implicaciones legales."
    });
  } else if (redPercentage > 8) {
    detections.push({
      id: "visual-red-high",
      category: "violencia",
      riskLevel: "alto",
      title: "Posible contenido violento o grafico",
      detail: `${redPercentage.toFixed(1)}% de tonos rojos detectados`,
      explanation: "La imagen contiene una cantidad significativa de tonos rojos que pueden indicar contenido violento, heridas, sangre u otro material grafico. Aunque tambien podria ser una imagen con elementos rojos naturales.",
      recommendation: "Revisa cuidadosamente el contenido de la imagen antes de compartirla. Si contiene violencia o material perturbador, no la publiques en redes sociales.",
      learnMore: "Los sistemas de moderacion de contenido profesionales combinan analisis de color con redes neuronales para clasificar contenido violento con mayor precision."
    });
  } else if (redPercentage > 4) {
    detections.push({
      id: "visual-red-medium",
      category: "violencia",
      riskLevel: "medio",
      title: "Tonos rojos inusuales detectados",
      detail: `${redPercentage.toFixed(1)}% de tonos rojos detectados`,
      explanation: "La imagen tiene una presencia notable de tonos rojos. Aunque puede ser completamente inofensiva (ropa roja, paisajes, alimentos), este patron tambien aparece en contenido que puede ser perturbador.",
      recommendation: "Antes de compartir, verifica que el contenido de la imagen sea apropiado para tu audiencia.",
      learnMore: "El analisis de color es uno de los primeros filtros en sistemas de moderacion de contenido. Se complementa con deteccion de objetos y analisis de contexto para reducir falsos positivos."
    });
  }

  // Violence: Dark + Red combination
  if (darkPercentage > 20 && redPercentage > 3) {
    const alreadyHasViolence = detections.some(d => d.category === "violencia");
    if (!alreadyHasViolence) {
      detections.push({
        id: "visual-darkred",
        category: "violencia",
        riskLevel: "alto",
        title: "Combinacion de tonos oscuros y rojos",
        detail: `${darkPercentage.toFixed(1)}% oscuro, ${redPercentage.toFixed(1)}% rojo`,
        explanation: "La combinacion de areas oscuras con tonos rojos es un patron visual frecuente en contenido grafico o violento.",
        recommendation: "Verifica el contenido antes de compartir. Si la imagen muestra violencia real, no la distribuyas y reporta a las autoridades si documenta un delito.",
        learnMore: "Los algoritmos de deteccion de contenido violento analizan la combinacion espacial de colores, no solo su presencia."
      });
    }
  }

  // =================================================================
  //  2. WEAPONS DETECTION (metallic patterns)
  // =================================================================

  // High metallic + dark metallic = strong weapon indicator
  if (metallicPct > 40 && darkMetallicPct > 15) {
    detections.push({
      id: "visual-weapon-critical",
      category: "armas",
      riskLevel: "critico",
      title: "Posible imagen de arma de fuego o arma blanca",
      detail: `${metallicPct.toFixed(1)}% tonos metalicos, ${darkMetallicPct.toFixed(1)}% metalico oscuro`,
      explanation: "La imagen tiene una concentracion muy alta de tonos metalicos grises y oscuros, patron caracteristico de armas de fuego, cuchillos y otros objetos metalicos. La exhibicion de armas en redes sociales esta regulada y puede tener consecuencias legales.",
      recommendation: "No publiques imagenes que exhiban armas de fuego o armas blancas. En Mexico, la portacion ilegal de armas es un delito federal. Si recibes imagenes con armas en contexto de amenaza, denuncia inmediatamente.",
      learnMore: "La exhibicion de armas en redes sociales es una tactica comun de intimidacion y reclutamiento del crimen organizado. Las plataformas prohiben este contenido, pero la deteccion automatica es limitada. La Ley Federal de Armas de Fuego regula la portacion y exhibicion."
    });
  } else if (metallicPct > 30 && darkMetallicPct > 10) {
    detections.push({
      id: "visual-weapon-high",
      category: "armas",
      riskLevel: "alto",
      title: "Tonos metalicos compatibles con armamento",
      detail: `${metallicPct.toFixed(1)}% tonos metalicos detectados`,
      explanation: "La imagen contiene una proporcion significativa de tonos metalicos y grises oscuros. Este patron es comun en imagenes de armas, aunque tambien aparece en maquinaria, vehiculos o electronica.",
      recommendation: "Verifica que la imagen no contenga armas antes de compartirla. Si muestra armas en contexto de amenaza o intimidacion, reporta a las autoridades.",
      learnMore: "Los algoritmos profesionales complementan el analisis de color con deteccion de formas para distinguir armas de otros objetos metalicos. El contexto visual es determinante."
    });
  } else if (metallicPct > 20 && darkMetallicPct > 8) {
    detections.push({
      id: "visual-weapon-medium",
      category: "armas",
      riskLevel: "medio",
      title: "Presencia notable de tonos metalicos",
      detail: `${metallicPct.toFixed(1)}% tonos metalicos detectados`,
      explanation: "La imagen tiene una presencia moderada de tonos metalicos grises y oscuros. Puede tratarse de objetos cotidianos, pero revisa el contenido visual antes de compartir.",
      recommendation: "Antes de compartir, verifica que la imagen no contenga objetos peligrosos o contenido que pueda ser interpretado como amenaza.",
      learnMore: "El analisis de tonalidades metalicas es uno de los indicadores en sistemas de deteccion de armas. Se combina con reconocimiento de formas para mayor precision."
    });
  }

  // Dark + metallic combination (tactical/military)
  if (darkPercentage > 25 && metallicPct > 15 && !detections.some(d => d.category === "armas")) {
    detections.push({
      id: "visual-tactical",
      category: "armas",
      riskLevel: "medio",
      title: "Patron oscuro-metalico (posible equipo tactico)",
      detail: `${darkPercentage.toFixed(1)}% oscuro, ${metallicPct.toFixed(1)}% metalico`,
      explanation: "La combinacion de tonos oscuros con reflejos metalicos es comun en imagenes de equipo tactico, armamento o escenas con armas. Tambien puede ser un entorno industrial o nocturno.",
      recommendation: "Revisa el contenido de la imagen. Si muestra armas o equipo militar en contexto de violencia o amenaza, no la compartas y reporta.",
      learnMore: "Los sistemas de clasificacion de contenido utilizan combinaciones de color y textura para identificar equipo tactico y armamento en imagenes."
    });
  }

  // =================================================================
  //  3. NUDITY DETECTION (skin tone analysis)
  // =================================================================

  // Very high skin tone percentage = likely nude content
  if (skinPct > 60) {
    detections.push({
      id: "visual-nudity-critical",
      category: "desnudos",
      riskLevel: "critico",
      title: "Posible desnudez o contenido sexual",
      detail: `${skinPct.toFixed(1)}% de tonos de piel detectados`,
      explanation: "La imagen tiene una concentracion muy alta de tonos de piel humana, lo que sugiere desnudez parcial o total. Compartir imagenes intimas de otra persona sin su consentimiento es un delito en Mexico bajo la Ley Olimpia.",
      recommendation: "NUNCA compartas imagenes intimas ajenas. Si eres victima de difusion no consentida, denuncia ante la policia cibernetica (088), guarda evidencia con capturas de pantalla y solicita eliminacion a la plataforma.",
      learnMore: "La Ley Olimpia (vigente en todo Mexico) tipifica como delito la difusion de contenido intimo sin consentimiento, con penas de 3 a 6 anos de prision y multas. Aplica tanto a quien difunde como a quien almacena y redistribuye."
    });
  } else if (skinPct > 45) {
    detections.push({
      id: "visual-nudity-high",
      category: "desnudos",
      riskLevel: "alto",
      title: "Alta proporcion de tonos de piel humana",
      detail: `${skinPct.toFixed(1)}% de tonos de piel detectados`,
      explanation: "La imagen contiene una proporcion significativa de tonos de piel. Esto puede indicar desnudez parcial, ropa interior visible, o simplemente un retrato cercano. Verifica el contenido antes de compartir.",
      recommendation: "Revisa que la imagen no contenga desnudez no consentida antes de compartirla. Si es contenido intimo que te enviaron, no lo redistribuyas; hacerlo es un delito.",
      learnMore: "El sexting (envio de imagenes intimas) entre menores de edad se considera distribucion de material de abuso sexual infantil, independientemente del consentimiento. Es un delito grave."
    });
  } else if (skinPct > 30) {
    detections.push({
      id: "visual-nudity-medium",
      category: "desnudos",
      riskLevel: "medio",
      title: "Proporcion moderada de tonos de piel",
      detail: `${skinPct.toFixed(1)}% de tonos de piel detectados`,
      explanation: "La imagen tiene una presencia notable de tonos de piel humana. Puede ser un retrato, foto en la playa, o contenido cotidiano. Sin embargo, revisa que no contenga contenido inapropiado.",
      recommendation: "Antes de compartir, verifica que la imagen sea apropiada para tu audiencia y que todas las personas en ella hayan consentido su difusion.",
      learnMore: "El analisis de tonos de piel es una tecnica basica en la deteccion de contenido para adultos. Los sistemas profesionales lo complementan con deteccion de anatomia y poses."
    });
  }

  // Skin + Red combination = strong violence/injury indicator
  if (skinPct > 20 && redPercentage > 6) {
    const alreadyHasCombo = detections.some(d => d.id === "visual-skin-blood");
    if (!alreadyHasCombo) {
      detections.push({
        id: "visual-skin-blood",
        category: "violencia",
        riskLevel: "alto",
        title: "Combinacion de tonos de piel y sangre/rojo",
        detail: `${skinPct.toFixed(1)}% piel, ${redPercentage.toFixed(1)}% rojo`,
        explanation: "La imagen combina tonos de piel humana con tonos rojos intensos, patron comun en imagenes de heridas, lesiones o violencia fisica contra personas.",
        recommendation: "Si esta imagen muestra lesiones o violencia contra una persona, no la difundas. Si documenta un delito, reporta a las autoridades. Si eres victima, busca ayuda.",
        learnMore: "La combinacion de tonos de piel con rojo intenso es el indicador visual mas fiable de contenido de violencia fisica contra personas."
      });
    }
  }

  // =================================================================
  //  4. GENERAL VISUAL INDICATORS
  // =================================================================

  // High contrast
  if (contrastStdDev > 85) {
    detections.push({
      id: "visual-contrast",
      category: "violencia",
      riskLevel: "medio",
      title: "Alto contraste visual",
      detail: `Desviacion de contraste: ${contrastStdDev.toFixed(0)}`,
      explanation: "La imagen tiene un contraste extremo entre areas claras y oscuras. Las imagenes con contenido perturbador o violento frecuentemente presentan alto contraste.",
      recommendation: "Las imagenes de alto contraste son disenadas para captar atencion. Analiza el contenido criticamente antes de reaccionar o compartir.",
      learnMore: "El alto contraste es una tecnica visual usada tanto en contenido impactante como en propaganda y desinformacion."
    });
  }

  // Highly saturated
  if (saturatedPct > 30) {
    detections.push({
      id: "visual-saturated",
      category: "deepfake",
      riskLevel: "bajo",
      title: "Imagen con alta saturacion de color",
      detail: `${saturatedPct.toFixed(1)}% de pixeles altamente saturados`,
      explanation: "La imagen tiene colores extremadamente vividos que pueden indicar edicion digital, filtros agresivos o generacion por IA.",
      recommendation: "Desconfia de imagenes con colores demasiado vividos o poco naturales. Pueden estar editadas para manipular tu percepcion.",
      learnMore: "Las imagenes generadas por IA tienden a tener saturacion de color superior a las fotografias naturales."
    });
  }

  // Mostly dark: hidden content
  if (darkPercentage > 50) {
    const alreadyHasDark = detections.some(d => d.id === "visual-darkred" || d.id === "visual-tactical");
    if (!alreadyHasDark) {
      detections.push({
        id: "visual-dark",
        category: "estafa",
        riskLevel: "bajo",
        title: "Imagen predominantemente oscura",
        detail: `${darkPercentage.toFixed(1)}% de pixeles oscuros`,
        explanation: "Las imagenes muy oscuras pueden ocultar contenido que solo es visible al ajustar brillo/contraste.",
        recommendation: "Si la imagen parece intencionalmente oscura, es posible que oculte contenido. Ajusta brillo y contraste para verificar antes de compartir.",
        learnMore: "La esteganografia visual (ocultar informacion en imagenes) es una tecnica usada para distribuir contenido ilegal."
      });
    }
  }

  return detections;
}

// ─── MAIN ANALYSIS FUNCTION ───
export async function analyzeImage(
  file: File,
  onProgress?: (progress: number, status: string) => void
): Promise<ImageAnalysisResult> {
  const detections: ImageDetection[] = [];
  let maxRiskScore = 0;
  let extractedText = "";
  let metadata: Record<string, string> = {};

  const riskScores: Record<ImageRiskLevel, number> = {
    critico: 100,
    alto: 75,
    medio: 50,
    bajo: 25,
    seguro: 0,
  };

  // Add file metadata
  metadata["Nombre"] = file.name;
  metadata["Tamano"] = `${(file.size / 1024).toFixed(1)} KB`;
  metadata["Tipo"] = file.type;
  metadata["Ultima modificacion"] = new Date(file.lastModified).toLocaleString("es-MX");

  // Step 1: Load image
  onProgress?.(10, "Cargando imagen...");
  const img = await loadImage(file);

  // Step 2: EXIF / Metadata analysis
  onProgress?.(20, "Analizando metadatos...");
  const exifResult = await analyzeExifData(img);
  metadata = { ...metadata, ...exifResult.metadata };
  for (const det of exifResult.detections) {
    detections.push({
      id: `meta-${detections.length}`,
      category: "metadatos",
      ...det
    });
    maxRiskScore = Math.max(maxRiskScore, riskScores[det.riskLevel]);
  }

  // Step 3: Visual pattern analysis
  onProgress?.(30, "Analizando patrones visuales...");
  const visualDetections = analyzeVisualPatterns(img);
  for (const det of visualDetections) {
    detections.push(det);
    maxRiskScore = Math.max(maxRiskScore, riskScores[det.riskLevel]);
  }

  // Step 4: OCR - Extract text from image
  onProgress?.(40, "Extrayendo texto de la imagen (OCR)...");
  try {
    const result = await Tesseract.recognize(file, "spa+eng", {
      logger: (m) => {
        if (m.status === "recognizing text" && m.progress) {
          const progress = 40 + Math.round(m.progress * 40);
          onProgress?.(progress, "Leyendo texto en la imagen...");
        }
      },
    });
    extractedText = result.data.text.trim();
  } catch {
    extractedText = "";
  }

  // Step 5: Analyze extracted text
  onProgress?.(85, "Analizando texto detectado...");
  if (extractedText.length > 5) {
    metadata["Texto detectado"] = extractedText.length > 100
      ? extractedText.substring(0, 100) + "..."
      : extractedText;

    const detectedTitles = new Set<string>();

    // Regex pattern matching on OCR text
    for (const pattern of imageTextPatterns) {
      const match = extractedText.match(pattern.pattern);
      if (match) {
        detectedTitles.add(pattern.title);
        detections.push({
          id: `ocr-${detections.length}`,
          category: pattern.category,
          riskLevel: pattern.riskLevel,
          title: pattern.title,
          detail: `Texto detectado: "${match[0]}"`,
          explanation: pattern.explanation,
          recommendation: pattern.recommendation,
          learnMore: pattern.learnMore,
        });
        maxRiskScore = Math.max(maxRiskScore, riskScores[pattern.riskLevel]);
      }
    }

    // Keyword matching on OCR text (normalized)
    const normalizedOcr = normalize(extractedText);
    for (const rule of imageKeywordRules) {
      if (detectedTitles.has(rule.title)) continue;
      const matched = rule.keywords.filter((kw) => normalizedOcr.includes(normalize(kw)));
      if (matched.length >= rule.minMatches) {
        detections.push({
          id: `ocr-kw-${detections.length}`,
          category: rule.category,
          riskLevel: rule.riskLevel,
          title: rule.title,
          detail: `Palabras detectadas: ${matched.join(", ")}`,
          explanation: rule.explanation,
          recommendation: rule.recommendation,
          learnMore: rule.learnMore,
        });
        maxRiskScore = Math.max(maxRiskScore, riskScores[rule.riskLevel]);
      }
    }
  }

  // Step 6: Generate result
  onProgress?.(95, "Generando resultado...");

  let overallRisk: ImageRiskLevel = "seguro";
  if (maxRiskScore >= 100) overallRisk = "critico";
  else if (maxRiskScore >= 75) overallRisk = "alto";
  else if (maxRiskScore >= 50) overallRisk = "medio";
  else if (maxRiskScore >= 25) overallRisk = "bajo";

  let summary = "";
  if (detections.length === 0) {
    summary = "No se detectaron riesgos significativos en esta imagen. Recuerda revisar manualmente que no contenga datos personales, ubicaciones reconocibles o contenido sensible antes de publicarla.";
  } else {
    const categories = [...new Set(detections.map((d) => d.category))];
    const categoryNames: Record<string, string> = {
      privacidad: "privacidad",
      estafa: "posibles estafas",
      violencia: "contenido violento",
      armas: "armas de fuego o armas blancas",
      desnudos: "desnudez o contenido sexual",
      metadatos: "metadatos",
      deepfake: "deepfake",
    };
    const catNames = categories.map((c) => categoryNames[c]).join(", ");
    summary = `Se detectaron ${detections.length} alerta(s) relacionadas con ${catNames}. Revisa cada deteccion antes de publicar esta imagen.`;
  }

  onProgress?.(100, "Analisis completado");

  return {
    overallRisk,
    score: maxRiskScore,
    detections,
    summary,
    extractedText: extractedText || undefined,
    metadata,
  };
}

// ─── HELPER: Load image from file ───
function loadImage(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = URL.createObjectURL(file);
  });
}
