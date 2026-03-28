// CiberShield Analysis Engine
// Pattern-based detection for educational purposes
// v2.0 — Flexible matching with accent tolerance and keyword detection

export type RiskLevel = "critico" | "alto" | "medio" | "bajo" | "seguro";

export interface Detection {
  id: string;
  category: "emocional" | "privacidad" | "grooming" | "deepfake";
  riskLevel: RiskLevel;
  title: string;
  matchedText?: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}

export interface AnalysisResult {
  overallRisk: RiskLevel;
  score: number; // 0-100, higher = more risky
  detections: Detection[];
  summary: string;
}

// Helper: normalize text (remove accents, lowercase) for flexible matching
function normalize(text: string): string {
  return text
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ñ/g, "n");
}

// ─── EMOTIONAL RISK PATTERNS ───
const emotionalPatterns: Array<{
  pattern: RegExp;
  riskLevel: RiskLevel;
  title: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}> = [
  {
    pattern: /\b(quiero morir|no quiero vivir|me quiero matar|suicid\w*|acabar con todo|quitarme la vida|ya no quiero estar aqui|ojala? me muriera|me quiero morir|quisiera estar muert[oa]|mejor me muero|ya no aguanto mas|ya no puedo seguir)\b/i,
    riskLevel: "critico",
    title: "Expresion de ideacion suicida",
    explanation: "Este mensaje contiene expresiones que pueden indicar pensamientos suicidas o autolesion. En redes sociales, estas expresiones pueden ser una senal de alerta real o un intento de manipulacion emocional.",
    recommendation: "Si conoces a esta persona, contacta inmediatamente a una linea de ayuda profesional. Si es contenido propio, busca apoyo psicologico. Linea de la vida: 800-911-2000.",
    learnMore: "La deteccion temprana de riesgo suicida en redes sociales es fundamental. Estudios muestran que el 80% de las personas que intentan suicidio dan senales previas en linea."
  },
  {
    pattern: /\b(me siento sol[oa]|nadie me quiere|no tengo amigos|soy un[a]? fracas\w*|no valgo nada|soy inutil|nadie me entiende|estoy sol[oa] en esto|nadie se preocupa por mi|no le importo a nadie|siento que sobro|no sirvo para nada|me siento vaci[oa]|todo mundo me ignora|soy un estorbo|soy una carga)\b/i,
    riskLevel: "alto",
    title: "Vulnerabilidad emocional expuesta",
    explanation: "Compartir sentimientos de soledad extrema o baja autoestima en redes sociales crea un perfil de vulnerabilidad. Los depredadores en linea buscan activamente este tipo de publicaciones para identificar victimas potenciales.",
    recommendation: "Evita publicar estados emocionales vulnerables de forma publica. Comparte estos sentimientos en entornos seguros y con personas de confianza. Considera hablar con un profesional.",
    learnMore: "El 65% de los casos de grooming comienzan con el depredador identificando expresiones de soledad o baja autoestima en perfiles publicos."
  },
  {
    pattern: /\b(te odio|voy a golpear|te voy a buscar|te arrepentir[aá]s|amenaz\w*|vas a pagar|te voy a partir|te voy a matar|te va a ir mal|cuidate la espalda|ya ver[aá]s lo que te pasa|me las vas a pagar|te voy a encontrar|donde te agarre)\b/i,
    riskLevel: "critico",
    title: "Contenido amenazante detectado",
    explanation: "Este mensaje contiene amenazas directas que pueden constituir ciberacoso o cyberbullying. Las amenazas en linea pueden escalar a violencia real y tienen consecuencias legales.",
    recommendation: "Documenta la amenaza con capturas de pantalla. Reporta al administrador de la plataforma y, si la amenaza es seria, denuncia ante las autoridades. No respondas al agresor.",
    learnMore: "En Mexico, las amenazas en linea son un delito tipificado. El ciberacoso puede derivar en sanciones penales segun la Ley Olimpia y codigos penales estatales."
  },
  {
    pattern: /\b(estoy muy deprimid[oa]|no puedo m[aá]s|todo me sale mal|la vida no tiene sentido|estoy desesperada?o?|estoy hart[oa] de todo|ya no le encuentro sentido|nada me importa|ya nada tiene sentido|todo es una mierda|odio mi vida|mi vida es un asco|estoy cansad[oa] de todo|ya me rendi|no tengo ganas de nada|para que seguir)\b/i,
    riskLevel: "alto",
    title: "Senales de angustia emocional",
    explanation: "Publicar estados de angustia emocional profunda en redes sociales expone a la persona a riesgos: manipulacion emocional, grooming, o aprovechamiento por parte de personas malintencionadas.",
    recommendation: "Antes de publicar, reflexiona si este contenido te pone en una posicion vulnerable. Busca apoyo en circulos cerrados de confianza, no en publicaciones abiertas.",
    learnMore: "Los algoritmos de redes sociales pueden amplificar contenido emocionalmente intenso, creando un ciclo de retroalimentacion negativa que empeora el estado emocional."
  },
  {
    pattern: /\b(me corto|autolesion|me hago da[nñ]o|cutting|me lastimo|me hago cortadas|me quemo|me golpeo a mi mism[oa]|me rasgu[nñ]o|cicatrices de|marcas en mis brazos)\b/i,
    riskLevel: "critico",
    title: "Referencia a autolesion",
    explanation: "Contenido relacionado con autolesion es extremadamente sensible. En redes sociales puede normalizar estas conductas o generar efecto de imitacion, especialmente entre adolescentes.",
    recommendation: "Este contenido debe ser reportado a la plataforma. Si es contenido propio, busca ayuda profesional inmediata. Si es de alguien que conoces, contacta a un adulto de confianza.",
    learnMore: "El efecto Werther o 'contagio suicida' es un fenomeno documentado donde la exposicion a contenido de autolesion incrementa el riesgo de imitacion."
  },
  {
    pattern: /\b(me hacen bullying|me molestan|se burlan de mi|me excluyen|me acosan|me hostigan|me mandan mensajes feos|me insultan|me ponen apodos|me empujan|me pegan en la escuela|me tratan mal|me humillan|me hacen menos|me discriminan|me rechazan)\b/i,
    riskLevel: "medio",
    title: "Posible victima de acoso",
    explanation: "Este mensaje sugiere que la persona puede estar experimentando acoso. Publicar esto abiertamente puede intensificar la situacion si los agresores ven el contenido.",
    recommendation: "Documenta los incidentes de acoso, reporta a las autoridades de la plataforma y habla con un adulto de confianza. Evita publicar detalles que identifiquen a los agresores o provoquen escalamiento.",
    learnMore: "El ciberbullying afecta al 35% de los adolescentes en America Latina. Las victimas que publican su situacion en redes a menudo sufren un aumento del acoso."
  },
  {
    pattern: /\b(ansiedad|ataque de p[aá]nico|no puedo respirar|me da miedo salir|no puedo dormir|insomnio|pesadillas|me tiemblan las manos|lloro todos los d[ií]as|no paro de llorar|crisis nerviosa|trastorno|medicamento para|pastillas para dormir|antidepresivos)\b/i,
    riskLevel: "medio",
    title: "Informacion de salud mental expuesta",
    explanation: "Compartir detalles sobre condiciones de salud mental o tratamientos en redes sociales puede ser usado para manipulacion, discriminacion o estigmatizacion.",
    recommendation: "Tu salud mental es informacion privada. Compartirla en foros publicos puede exponerte a juicios, discriminacion laboral o manipulacion. Busca grupos de apoyo privados y profesionales.",
    learnMore: "La informacion sobre salud mental compartida en redes sociales puede ser recopilada por anunciantes, empleadores potenciales o personas malintencionadas."
  }
];

// ─── PRIVACY PATTERNS ───
const privacyPatterns: Array<{
  pattern: RegExp;
  riskLevel: RiskLevel;
  title: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}> = [
  {
    pattern: /\b(estoy en|me encuentro en|vivo en|mi casa queda en|mi direcci[oó]n es|estoy por|ando por|ando en|me encuentro por|aqu[ií] en)\s+[A-ZÁÉÍÓÚa-záéíóú\s,#\.]+/i,
    riskLevel: "critico",
    title: "Ubicacion fisica compartida",
    explanation: "Compartir tu ubicacion exacta o direccion en redes sociales es una de las acciones mas peligrosas. Esta informacion puede ser usada para acoso, robo, secuestro o seguimiento fisico.",
    recommendation: "Nunca compartas tu direccion exacta en redes sociales. Desactiva la geolocalizacion en tus publicaciones. Si necesitas dar una ubicacion, usa referencias generales.",
    learnMore: "El 78% de los robos a domicilio en zonas urbanas de Mexico estan vinculados a informacion compartida en redes sociales, segun datos de seguridad publica."
  },
  {
    pattern: /\b(mi tel[eé]fono es|ll[aá]mame al|mi cel es|mi n[uú]mero es|whatsapp|mi whats|mi wa es|mi tel es|m[aá]rcame al|este es mi n[uú]mero|agr[eé]game al|mi celular es)\s*[:\s]?\s*[\d\+\(\)\-\s]{7,}/i,
    riskLevel: "critico",
    title: "Numero telefonico expuesto",
    explanation: "Un numero de telefono es informacion personal altamente sensible. Puede usarse para SIM swapping, acoso telefonico, suplantacion de identidad, y acceso a cuentas vinculadas a ese numero.",
    recommendation: "Elimina inmediatamente cualquier publicacion que contenga tu numero. Usa canales privados y cifrados para compartir datos de contacto.",
    learnMore: "El SIM swapping ha crecido un 400% en America Latina. Con tu numero, un atacante puede acceder a tus cuentas bancarias, redes sociales y correos electronicos."
  },
  {
    pattern: /\b(mi escuela es|estudio en|voy a la escuela|trabajo en|mi trabajo es|voy en la prepa|estoy en la secundaria|voy en la uni|mi facultad|estudio la carrera|soy alumno de|soy estudiante de|trabajo de|chambeo en)\b/i,
    riskLevel: "alto",
    title: "Informacion institucional revelada",
    explanation: "Revelar donde estudias o trabajas permite a potenciales acosadores localizarte fisicamente. Combinado con horarios publicados, crea un patron de movimientos predecible.",
    recommendation: "Limita la informacion sobre tu escuela o trabajo a perfiles privados. Nunca combines esta informacion con horarios o rutas.",
    learnMore: "Los depredadores usan la combinacion escuela + horario + fotos geolocalizadas para establecer patrones de movimiento de sus victimas."
  },
  {
    pattern: /\b(mi contrase[nñ]a|password|mi clave|mi nip|pin|mi pass)\s*(es|:)\s*\S+/i,
    riskLevel: "critico",
    title: "Credenciales expuestas",
    explanation: "Compartir contrasenas, NIP o claves de acceso en cualquier red social es extremadamente peligroso. Estas credenciales pueden ser usadas para acceso no autorizado a tus cuentas.",
    recommendation: "Cambia inmediatamente cualquier credencial que hayas compartido. Usa un gestor de contrasenas. Nunca compartas claves por mensajes, ni siquiera privados.",
    learnMore: "El 81% de las brechas de seguridad estan relacionadas con contrasenas debiles o comprometidas. Una contrasena publicada en redes se propaga en minutos."
  },
  {
    pattern: /\b(me voy de vacaciones|salimos de viaje|la casa sola|no hay nadie en casa|nos fuimos todos|no estoy en mi casa|casa vac[ií]a|nos vamos de viaje|me fui de viaje|estoy fuera de casa|salgo de viaje)\b/i,
    riskLevel: "alto",
    title: "Ausencia del hogar anunciada",
    explanation: "Anunciar que tu casa estara vacia es una invitacion abierta para criminales. Los ladrones monitorizan activamente redes sociales buscando casas desocupadas.",
    recommendation: "Comparte fotos y experiencias de viaje DESPUES de regresar, no durante. Evita publicar en tiempo real cuando no estas en casa.",
    learnMore: "El 80% de los ladrones profesionales revisan redes sociales de sus posibles victimas antes de actuar, buscando patrones de ausencia."
  },
  {
    pattern: /\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b/,
    riskLevel: "critico",
    title: "Posible numero de tarjeta",
    explanation: "Un patron de 16 digitos puede ser un numero de tarjeta de credito o debito. Compartir datos financieros en redes sociales facilita el fraude y clonacion de tarjetas.",
    recommendation: "Elimina inmediatamente esta publicacion. Contacta a tu banco para verificar que no haya cargos no reconocidos. Considera solicitar una nueva tarjeta.",
    learnMore: "Mexico ocupa el 8vo lugar mundial en fraude con tarjetas. Un numero de tarjeta publicado puede ser utilizado en segundos para compras fraudulentas."
  },
  {
    pattern: /\b(mi nombre completo es|me llamo|mi CURP|mi RFC|mi INE|credencial de elector|mi nombre real|mi apellido es|mi nombre de pila)\b/i,
    riskLevel: "alto",
    title: "Datos de identidad personal",
    explanation: "Datos como CURP, RFC o nombre completo pueden usarse para robo de identidad, apertura de cuentas fraudulentas, y suplantacion de identidad ante instituciones.",
    recommendation: "Nunca publiques documentos de identidad ni datos personales completos. Tapa datos sensibles si necesitas compartir una imagen de un documento.",
    learnMore: "El robo de identidad es el delito cibernetico de mayor crecimiento en Mexico. Con CURP y nombre completo, un criminal puede abrir cuentas bancarias y solicitar creditos."
  },
  {
    pattern: /\b(foto de mi hij[oa]|mi hij[oa] tiene \d+|mis hij[oa]s van a|mi beb[eé]|mi ni[nñ][oa] en|mi peque[nñ][oa]|aqui mi beb[eé]|mi hijo en la escuela|mi hija en)\b/i,
    riskLevel: "alto",
    title: "Informacion de menores expuesta",
    explanation: "Compartir informacion sobre menores (ubicacion, escuela, rutinas, fotos) los expone a riesgos de grooming, secuestro y explotacion. Los depredadores recopilan esta informacion sistematicamente.",
    recommendation: "Limita las fotos de menores a circulos privados. Nunca publiques informacion que permita localizar o identificar a un menor en combinacion con su rutina.",
    learnMore: "UNICEF reporta que el 1 de cada 3 usuarios de internet es un menor. El sharenting (compartir excesivamente sobre hijos) es un vector creciente de riesgo."
  },
  {
    pattern: /\b(mi correo es|mi email es|mi mail es|escr[ií]beme a|contactame en)\s*\S*@\S*/i,
    riskLevel: "medio",
    title: "Correo electronico expuesto",
    explanation: "Publicar tu correo electronico en redes sociales facilita ataques de phishing dirigido, spam, y puede ser usado para recuperar acceso a tus otras cuentas.",
    recommendation: "No publiques tu correo principal en redes sociales. Si necesitas compartirlo, usa un correo secundario exclusivo para contacto publico.",
    learnMore: "El phishing dirigido (spear phishing) utiliza correos electronicos recopilados de redes sociales para crear ataques personalizados con mayor tasa de exito."
  },
  {
    pattern: /\b(tengo \d+ a[nñ]os|nac[ií] en \d{4}|mi cumplea[nñ]os es|mi fecha de nacimiento|cumplo a[nñ]os el)\b/i,
    riskLevel: "medio",
    title: "Edad o fecha de nacimiento expuesta",
    explanation: "La edad y fecha de nacimiento son datos usados frecuentemente como preguntas de seguridad en servicios financieros. Combinados con otros datos, facilitan el robo de identidad.",
    recommendation: "Evita publicar tu edad exacta o fecha de nacimiento en perfiles publicos. Configura esta informacion como privada en todas tus redes sociales.",
    learnMore: "La fecha de nacimiento es uno de los tres datos mas usados para verificacion de identidad. Publicarla facilita que terceros suplanten tu identidad ante bancos y servicios."
  }
];

// ─── GROOMING PATTERNS ───
const groomingPatterns: Array<{
  pattern: RegExp;
  riskLevel: RiskLevel;
  title: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}> = [
  {
    pattern: /\b(eres muy madur[oa] para tu edad|no pareces de \d+|eres diferente a los dem[aá]s|tu si me entiendes|eres muy especial|no eres como las dem[aá]s|eres [uú]nic[oa]|me encantas|nunca conoc[ií] a alguien como t[uú]|eres muy bonit[oa]|eres muy guap[oa] para tu edad|pareces m[aá]s grande)\b/i,
    riskLevel: "critico",
    title: "Halago manipulador (fase de confianza)",
    explanation: "Frases como 'eres muy madura para tu edad' son tacticas clasicas de grooming. El depredador busca hacer sentir especial a la victima para crear un vinculo emocional que permita la manipulacion.",
    recommendation: "Si un adulto desconocido te dice estas frases, bloquea inmediatamente. Informa a un adulto de confianza. Estos halagos son senales de alerta de grooming.",
    learnMore: "El modelo de grooming de Olson (2007) identifica 5 fases: seleccion, acceso, confianza, desensibilizacion y mantenimiento. Los halagos manipuladores son la fase 3."
  },
  {
    pattern: /\b(esto es nuestro secreto|no le digas a nadie|entre t[uú] y yo|no le cuentes a tus pap[aá]s|que nadie sepa|no se lo digas a nadie|queda entre nosotros|no le vayas a decir|prométeme que no dices nada|nadie tiene que saber|si le dices a alguien|no se lo cuentes)\b/i,
    riskLevel: "critico",
    title: "Imposicion de secretismo",
    explanation: "El secretismo es una de las herramientas mas peligrosas del grooming. El depredador aisla a la victima de su red de apoyo para tener control total sobre la relacion.",
    recommendation: "Cualquier adulto que pida mantener secretos a un menor esta actuando de forma inapropiada. Reporta inmediatamente a un adulto de confianza y a las autoridades.",
    learnMore: "El 93% de los casos de abuso sexual infantil involucran alguna forma de secretismo impuesto. El aislamiento es fundamental para que el depredador mantenga el control."
  },
  {
    pattern: /\b(m[aá]ndame una foto|quiero verte|enciende la c[aá]mara|tienes foto|env[ií]ame foto|pasa foto|manda foto|quiero ver c[oó]mo te ves|m[aá]ndame un selfie|pasa tu foto|quiero una foto tuya|pr[eé]ndele a la cam|p[aá]same foto)\b/i,
    riskLevel: "alto",
    title: "Solicitud de material visual",
    explanation: "Solicitar fotos o video en contextos de chat puede ser una tactica de escalamiento en grooming. El objetivo es obtener material comprometedor que luego puede usarse para chantaje (sextorsion).",
    recommendation: "Nunca envies fotos personales a desconocidos. Si alguien insiste en obtener fotos tuyas, bloquea y reporta. Si ya enviaste material, busca ayuda profesional.",
    learnMore: "La sextorsion ha aumentado un 300% en America Latina. El material visual obtenido en el grooming se usa para chantajear a la victima y exigir mas material o dinero."
  },
  {
    pattern: /\b(nos podemos ver|quiero conocerte en persona|vamos a vernos|te paso a buscar|ven a mi casa|nos vemos en|quiero verte en persona|paso por ti|te recojo|te invito a mi depa|ven a mi cuarto|vernos a solas|encontrarnos en alg[uú]n lugar|te quiero ver)\b/i,
    riskLevel: "critico",
    title: "Intento de encuentro presencial",
    explanation: "La solicitud de encuentro fisico es la fase final y mas peligrosa del grooming. El depredador busca trasladar la relacion digital al mundo real donde puede ejercer control directo.",
    recommendation: "NUNCA aceptes encontrarte con alguien que conociste en linea sin la presencia de un adulto de confianza. Informa inmediatamente a tus padres o tutores.",
    learnMore: "El 16% de los adolescentes que han recibido propuestas de encuentro en linea han acudido. De estos, el 75% fueron victimas de algun tipo de agresion."
  },
  {
    pattern: /\b(cu[aá]ntos a[nñ]os tienes|qu[eé] edad tienes|eres menor|en qu[eé] grado vas|vas a la secundaria|en qu[eé] a[nñ]o vas|eres de prepa|cu[aá]ntos a[nñ]os cumpliste|qu[eé] tan grande eres|ya cumpliste \d+|eres chic[oa]|eres joven)\b/i,
    riskLevel: "medio",
    title: "Indagacion de edad",
    explanation: "Preguntar la edad de forma reiterada o temprana en una conversacion puede indicar interes predatorio. Los depredadores verifican la edad para seleccionar victimas vulnerables.",
    recommendation: "No reveles tu edad real a desconocidos en linea. Si un adulto insiste en conocer tu edad, es una senal de alerta. Configura tu perfil como privado.",
    learnMore: "La fase de seleccion del grooming incluye la busqueda activa de menores que revelen su edad. Perfiles publicos con edad visible son el primer filtro del depredador."
  },
  {
    pattern: /\b(tus pap[aá]s no te entienden|tus padres son injustos|yo s[ií] te escucho|ellos no te merecen|yo te valoro m[aá]s|tus pap[aá]s no te quieren|conmigo vas a estar mejor|tus padres no saben nada|ellos no te cuidan|yo te cuido mejor|no les hagas caso a tus pap[aá]s|tus padres son el problema)\b/i,
    riskLevel: "alto",
    title: "Triangulacion contra figuras de autoridad",
    explanation: "El depredador intenta crear una brecha entre la victima y sus protectores naturales (padres, maestros). Al desacreditar a los adultos de confianza, el depredador se posiciona como unica fuente de apoyo.",
    recommendation: "Desconfia de cualquier persona en linea que intente ponerte en contra de tus padres o adultos de confianza. Esta es una tactica de manipulacion documentada.",
    learnMore: "La alienacion de figuras protectoras es una estrategia sistematica del grooming. El depredador necesita eliminar la red de seguridad del menor para operar sin deteccion."
  },
  {
    pattern: /\b(tienes novi[oa]|ya has besado|has tenido relaciones|eres virgen|te has tocado|tienes experiencia|has hecho algo con alguien|qu[eé] tan lejos has llegado|te gusta alguien|te atraen los hombres|te atraen las mujeres|alguna vez has hecho|con cuantas personas)\b/i,
    riskLevel: "critico",
    title: "Contenido sexualizado dirigido a menor",
    explanation: "Preguntas de naturaleza sexual hacia menores son una senal inequivoca de abuso potencial. Esta es la fase de desensibilizacion donde el depredador normaliza el contenido sexual.",
    recommendation: "Reporta inmediatamente a la plataforma y a las autoridades. Guarda evidencia (capturas de pantalla). Contacta la linea de ayuda contra la explotacion sexual infantil.",
    learnMore: "La desensibilizacion sexual es la fase 4 del modelo de grooming. El depredador introduce gradualmente temas sexuales para normalizar el abuso futuro."
  },
  {
    pattern: /\b(te voy a dar dinero|te compro lo que quieras|te mando dinero|te doy un regalo|te quiero regalar|te deposito|te hago una transferencia|quieres que te compre|te pago por)\b/i,
    riskLevel: "alto",
    title: "Ofrecimiento de regalos o dinero",
    explanation: "El ofrecimiento de regalos, dinero o beneficios materiales por parte de desconocidos es una tactica de grooming para crear dependencia y sentimiento de deuda en la victima.",
    recommendation: "Nunca aceptes dinero ni regalos de personas que conociste en linea. Esta es una estrategia para crear una relacion de poder y obligacion.",
    learnMore: "La fase de acceso del grooming frecuentemente incluye regalos y favores. El depredador invierte recursos para que la victima sienta que 'le debe algo'."
  }
];

// ─── DEEPFAKE PATTERNS ───
const deepfakePatterns: Array<{
  pattern: RegExp;
  riskLevel: RiskLevel;
  title: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
}> = [
  {
    pattern: /\b(mira este video de|sale en un video|video [ií]ntimo de|video sexual de|filtraron un video|se filtro un video|anda circulando un video|video privado de|video de tu compañera|video de tu amiga)\b/i,
    riskLevel: "critico",
    title: "Posible deepfake o material no consensuado",
    explanation: "Los mensajes que comparten supuestos 'videos intimos filtrados' frecuentemente involucran deepfakes (videos falsos generados con IA) o material de difusion no consensuada. Compartirlos es un delito.",
    recommendation: "No abras ni compartas este tipo de enlaces. Reporta el contenido a la plataforma. La distribucion de material intimo no consensuado esta penalizada por la Ley Olimpia.",
    learnMore: "Los deepfakes sexuales representan el 96% de todos los deepfakes en internet. La tecnologia permite crear videos falsos hiperrealistas con solo unas pocas fotos de la victima."
  },
  {
    pattern: /\b(genera una imagen|crea un video|pon mi cara en|faceswap|face swap|cambia la cara|genera un deepfake|haz un video falso|ponle la cara de|intercambia la cara|desnud\w* con ia|genera\w* desnud\w*)\b/i,
    riskLevel: "alto",
    title: "Solicitud de manipulacion con IA",
    explanation: "Solicitar o crear imagenes/videos manipulados con IA puede derivar en deepfakes que se usan para difamacion, pornovenganza, fraude o suplantacion de identidad.",
    recommendation: "El uso de IA para crear contenido no consensuado de otras personas es ilegal en muchos paises. No participes en la creacion ni distribucion de este material.",
    learnMore: "Herramientas de face swap estan disponibles gratuitamente, lo que ha democratizado la creacion de deepfakes. En 2025, se estima que el 90% de contenido visual falso sera generado por IA."
  },
  {
    pattern: /\b(es real este video|ser[aá] verdad|esto es fake|parece falso|es verdadero|esto no puede ser real|ser[aá] cierto|es real o falso|no me lo creo|esto es real|esto ser[aá] verdad|es falso|no es real)\b/i,
    riskLevel: "medio",
    title: "Cuestionamiento de autenticidad",
    explanation: "Es positivo cuestionar la autenticidad de contenido en linea. Sin embargo, la incapacidad de distinguir deepfakes de contenido real es un riesgo creciente que requiere alfabetizacion digital.",
    recommendation: "Verifica contenido sospechoso: busca inconsistencias en bordes faciales, parpadeo irregular, iluminacion inconsistente, y audio desincronizado. Usa herramientas de verificacion.",
    learnMore: "Solo el 30% de las personas pueden distinguir un deepfake de alta calidad. Tecnicas de verificacion: analizar la fuente, buscar la imagen original con busqueda inversa, verificar metadatos."
  },
  {
    pattern: /\b(voz clonada|voz artificial|me llamaron y sonaba como|imit[oó] mi voz|voz de ia|audio falso|clonaron mi voz|sonaba igualito a|parec[ií]a su voz pero|voz generada|llamada falsa|llamada sospechosa)\b/i,
    riskLevel: "alto",
    title: "Deepfake de audio / Voz clonada",
    explanation: "La clonacion de voz con IA permite crear audios hiperrealistas con solo 3 segundos de muestra. Se usa para fraudes telefonicos, extorsion y manipulacion emocional.",
    recommendation: "Establece una 'palabra clave' familiar que solo tu y tus seres queridos conozcan para verificar identidad en llamadas sospechosas. Desconfia de llamadas urgentes que pidan dinero.",
    learnMore: "Los fraudes por voz clonada han crecido un 700% desde 2023. Un atacante puede clonar tu voz desde audios publicos en redes sociales o mensajes de voz."
  },
  {
    pattern: /\b(foto retocada|photoshop|imagen editada|trucada|imagen falsa|foto manipulada|imagen generada|foto con filtro|editada con ia|generada con ia|hecha con ia|creada con inteligencia artificial)\b/i,
    riskLevel: "bajo",
    title: "Conciencia de manipulacion visual",
    explanation: "Reconocer imagenes editadas o generadas por IA es una habilidad critica de alfabetizacion digital. Las imagenes manipuladas se usan para desinformacion, fraude y dano reputacional.",
    recommendation: "Desarrolla el habito de verificar imagenes antes de compartirlas. Usa busqueda inversa de imagenes (Google Lens, TinEye) y analiza metadatos EXIF cuando sea posible.",
    learnMore: "Las imagenes generadas por IA pueden detectarse por: textura de piel demasiado perfecta, fondos inconsistentes, detalles anomalos en manos/orejas, y texto ilegible en fondos."
  },
  {
    pattern: /\b(me suplantaron|crearon un perfil falso|alguien se hace pasar por mi|perfil fake|cuenta falsa con mi nombre|robaron mi identidad|hackearon mi cuenta|me clonaron el perfil|alguien usa mi foto|perfil falso|se hicieron pasar por m[ií])\b/i,
    riskLevel: "alto",
    title: "Suplantacion de identidad digital",
    explanation: "La suplantacion de identidad en redes sociales puede incluir el uso de fotos reales o deepfakes para crear perfiles falsos. Estos perfiles se usan para estafas, difamacion o acoso.",
    recommendation: "Reporta el perfil falso a la plataforma. Documenta con capturas de pantalla. Alerta a tus contactos. Si involucra fraude, presenta denuncia ante las autoridades.",
    learnMore: "La suplantacion de identidad digital es delito en Mexico. Las plataformas estan obligadas a eliminar perfiles falsos cuando se reportan con evidencia suficiente."
  },
  {
    pattern: /\b(noticias falsas|fake news|desinformaci[oó]n|informaci[oó]n falsa|bulo|es mentira|no es cierto|no le crean|es propaganda|manipulaci[oó]n medi[aá]tica)\b/i,
    riskLevel: "bajo",
    title: "Contenido potencialmente desinformativo",
    explanation: "La desinformacion se propaga 6 veces mas rapido que la informacion verificada en redes sociales. Los deepfakes son una herramienta creciente para crear noticias falsas convincentes.",
    recommendation: "Antes de compartir noticias impactantes, verifica la fuente original. Consulta sitios de fact-checking como Verificado o Animal Politico. No compartas contenido solo porque confirma tus creencias.",
    learnMore: "El 86% de los internautas ha creido informacion falsa al menos una vez. La desinformacion genera reacciones emocionales que impulsan a compartir sin verificar."
  }
];

// ─── KEYWORD-BASED DETECTION (catches individual concerning words) ───
interface KeywordRule {
  keywords: string[];
  category: "emocional" | "privacidad" | "grooming" | "deepfake";
  riskLevel: RiskLevel;
  title: string;
  explanation: string;
  recommendation: string;
  learnMore: string;
  minMatches: number; // how many keywords must match to trigger
}

const keywordRules: KeywordRule[] = [
  {
    keywords: ["suicidio", "suicidarme", "suicida", "matarme", "morir", "muerte"],
    category: "emocional",
    riskLevel: "critico",
    title: "Palabras asociadas a riesgo vital",
    explanation: "Se detectaron palabras que pueden estar asociadas con pensamientos de autolesion o riesgo vital. Aunque el contexto puede variar, es importante prestar atencion a estas senales.",
    recommendation: "Si este contenido refleja sentimientos reales, busca ayuda profesional. Linea de la vida: 800-911-2000. Si es de otra persona, no ignores la senal.",
    learnMore: "Las senales linguisticas de riesgo suicida incluyen palabras absolutas ('nunca', 'siempre', 'nada'), referencias a muerte, y expresiones de desesperanza.",
    minMatches: 1
  },
  {
    keywords: ["depresion", "deprimido", "deprimida", "triste", "tristeza", "llorar", "lloro", "soledad", "vacio", "vacia", "angustia", "desesperacion", "sufro", "sufrimiento", "dolor emocional"],
    category: "emocional",
    riskLevel: "medio",
    title: "Vocabulario de vulnerabilidad emocional",
    explanation: "El texto contiene multiples palabras asociadas con estados emocionales vulnerables. Publicar este tipo de contenido en redes sociales puede atraer a personas manipuladoras.",
    recommendation: "Es valido expresar emociones, pero hazlo en entornos seguros y privados. Las redes sociales publicas no son el mejor espacio para compartir vulnerabilidad emocional profunda.",
    learnMore: "Los depredadores en linea utilizan algoritmos sociales y busquedas de hashtags relacionados con tristeza y soledad para identificar victimas potenciales.",
    minMatches: 2
  },
  {
    keywords: ["direccion", "colonia", "codigo postal", "calle", "numero de casa", "manzana", "lote", "departamento", "piso", "edificio"],
    category: "privacidad",
    riskLevel: "alto",
    title: "Posibles datos de ubicacion",
    explanation: "Se detectaron palabras que frecuentemente acompanan datos de ubicacion fisica. Compartir estos detalles facilita la localizacion por parte de terceros malintencionados.",
    recommendation: "Revisa que no estes compartiendo datos que permitan localizar tu domicilio o lugar frecuente. Elimina detalles especificos como numero de calle, colonia o codigo postal.",
    learnMore: "La geolocalizacion involuntaria es uno de los principales vectores de riesgo en redes sociales. Datos como colonia + calle son suficientes para localizar a una persona.",
    minMatches: 2
  },
  {
    keywords: ["nudes", "pack", "desnudo", "desnuda", "sin ropa", "encuerado", "encuerada", "foto intima", "fotos intimas", "contenido intimo", "video intimo"],
    category: "deepfake",
    riskLevel: "critico",
    title: "Contenido intimo o solicitud de material explicito",
    explanation: "Palabras relacionadas con contenido intimo pueden indicar sextorsion, distribucion no consensuada (Ley Olimpia), o solicitud de material de abuso. Este tipo de contenido tiene graves consecuencias legales.",
    recommendation: "NUNCA compartas material intimo en linea. Si alguien te lo solicita o te amenaza con distribuirlo, contacta a las autoridades. La Ley Olimpia protege a las victimas.",
    learnMore: "En Mexico, la Ley Olimpia tipifica como delito la difusion de contenido intimo sin consentimiento con penas de 3 a 6 anos de prision.",
    minMatches: 1
  },
  {
    keywords: ["regalo", "dinero", "transferencia", "deposito", "premio", "ganaste", "sorteo", "loteria", "herencia", "beneficiario"],
    category: "grooming",
    riskLevel: "medio",
    title: "Posible estafa o manipulacion economica",
    explanation: "Ofrecimientos de dinero, premios o regalos de desconocidos son tacticas comunes tanto en grooming como en fraude digital. Buscan crear dependencia o obtener datos personales.",
    recommendation: "Desconfia de ofertas de dinero o premios no solicitados. Nadie regala nada sin esperar algo a cambio. Verifica la identidad de quien ofrece y nunca compartas datos bancarios.",
    learnMore: "El 70% de las estafas en redes sociales involucran algun tipo de incentivo economico falso. Los jovenes son el grupo demografico mas vulnerable a estas tacticas.",
    minMatches: 2
  }
];

// ─── ANALYSIS FUNCTION ───
export function analyzeContent(text: string): AnalysisResult {
  const detections: Detection[] = [];
  let maxRiskScore = 0;

  const riskScores: Record<RiskLevel, number> = {
    critico: 100,
    alto: 75,
    medio: 50,
    bajo: 25,
    seguro: 0,
  };

  // Run all regex pattern categories
  const allPatterns = [
    ...emotionalPatterns.map((p) => ({ ...p, category: "emocional" as const })),
    ...privacyPatterns.map((p) => ({ ...p, category: "privacidad" as const })),
    ...groomingPatterns.map((p) => ({ ...p, category: "grooming" as const })),
    ...deepfakePatterns.map((p) => ({ ...p, category: "deepfake" as const })),
  ];

  // Track which categories already have detections (to avoid duplicates from keyword rules)
  const detectedTitles = new Set<string>();

  for (const patternDef of allPatterns) {
    const match = text.match(patternDef.pattern);
    if (match) {
      detectedTitles.add(patternDef.title);
      detections.push({
        id: `${patternDef.category}-${detections.length}`,
        category: patternDef.category,
        riskLevel: patternDef.riskLevel,
        title: patternDef.title,
        matchedText: match[0],
        explanation: patternDef.explanation,
        recommendation: patternDef.recommendation,
        learnMore: patternDef.learnMore,
      });
      maxRiskScore = Math.max(maxRiskScore, riskScores[patternDef.riskLevel]);
    }
  }

  // Run keyword-based detection (normalized, accent-tolerant)
  const normalizedText = normalize(text);
  for (const rule of keywordRules) {
    if (detectedTitles.has(rule.title)) continue; // Skip if already detected by regex
    
    const matchedKeywords: string[] = [];
    for (const kw of rule.keywords) {
      const normalizedKw = normalize(kw);
      if (normalizedText.includes(normalizedKw)) {
        matchedKeywords.push(kw);
      }
    }

    if (matchedKeywords.length >= rule.minMatches) {
      detections.push({
        id: `${rule.category}-kw-${detections.length}`,
        category: rule.category,
        riskLevel: rule.riskLevel,
        title: rule.title,
        matchedText: matchedKeywords.join(", "),
        explanation: rule.explanation,
        recommendation: rule.recommendation,
        learnMore: rule.learnMore,
      });
      maxRiskScore = Math.max(maxRiskScore, riskScores[rule.riskLevel]);
    }
  }

  // Determine overall risk
  let overallRisk: RiskLevel = "seguro";
  if (maxRiskScore >= 100) overallRisk = "critico";
  else if (maxRiskScore >= 75) overallRisk = "alto";
  else if (maxRiskScore >= 50) overallRisk = "medio";
  else if (maxRiskScore >= 25) overallRisk = "bajo";

  // Generate summary
  let summary = "";
  if (detections.length === 0) {
    summary = "No se detectaron riesgos significativos en este contenido. Sin embargo, recuerda que ningun filtro es infalible. Siempre aplica tu juicio critico antes de publicar.";
  } else {
    const categories = [...new Set(detections.map((d) => d.category))];
    const categoryNames: Record<string, string> = {
      emocional: "riesgo emocional",
      privacidad: "privacidad visual",
      grooming: "patrones de grooming",
      deepfake: "amenazas de deepfake",
    };
    const catNames = categories.map((c) => categoryNames[c]).join(", ");
    summary = `Se detectaron ${detections.length} alerta(s) en las categorias de ${catNames}. Revisa cada deteccion para entender por que este contenido podria ser riesgoso.`;
  }

  return {
    overallRisk,
    score: maxRiskScore,
    detections,
    summary,
  };
}

// ─── EXAMPLE SCENARIOS ───
export interface Scenario {
  id: string;
  title: string;
  description: string;
  text: string;
  category: "emocional" | "privacidad" | "grooming" | "deepfake" | "mixto";
}

export const exampleScenarios: Scenario[] = [
  {
    id: "s1",
    title: "Chat con desconocido",
    description: "Un adulto contacta a un menor por DM",
    text: "Hola, eres muy madura para tu edad. Me gustaria conocerte en persona. Esto es nuestro secreto, no le digas a nadie. ¿Cuantos anos tienes? Tus papas no te entienden como yo.",
    category: "grooming",
  },
  {
    id: "s2",
    title: "Publicacion emocional",
    description: "Post en red social con vulnerabilidad expuesta",
    text: "Me siento sola, nadie me quiere. Estoy muy deprimida y no puedo mas. No tengo amigos en la escuela y me hacen bullying todos los dias.",
    category: "emocional",
  },
  {
    id: "s3",
    title: "Exposicion de datos",
    description: "Mensaje que revela informacion personal",
    text: "Mi telefono es 55-1234-5678, llamame al WhatsApp. Estudio en la Secundaria Benito Juarez en Polanco. Me voy de vacaciones la proxima semana y no hay nadie en casa.",
    category: "privacidad",
  },
  {
    id: "s4",
    title: "Contenido deepfake",
    description: "Mensaje sobre video posiblemente manipulado",
    text: "Mira este video de tu compañera, filtraron un video intimo de ella. Alguien le hizo face swap con su cara. ¿Sera verdad o es fake? Me suplantaron y crearon un perfil falso con mi nombre.",
    category: "deepfake",
  },
  {
    id: "s5",
    title: "Escenario combinado",
    description: "Multiples riesgos en un solo mensaje",
    text: "Me siento sola y no valgo nada. Mi telefono es 55-9876-5432, mandame una foto para conocernos. Esto es nuestro secreto, no le cuentes a tus papas. Mira este video de la escuela.",
    category: "mixto",
  },
  {
    id: "s6",
    title: "Texto seguro",
    description: "Publicacion sin riesgos detectados",
    text: "Hoy tuve un gran dia en el parque con mis amigos. Jugamos futbol y comimos helado. Me encanta el atardecer desde el mirador de la ciudad.",
    category: "mixto",
  },
];
