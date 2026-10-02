"""Annotate normalized text with INTENT / DATA / SUBJECT / context labels.

Labels are plain strings (``intent:track``, ``data:home_address``, ``subject:person``, …).
Relation labels such as ``data:contact@person`` or ``intent:monitor@relational`` say that a data
item (or the object of an intent) is attached to a subject of that kind — via ``of``/``for``/
``de``…, ``'s`` or a possessive pronoun, within 8 tokens. Rule packs reference these labels;
:data:`KNOWN_LABELS` is the vocabulary a rule pack is validated against.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from angel_engine.policy import lexicons as lx
from angel_engine.policy.normalize import NormalizedText, Token
from angel_engine.policy.types import PolicyContext, Surface

SUBJECT_TYPES = (
    "organization",
    "website",
    "public_event",
    "public_figure_role",
    "individual",
    "image_provenance",
    "other",
    "unknown",
)
RELATION_KINDS = ("person", "relational", "public_role", "org")
_ATTACH_WINDOW = 8

# --------------------------------------------------------------------------------------------
# Phrase lexicons: label -> regex fragments matched on the normalized (casefolded) text.
# --------------------------------------------------------------------------------------------
_P = dict[str, tuple[str, ...]]

INTENT_PHRASES: _P = {
    "intent:find": (
        r"find(?:s|ing)?",
        r"found",
        r"locat(?:e|es|ed|ing)",
        r"look(?:s|ing)?\s+up",
        r"lookup",
        r"search(?:es|ing)?(?:\s+for)?",
        r"get(?:s|ting)?",
        r"obtain(?:ing)?",
        r"retriev(?:e|ing)",
        r"discover(?:ing)?",
        r"figure\s+out",
        r"find\s+out",
        r"dig\s+up",
        r"uncover(?:ing)?",
        r"track\s+down",
        r"hunt\s+down",
        r"pinpoint(?:ing)?",
        r"determine",
        r"show\s+me",
        r"give\s+me",
        r"tell\s+me",
        r"send\s+me",
        r"what\s+is",
        r"what's",
        r"whats",
        r"what\s+are",
        r"where\s+is",
        r"where's",
        r"list",
        r"encontrar",
        r"encuentra",
        r"buscar",
        r"busca",
        r"localizar",
        r"averiguar",
        r"achar",
        r"procurar",
        r"descobrir",
        r"trouver",
        r"trouve",
        r"chercher",
        r"cherche",
        r"localiser",
        r"finden",
        r"finde",
        r"suchen",
        r"suche",
        r"herausfinden",
        r"ermitteln",
        r"quiero",
        r"quero",
        r"je\s+veux",
        r"ich\s+will",
        r"cual\s+es",
        r"qual\s+e",
        r"quelle\s+est",
        r"was\s+ist",
    ),
    "intent:track": (
        r"track(?:s|ed|ing)?",
        r"trac(?:e|es|ed|ing)",
        r"tail(?:ing)?",
        r"shadow(?:ing)?",
        r"keep\s+tabs\s+on",
        r"keep\s+track\s+of",
        r"follow(?:ing)?\s+(?:her|him|them|my\s+\w+)(?!\s+on\b)",
        r"geolocat(?:e|ing)\s+(?:her|him|them|my)",
        r"rastrear",
        r"rastreie",
        r"seguir\s+a",
        r"suivre",
        r"pister",
        r"verfolgen",
        r"orten",
        r"tracken",
    ),
    "intent:monitor": (
        r"monitor(?:s|ed|ing)?",
        r"surveil(?:l|s|led|ling|lance)?",
        r"spy(?:ing)?(?:\s+on)?",
        r"spies\s+on",
        r"keep\s+an\s+eye\s+on",
        r"watch(?:ing)?\s+(?:her|him|them|my\s+\w+|this\s+(?:person|guy|girl|woman|man))",
        r"alert\s+me",
        r"notify\s+me",
        r"let\s+me\s+know\s+(?:when|whenever|if|every\s+time)",
        r"send\s+me\s+(?:an?\s+)?(?:alerts?|notifications?|updates?)",
        r"(?:every\s+time|whenever)\s+(?:she|he|they|my\s+\S+|\S+)\s+(?:posts?|goes|logs|checks|is|comes|leaves|tweets|uploads|updates)",
        r"real[\s-]?time\s+updates?",
        r"vigilar",
        r"monitorear",
        r"monitorar",
        r"espiar",
        r"surveiller",
        r"espionner",
        r"uberwachen",
        r"beobachten",
        r"ausspionieren",
    ),
    "intent:identify": (
        r"identif(?:y|ies|ied|ying|ication)",
        r"recogni[sz](?:e|es|ed|ing)",
        r"who\s+is",
        r"who's",
        r"whos",
        r"who\s+are",
        r"who\s+was",
        r"who\s+runs",
        r"who\s+operates",
        r"who\s+owns",
        r"who\s+controls",
        r"find\s+out\s+who",
        r"figure\s+out\s+who",
        r"tell\s+me\s+who",
        r"put\s+a\s+name\s+to",
        r"unmask(?:ing)?",
        r"de-?anonymi[sz](?:e|ing)",
        r"identificar",
        r"quien\s+es",
        r"quem\s+e",
        r"identifier",
        r"qui\s+est",
        r"identifizieren",
        r"wer\s+ist",
    ),
    "intent:dox": (r"doxx?(?:ing|ed|es)?", r"doxear", r"doxar"),
    "intent:expose": (
        r"unmask(?:ing)?",
        r"expose",
        r"exposing",
        r"reveal(?:ing)?\s+(?:the\s+)?(?:identity|real\s+name|name|address|who|where)",
        r"out\s+(?:her|him|them)",
        r"name\s+and\s+shame",
        r"publish\s+(?:her|his|their)\s+(?:address|details|info|information|identity|name|number|photos?)",
        r"leak\s+(?:her|his|their)\s+(?:address|details|info|number|photos|nudes)",
        r"de-?anonymi[sz](?:e|ing)",
        r"exponer",
        r"expor",
        r"exposer",
        r"blossstellen",
    ),
    "intent:bypass": (
        r"bypass(?:es|ed|ing)?",
        r"circumvent(?:s|ed|ing)?",
        r"get\s+(?:around|past|through|behind|into)",
        r"getting\s+(?:around|past|into)",
        r"go\s+around",
        r"break\s+into",
        r"break(?:ing)?\s+(?:the\s+)?(?:paywall|captcha|login|password|encryption)",
        r"hack(?:s|ed|ing)?(?:\s+into)?",
        r"crack(?:s|ed|ing)?",
        r"defeat(?:ing)?",
        r"evad(?:e|ing)",
        r"skip(?:ping)?",
        r"disabl(?:e|ing)",
        r"remov(?:e|ing)\s+(?:the\s+)?(?:paywall|login|captcha|blur|restriction|block)",
        r"solv(?:e|ing)\s+(?:the\s+)?captchas?",
        r"unlock(?:ing)?",
        r"without\s+(?:logging\s+in|login|log\s+in|an\s+account|signing\s+in|following|being\s+(?:a\s+)?(?:friend|follower)|permission|paying|a\s+subscription)",
        r"saltar",
        r"burlar",
        r"contornar",
        r"contourner",
        r"umgehen",
    ),
    "intent:access": (
        r"view(?:ing)?",
        r"see(?:ing)?",
        r"access(?:ing)?",
        r"open(?:ing)?",
        r"look\s+at",
        r"read(?:ing)?",
        r"download(?:ing)?",
        r"scrap(?:e|ing)",
        r"brows(?:e|ing)",
        r"get\s+into",
        r"ver",
        r"acceder",
        r"acessar",
        r"voir",
        r"ansehen",
    ),
    "intent:harass": (
        r"harass(?:es|ed|ing)?",
        r"(?:organi[sz]e|start|run|launch|plan|coordinate)\s+(?:a\s+)?harassment",
        r"threaten(?:s|ed|ing)?",
        r"intimidat(?:e|es|ed|ing|ion)",
        r"scare",
        r"frighten",
        r"bully(?:ing)?",
        r"humiliat(?:e|ing)",
        r"blackmail(?:ing)?",
        r"extort(?:ing|ion)?",
        r"send\s+(?:her|him|them)\s+threats",
        r"send\s+threats",
        r"get\s+back\s+at",
        r"revenge\s+on",
        r"take\s+revenge",
        r"ruin\s+(?:her|his|their)\s+(?:life|reputation|career)",
        r"make\s+(?:her|him|them)\s+(?:pay|suffer|afraid|scared)",
        r"show\s+up\s+(?:there|at\s+(?:her|his|their)\b|at\s+(?:the|her|his)\s+(?:house|home|door|work|office|school))",
        r"confront\s+(?:her|him|them)",
        r"swat(?:ting)?",
        r"acosar",
        r"amenazar",
        r"assediar",
        r"ameacar",
        r"harceler",
        r"menacer",
        r"belastigen",
        r"bedrohen",
    ),
    "intent:stalk": (r"stalk(?:s|ed|ing|er|ers)?", r"cyberstalk(?:ing)?", r"acechar", r"perseguir", r"traquer"),
    "intent:impersonate": (
        r"impersonat(?:e|es|ed|ing|ion)",
        r"pos(?:e|es|ing)\s+as",
        r"pretend(?:s|ing)?\s+to\s+be",
        r"fake\s+(?:profiles?|accounts?|pages?|personas?|identit(?:y|ies)|id)",
        r"sock\s?puppets?",
        r"catfish(?:ing)?",
        r"clone\s+(?:her|his|their|the)\s+(?:account|profile)",
        r"spoof(?:ing)?",
        r"masquerad(?:e|ing)\s+as",
        r"suplantar",
        r"fingir\s+ser",
        r"se\s+faire\s+passer\s+pour",
        r"usurper",
        r"ausgeben\s+als",
    ),
    "intent:research": (
        r"research(?:ing)?",
        r"investigat(?:e|es|ing)",
        r"background\s+(?:check|research|info|information|report)s?",
        r"find\s+(?:info|information|details|everything|anything|dirt)\s+(?:on|about)",
        r"look(?:ing)?\s+into",
        r"everything\s+about",
        r"all\s+about",
        r"dig\s+(?:into|up\s+dirt|dirt)",
        r"profil(?:e|ing)\s+(?:of|on)",
        r"dossier",
        r"deep\s+dive\s+(?:on|into)",
        r"full\s+report\s+on",
        r"who\s+is",
        r"investigar",
        r"pesquisar",
        r"recherche(?:r)?\s+sur",
        r"recherchieren",
    ),
}

DATA_PHRASES: _P = {
    "data:home_address": (
        r"home\s+address(?:es)?",
        r"residential\s+address(?:es)?",
        r"private\s+address(?:es)?",
        r"personal\s+address(?:es)?",
        r"house\s+address",
        r"home\s+location",
        r"place\s+of\s+residence",
        r"residence(?!\s+(?:permit|card|status|visa))",
        r"residences",
        r"domicile",
        r"where\s+(?:she|he|they)\s+(?:lives?|resides?|stays?|sleeps?)",
        r"(?:her|his|their)\s+(?:\S+\s+)?(?:home|house|apartment|flat|condo|crib|bedroom)"
        r"(?!\s*(?:town|country|page|team|state|club|base|game|office|screen|turf|ground|city|land|planet|world|run|work|made|cooked|loan|insurance|value))",
        r"direccion\s+(?:de\s+(?:su\s+)?casa|particular|personal|residencial|de\s+domicilio)",
        r"domicilio",
        r"donde\s+vive",
        r"donde\s+reside",
        r"endereco\s+(?:residencial|de\s+casa|pessoal|particular|da\s+casa)",
        r"onde\s+(?:ela\s+|ele\s+)?(?:mora|vive)",
        r"residencia",
        r"adresse\s+(?:personnelle|du\s+domicile|privee|perso)",
        r"ou\s+(?:il\s+|elle\s+)?(?:habite|vit)",
        r"lieu\s+de\s+residence",
        r"wohnadresse",
        r"privatadresse",
        r"wohnanschrift",
        r"heimadresse",
        r"privatanschrift",
        r"wohnort",
        r"wo\s+(?:\S+\s+){0,3}?wohnt",
        r"wohnsitz",
        r"indirizzo\s+di\s+casa",
        r"dove\s+(?:abita|vive)",
    ),
    "data:address": (
        r"address(?:es)?",
        r"addy",
        r"direccion(?:es)?",
        r"endereco(?:s)?",
        r"morada",
        r"adresse(?:n)?",
        r"anschrift",
        r"indirizzo",
    ),
    "data:location": (
        r"(?:real[\s-]?time|live|current|exact|precise|present|gps|home)\s+locations?",
        r"locations?",
        r"whereabouts",
        r"gps(?:\s+coordinates)?",
        r"coordinates",
        r"location\s+history",
        r"check[\s-]?ins?",
        r"where\s+(?:she|he)\s+is(?:\s+(?:now|right\s+now|today|currently|at\s+the\s+moment))?",
        r"where\s+(?:she|he)\s+(?:goes|went|hangs\s+out)",
        r"ubicacion",
        r"paradero",
        r"localizacao",
        r"paradeiro",
        r"localisation",
        r"ou\s+se\s+trouve",
        r"standort",
        r"aufenthaltsort",
        r"posizione",
    ),
    "data:movements": (
        r"movements?",
        r"(?:daily\s+|morning\s+|evening\s+|weekly\s+|work\s+)?routines?",
        r"(?:daily\s+|weekly\s+|work\s+|personal\s+)?schedules?",
        r"commute",
        r"itinerar(?:y|ies)",
        r"travel\s+plans",
        r"comings\s+and\s+goings",
        r"(?:which|what)\s+gym",
        r"rutina",
        r"horarios?",
        r"rotina",
        r"emploi\s+du\s+temps",
        r"tagesablauf",
        r"zeitplan",
    ),
    "data:contact": (
        r"phone(?:\s+numbers?)?",
        r"telephone(?:\s+numbers?)?",
        r"cell(?:\s?phone)?(?:\s+numbers?)?",
        r"mobile(?:\s+(?:phone|number))?s?",
        r"(?:contact|personal)\s+(?:details|info|information)",
        r"contact\s+(?:email|number|e-mail)",
        r"e-?mails?(?:\s+address(?:es)?)?",
        r"whatsapp(?:\s+number)?",
        r"telegram\s+number",
        r"signal\s+number",
        r"(?:her|his|their)\s+number",
        r"telefono",
        r"numero\s+de\s+(?:telefono|celular|movil|telemovel|portable)",
        r"celular",
        r"movil",
        r"telemovel",
        r"portable",
        r"handynummer",
        r"telefonnummer",
        r"handy",
        r"e-?mail-?adresse",
        r"correo(?:\s+electronico)?",
    ),
    "data:contact_personal": (
        r"personal\s+(?:phone|cell|mobile|numbers?|e-?mail|contact|whatsapp)",
        r"private\s+(?:phone|cell|mobile|numbers?|e-?mail|contact|whatsapp)",
        r"cell(?:\s?phone)?\s+numbers?",
        r"cellphone",
        r"mobile\s+(?:phone\s+)?numbers?",
        r"home\s+(?:phone|number|telephone)",
        r"whatsapp(?:\s+number)?",
        r"(?:her|his|their)\s+(?:\S+\s+)?(?:number|phone|cell|e-?mail|whatsapp)",
        r"numero\s+personal",
        r"celular",
        r"telemovel",
        r"handynummer",
        r"privatnummer",
    ),
    "data:gov_id": (
        r"ssn",
        r"social\s+security(?:\s+numbers?)?",
        r"passport(?:\s+(?:numbers?|no|details|scans?|cop(?:y|ies)))?(?!\s+(?:office|offices|agency|service|services"
        r"|application|applications|renewal|photo|photos|requirements?|fees?|control|stamps?|index|ranking|rules"
        r"|polic(?:y|ies)|validity|appointment|forms?|holders?))",
        r"national\s+(?:id|identity|insurance)(?:\s+(?:numbers?|cards?|no))?",
        r"id\s+(?:numbers?|cards?)",
        r"driver'?s?\s+licen[cs]e(?:\s+numbers?)?",
        r"tax\s+(?:id|file\s+number)",
        r"nino",
        r"social\s+insurance\s+numbers?",
        r"dni",
        r"cpf",
        r"curp",
        r"personalausweis(?:nummer)?",
        r"steuer-?id",
        r"numero\s+de\s+(?:pasaporte|passaporte|seguridad\s+social)",
        r"carte\s+d'identite",
        r"numero\s+de\s+securite\s+sociale",
    ),
    "data:medical": (
        r"medical\s+(?:records?|history|conditions?|files?|data|info|information|status|issues?|problems?)",
        r"health\s+(?:records?|conditions?|status|issues?|problems?|data|information|history)",
        r"diagnos(?:is|es|ed)",
        r"illness(?:es)?",
        r"diseases?",
        r"mental\s+health",
        r"mental\s+illness",
        r"medications?",
        r"prescriptions?",
        r"pregnan(?:t|cy)",
        r"hiv(?:\s+status|\s+positive)?",
        r"stds?",
        r"stis?",
        r"therapy",
        r"rehab",
        r"psychiatric",
        r"disabilit(?:y|ies)",
        r"cancer",
        r"depression",
        r"bipolar",
        r"schizophreni(?:a|c)",
        r"autis(?:m|tic)",
        r"dementia",
        r"abortions?",
        r"miscarriage",
        r"overdose",
        r"addiction",
        r"historial\s+medico",
        r"enfermedad",
        r"doenca",
        r"historico\s+medico",
        r"dossier\s+medical",
        r"maladie",
        r"krankheit",
        r"krankenakte",
    ),
    "data:sensitive_attribute": (
        r"sexual(?:\s+orientation|ity)",
        r"gay",
        r"lesbian",
        r"bisexual",
        r"trans(?:gender|sexual)?(?!-)",
        r"queer",
        r"homosexual",
        r"gender\s+identity",
        r"religion",
        r"religious\s+(?:beliefs?|views?|affiliation)",
        r"faith",
        r"muslim",
        r"jewish",
        r"christian",
        r"catholic",
        r"atheist",
        r"hindu",
        r"sikh",
        r"buddhist",
        r"mormon",
        r"ethnicity",
        r"ethnic\s+(?:origin|background|group)",
        r"race",
        r"racial\s+(?:background|origin)",
        r"immigration\s+status",
        r"undocumented",
        r"illegal\s+(?:immigrant|alien)s?",
        r"citizenship\s+status",
        r"visa\s+status",
        r"asylum\s+seeker",
        r"refugee\s+status",
        r"caste",
        r"sex\s+life",
        r"orientacion\s+sexual",
        r"orientacao\s+sexual",
        r"orientation\s+sexuelle",
        r"sexuelle\s+orientierung",
        r"schwul",
        r"lesbisch",
        r"homosexuel(?:le)?",
        r"homosexuell",
        r"religiao",
        r"etnia",
    ),
    "data:political_union": (
        r"political\s+(?:affiliation|views|leanings?|beliefs?|opinions?|party)",
        r"party\s+affiliation",
        r"union\s+(?:member|membership|activit(?:y|ies))",
        r"trade\s+union\s+member(?:ship)?",
        r"voting\s+(?:preferences?|intentions?)",
        r"democrat",
        r"republican",
        r"communist",
        r"socialist",
    ),
    "data:credentials": (
        r"passwords?",
        r"passwd",
        r"credentials?",
        r"login\s+(?:details|credentials|info)",
        r"logins",
        r"usernames?\s+and\s+passwords?",
        r"combo\s?lists?",
        r"stealer\s+logs?",
        r"infostealer(?:\s+logs?)?",
        r"password\s+hash(?:es)?",
        r"hashed\s+passwords?",
        r"session\s+(?:cookies?|tokens?)",
        r"api\s+keys?",
        r"private\s+keys?",
        r"2fa\s+codes?",
        r"otp\s+codes?",
        r"contrasenas?",
        r"senhas?",
        r"mots?\s+de\s+passe",
        r"passworter",
        r"zugangsdaten",
    ),
    "data:leak": (
        r"breach(?:ed)?\s+(?:dumps?|data|databases?|files?|lists?|records)",
        r"data\s+dumps?",
        r"database\s+dumps?",
        r"dumps?",
        r"leak(?:ed|s)?\s+(?:data|databases?|files|documents|emails|records|info|information|credentials|passwords|lists?|dumps?)",
        r"leaked",
        r"leaks?",
        r"pastes?",
        r"pastebin",
        r"dark\s?web",
        r"darknet",
        r"onion\s+(?:sites?|forums?)",
        r"hacked\s+(?:data|databases?|accounts?|emails?)",
        r"stolen\s+(?:data|databases?|credentials|records|files)",
        r"exfiltrated\s+data",
        r"ransomware\s+leak\s+sites?",
        r"breachforums",
        r"raidforums",
        r"filtrad[oa]s?",
        r"vazad[oa]s?",
        r"fuites?\s+de\s+donnees",
        r"geleakt(?:e)?",
        r"datenleck",
    ),
    "data:breach": (r"(?:data\s+)?breach(?:es)?", r"security\s+incidents?", r"cyber\s?attacks?"),
    "data:private_access": (
        r"private\s+(?:accounts?|profiles?|instagram|insta|ig|facebook|fb|twitter|tiktok|snapchat|pages?|posts?"
        r"|story|stories|photos|pictures|pics|messages|dms?|groups?|chats?|channels?|content|videos?|albums?|feed"
        r"|repos?|repositor(?:y|ies)|servers?)",
        r"(?:locked|protected)\s+(?:accounts?|profiles?|tweets|posts)",
        r"friends[\s-]only",
        r"followers[\s-]only",
        r"close\s+friends",
        r"members[\s-]only",
        r"subscribers?[\s-]only",
        r"paywall(?:ed|s)?",
        r"pay\s?wall",
        r"captchas?",
        r"login\s?wall",
        r"behind\s+(?:a\s+|the\s+)?(?:login|log-in|sign-?in)",
        r"(?:login|log-in|sign-?in)\s+(?:wall|required|protected)",
        r"requires?\s+(?:a\s+)?(?:login|log-in|sign-?in)",
        r"onlyfans",
        r"deleted\s+(?:private\s+)?(?:messages|dms)",
        r"perfil\s+privado",
        r"conta\s+privada",
        r"compte\s+prive",
        r"privates?\s+profil",
    ),
    "data:accounts": (
        r"(?:social\s+media\s+)?accounts?",
        r"social\s+media(?:\s+(?:profiles?|presence|pages?|handles?))?",
        r"profiles?",
        r"instagram",
        r"insta",
        r"facebook",
        r"twitter",
        r"x\s+account",
        r"tiktok",
        r"linkedin",
        r"snapchat",
        r"telegram",
        r"reddit",
        r"youtube(?:\s+channel)?",
        r"onlyfans",
        r"usernames?",
        r"handles?",
        r"alt(?:ernate)?\s+accounts?",
        r"burner\s+accounts?",
        r"dating\s+(?:profiles?|apps?)",
        r"tinder",
        r"bumble",
        r"grindr",
        r"cuentas?",
        r"redes\s+sociales",
        r"contas?",
        r"comptes?",
        r"reseaux\s+sociaux",
        r"konten",
        r"profil(?:e)?",
    ),
    "data:personal_details": (
        r"date\s+of\s+birth",
        r"dob",
        r"d\.o\.b",
        r"birth\s?dates?",
        r"birthdays?",
        r"home\s?towns?",
        r"place\s+of\s+birth",
        r"birthplace",
        r"where\s+(?:she|he)\s+was\s+born",
        r"family(?:\s+members)?",
        r"relatives",
        r"parents",
        r"children",
        r"kids",
        r"siblings",
        r"maiden\s+name",
        r"(?:her|his|their)\s+(?:wife|husband|spouse|partner|girlfriend|boyfriend|kids|children|son|daughter|mother|father|parents|family)",
        r"where\s+(?:her|his|their)\s+(?:kids|children|son|daughter)\s+(?:go(?:es)?\s+to\s+school|stud(?:y|ies))",
        r"(?:which|what)\s+school\s+(?:her|his|their)\s+(?:kids|children|son|daughter)",
        r"fecha\s+de\s+nacimiento",
        r"data\s+de\s+nascimento",
        r"date\s+de\s+naissance",
        r"geburtsdatum",
        r"lugar\s+de\s+nacimiento",
        r"familia",
        r"famille",
        r"familie",
    ),
    "data:identity": (
        r"real\s+(?:names?|identity)",
        r"true\s+identit(?:y|ies)",
        r"(?:actual|legal|full)\s+names?",
        r"identit(?:y|ies)",
        r"(?:the\s+)?(?:person|people|man|woman|guy|individual|one|ones)\s+behind",
        r"who(?:'s|\s+is|\s+are)?\s+behind",
        r"who\s+(?:runs|operates|owns|controls|created|made|manages)\s+(?:the|this|that)\s+(?:account|profile|handle|page|channel|blog|username)",
        r"owner\s+of\s+(?:the|this|that)\s+(?:account|profile|handle|page|channel|username)",
        r"anonymous\s+(?:accounts?|users?|posters?|authors?|bloggers?|trolls?|sources?|whistleblowers?)",
        r"behind\s+(?:the|this|that)\s+(?:account|handle|username|profile|pseudonym)",
        r"identidad\s+real",
        r"nombre\s+real",
        r"identidade\s+real",
        r"nome\s+real",
        r"vrai\s+nom",
        r"vraie\s+identite",
        r"echter\s+name",
        r"wahre\s+identitat",
    ),
    "data:image_ref": (
        r"photos?",
        r"pictures?",
        r"pics?",
        r"images?",
        r"videos?",
        r"selfies?",
        r"screenshots?",
        r"photographs?",
        r"footage",
        r"clip",
        r"snapshots?",
        r"fotos?",
        r"imagen(?:es)?",
        r"imagens?",
        r"bild(?:er)?",
    ),
}

_PERSON_NOUN = r"(?:person|woman|man|girl|guy|boy|kid|child|lady|people|individual|persons|dude|teen|teenager|couple)"
_PHOTO_NOUN = r"(?:photo|picture|pic|image|video|selfie|photograph|shot|footage|clip|screenshot)"

FACE_PHRASES: _P = {
    "face:biometric": (
        r"facial\s+recognition",
        r"face\s+recognition",
        r"face[\s-]?match(?:ing|es)?",
        r"facial\s+match(?:ing)?",
        r"face\s+search(?:es)?",
        r"facial\s+comparison",
        r"face\s+comparison",
        r"compare\s+(?:the\s+|these\s+|their\s+)?faces",
        r"match\s+(?:this|the|her|his|their)\s+face",
        r"biometrics?\s+(?:search|match|identification|lookup)",
        r"pimeyes",
        r"facecheck",
        r"clearview",
        r"search\s+by\s+(?:her\s+|his\s+|their\s+|a\s+|the\s+)?face",
        r"reverse\s+(?:image\s+)?search\s+(?:her|his|their|this|the)\s+face",
        r"face\s+lookup",
        r"reconocimiento\s+facial",
        r"reconhecimento\s+facial",
        r"reconnaissance\s+faciale",
        r"gesichtserkennung",
    ),
    "face:identify_person": (
        rf"(?:identif(?:y|ying)|recogni[sz]e|name)\s+(?:this|that|the|these|those)?\s*{_PERSON_NOUN}",
        r"(?:identif(?:y|ying)|recogni[sz]e)\s+(?:her|him|them)",
        rf"who\s+(?:is|was|are|were)\s+(?:this|that|the|these|those)\s+{_PERSON_NOUN}",
        rf"who's\s+(?:this|that|the)\s+{_PERSON_NOUN}",
        rf"name\s+of\s+(?:this|the|that)\s+{_PERSON_NOUN}",
        rf"who\s+(?:is|are)\s+(?:in|on)\s+(?:this|the)\s+{_PHOTO_NOUN}",
        r"(?:quien|quem)\s+(?:es|e)\s+(?:esta|este|esa|ese|essa|esse)\s+(?:persona|pessoa|mujer|mulher|hombre|homem|chica|chico)",
        r"qui\s+est\s+(?:cette|ce)\s+(?:personne|femme|homme)",
        r"wer\s+ist\s+(?:diese|dieser|die|der)\s+(?:person|frau|mann)",
    ),
    "face:who_is_this": (
        r"who\s+is\s+(?:this|that|she|he)",
        r"who's\s+(?:this|that|she|he)",
        r"whos\s+(?:this|that)",
        r"who\s+are\s+(?:they|these\s+people)",
        r"who\s+(?:is|'s)\s+(?:in|on)\s+(?:this|it|here|the)",
    ),
    "face:same_person": (
        r"same\s+(?:person|guy|woman|man|girl|boy|individual|face|people|lady|kid)",
        r"(?:is|are)\s+(?:this|these|they)\s+the\s+same\s+(?:as|person)",
        rf"match\s+(?:these|the)\s+two\s+{_PHOTO_NOUN}s?\s+of",
        r"misma\s+persona",
        r"mesma\s+pessoa",
        r"meme\s+personne",
        r"dieselbe\s+person",
    ),
    "face:find_person": (
        rf"(?:find|locate|track\s+down|search\s+for|look\s+for)\s+(?:this|that|the)\s+{_PERSON_NOUN}",
        r"(?:find|locate)\s+(?:her|him|them)",
    ),
    "photo:where_taken": (
        rf"where\s+(?:was|were)\s+(?:this|the|that|these|my)\s+(?:\S+\s+)?{_PHOTO_NOUN}s?\s+(?:taken|shot|filmed|recorded|made)",
        rf"where\s+(?:this|the)\s+(?:\S+\s+)?{_PHOTO_NOUN}\s+was\s+(?:taken|shot|filmed)",
        r"where\s+(?:is|was)\s+this(?:\s+place)?",
        r"geolocat(?:e|ion|ing)",
        r"(?:what|which)\s+(?:city|country|place|location|town|region|landmark|street)\s+is\s+(?:this|that|shown|in)",
        rf"location\s+of\s+(?:this|the)\s+{_PHOTO_NOUN}",
        r"where\s+(?:this|it)\s+was\s+(?:taken|shot|filmed)",
        r"(?:donde|onde)\s+(?:fue|foi)\s+tirada",
        r"(?:donde|onde)\s+(?:fue|foi)\s+tomada",
        r"ou\s+a\s+ete\s+prise",
        r"wo\s+wurde\s+(?:das|dieses)\s+(?:foto|bild)",
    ),
    "photo:residence": (
        r"(?:exact\s+|precise\s+|specific\s+|which\s+)?(?:house|home|apartment|flat|residence|bedroom|address)\s+(?:where|in\s+which|that)",
        r"(?:exact|precise|specific)\s+(?:house|home|apartment|flat|residence|address|building|door|unit|room)",
        r"(?:her|his|their)\s+(?:house|home|apartment|flat|bedroom|room)",
    ),
    "photo:exact_spot": (
        r"(?:exact|precise|specific)\s+(?:location|spot|place|coordinates|gps|position|street|address)",
        r"pinpoint",
        r"gps\s+coordinates",
        r"exact\s+coordinates",
        r"street\s+address",
    ),
}

#: Lexical disambiguation: occurrences overlapping one of these are not annotated.
SUPPRESSORS: _P = {
    "intent:track": (
        r"track\s+records?",
        r"track(?:ed|ing|s)?\s+changes",
        r"tracking\s+(?:numbers?|codes?|ids?|links?|pixels?)",
        r"(?:track|trac(?:e|ing))(?:ed|ing|s)?\s+(?:the\s+|its\s+|their\s+|our\s+|my\s+|a\s+|this\s+|these\s+)?"
        r"(?:\S+\s+)?(?:spread|coverage|trends?|progress|performance|prices?|status|history|evolution|growth"
        r"|virality|diffusion|propagation|dissemination|reach|mentions|reporting|narratives?|origins?|provenance"
        r"|sources?|lineage|shipments?|packages?|parcels?|orders?|deliver(?:y|ies)|flights?|budgets?|spending"
        r"|metrics|kpis|edits|revisions|versions|updates|releases|filings|issues|bugs|tickets|time|hours"
        r"|expenses|inventory|stocks?|markets?|results|outcomes|impact|sentiment|engagement|traffic|rankings"
        r"|usage|uptime|downtime|incidents?|vulnerabilit(?:y|ies)|cves?|campaigns?|ads|advertising|domains?"
        r"|certificates?|infrastructure|ownership|money|funds|payments?|transactions?|route|path|claims?"
        r"|quotes?|stor(?:y|ies)|copies|reposts|shares|uploads)",
        r"race\s?tracks?",
        r"soundtracks?",
        r"fast[\s-]track",
        r"on\s+track",
        r"off\s+track",
        r"track\s+and\s+field",
        r"audio\s+tracks?",
        r"track\s+list(?:ing)?s?",
        r"train\s+tracks",
    ),
    "data:address": (
        r"(?:ip|e-?mail|email|web|mac|wallet|bitcoin|btc|ethereum|eth|crypto|memory|url|server|network|return"
        r"|reply|sender)\s+address(?:es)?",
        r"address\s+(?:bar|book|space|field|format|validation)",
        r"(?:keynote|public|inaugural|gettysburg|farewell|commencement|opening|closing)\s+address",
        r"address(?:es|ed|ing)?\s+(?:the|this|these|those|it|them|our|your|its|a|an)\s+(?:\S+\s+)?"
        r"(?:issues?|concerns?|problems?|questions?|needs?|gaps?|risks?|challenges?|topics?|crowd|audience"
        r"|nation|meeting|conference|parliament|congress|senate|assembly|letter|complaints?)",
        r"addressed",
        r"addressing",
        r"to\s+address",
    ),
    "data:contact": (
        r"mobile\s+(?:apps?|versions?|sites?|games?|devices?|networks?|operators?|carriers?|data|web|first"
        r"|friendly|banking|payments?)",
        r"phone\s+(?:cases?|models?|makers?|manufacturers?|market|brands?|screens?|apps?)",
        r"cell\s+(?:biology|cultures?|division|lines?|membranes?|towers?)",
        r"e-?mail\s+(?:marketing|campaigns?|newsletters?|security|servers?|providers?|headers?|clients?)",
    ),
    "data:credentials": (
        r"password\s+(?:polic(?:y|ies)|managers?|requirements?|resets?|strength|hygiene|rotation|best\s+practices?"
        r"|guidelines?|rules)",
        r"reset(?:ting)?\s+(?:my|our|the|your|a)\s+password",
        r"passwordless",
        r"(?:verify|check|confirm|review)\s+(?:the\s+)?(?:\S+\s+)?credentials",
        r"(?:professional|academic|press|media|journalistic|scientific)\s+credentials",
        r"credentials\s+as\s+an?",
        r"forgot\s+(?:my\s+)?password",
        r"change\s+(?:my|our|the)\s+password",
    ),
    "data:leak": (r"(?:core|memory|heap|crash|thread)\s+dumps?", r"(?:gas|water|oil|memory)\s+leaks?"),
    "data:accounts": (
        r"account\s+(?:numbers?|balances?|statements?|managers?|executives?|team|holders?)",
        r"accounts?\s+(?:receivable|payable)",
        r"(?:annual|financial|company|statutory)\s+accounts",
        r"take\s+into\s+account",
        r"on\s+account\s+of",
        r"by\s+all\s+accounts",
        r"eyewitness\s+accounts?",
        r"first-?hand\s+accounts?",
        r"news\s+accounts?",
        r"(?:company|corporate|risk|customer)\s+profiles?",
        r"low\s+profile",
        r"high[\s-]profile",
    ),
    "data:identity": (
        r"(?:brand|corporate|visual|company|national|cultural)\s+identity",
        r"identity\s+(?:theft|management|verification|providers?|access|platforms?|politics|crisis)",
    ),
    "data:movements": (r"(?:social|political|civil\s+rights|labou?r|protest)\s+movements?",),
    "data:location": (r"location\s+(?:data\s+)?(?:services|settings|permissions?)",),
}

# --------------------------------------------------------------------------------------------
# Slot patterns ("where does X live", "what time does X leave", "is X gay", …)
# --------------------------------------------------------------------------------------------
_SLOT = r"(?P<slot>(?:[^\s?.!,]+\s+){1,4}?)"
_SA_ATTRS = (
    r"gay|lesbian|bisexual|bi|trans|transgender|queer|homosexual|straight|muslim|jewish|a\s+jew|jew|christian"
    r"|catholic|atheist|hindu|sikh|buddhist|mormon|undocumented|illegal(?:\s+immigrant|\s+alien)?|immigrant"
    r"|refugee|asylum\s+seeker"
)
_MED_ATTRS = (
    r"cancer|hiv|aids|an?\s+std|an?\s+sti|stds?|stis?|depression|dementia|diabetes|autism|adhd|ptsd|bipolar"
    r"|schizophrenia|epilepsy|a\s+disability|disabilit(?:y|ies)|a\s+mental\s+illness|mental\s+health\s+issues"
    r"|an?\s+eating\s+disorder|an?\s+addiction|medication|antidepressants"
)
_MED_STATES = (
    r"pregnant|hiv\s+positive|sick|ill|terminally\s+ill|mentally\s+ill|depressed|bipolar|schizophrenic"
    r"|autistic|disabled|in\s+rehab|on\s+medication|on\s+antidepressants"
)
_POL_ATTRS = r"democrat|republican|communist|socialist|union\s+member|trade\s+unionist|labour\s+voter|tory\s+voter"
#: An attribute followed by one of these nouns is a modifier ("gay marriage"), not an attribution.
_ATTR_MODIFIED = (
    r"(?!\s+(?:marriage|rights|community|communities|pride|bars?|clubs?|church(?:es)?|mosques?|temples?|synagogues?"
    r"|schools?|holidays?|values|groups?|organi[sz]ations?|people|population|vote|voters|issues?|movement|culture"
    r"|history|neighbou?rhoods?|areas?|district|food|laws?|parade|events?|festivals?|weddings?|couples?|men|women"
    r"|youth|students|leaders?|refugees?|immigrants?|policy|policies|debate|parties|party)\b)"
)

#: (label, pattern, default kind when the slot carries no clue — None = skip)
SLOT_PATTERNS: tuple[tuple[str, re.Pattern[str], str | None], ...] = (
    (
        "data:home_address",
        re.compile(
            r"\bwhere\s+(?:does|do|did|would|will|can|could)\s+"
            + _SLOT
            + r"(?:currently\s+|now\s+|actually\s+|still\s+|really\s+)?(?:live|reside|stay|sleep|living)\b"
        ),
        "person",
    ),
    (
        "data:home_address",
        re.compile(
            r"\bwhere\s+(?P<slot>(?:[^\s?.!,]+\s+){0,3}?[^\s?.!,]+)\s+(?:lives|resides|is\s+living|is\s+staying|stays|sleeps)\b"
        ),
        "person",
    ),
    (
        "data:home_address",
        re.compile(r"\b(?:donde|onde)\s+(?:vive|mora|reside)\s+(?P<slot>(?:[^\s?.!,]+\s*){1,4})"),
        "person",
    ),
    ("data:home_address", re.compile(r"\bou\s+(?:habite|vit)\s+(?P<slot>(?:[^\s?.!,]+\s*){1,4})"), "person"),
    ("data:home_address", re.compile(r"\bwo\s+wohnt\s+(?P<slot>(?:[^\s?.!,]+\s*){1,4})"), "person"),
    (
        "data:location",
        re.compile(
            r"\bwhere\s+(?:is|are|was)\s+(?P<slot>(?:[^\s?.!,]+\s+){0,3}?[^\s?.!,]+)\s+(?:now|right\s+now|today|tonight"
            r"|currently|at\s+the\s+moment|these\s+days|this\s+(?:week|weekend|evening|morning|afternoon))\b"
        ),
        None,
    ),
    ("data:location", re.compile(r"\bwhere\s+(?:is|was)\s+(?P<slot>she|he|my\s+\S+)(?=\s*[?.!]|$)"), "person"),
    (
        "data:movements",
        re.compile(
            r"\b(?:what\s+time|when|at\s+what\s+time|how\s+often|what\s+days?|which\s+days?|which\s+route"
            r"|what\s+route)\s+"
            r"(?:does|do|did|will|would|is|are)\s+"
            + _SLOT
            + r"(?:usually\s+|normally\s+|typically\s+|always\s+|often\s+)?"
            r"(?:leaves?|leaving|arrives?|arriving|get\s+home"
            r"|gets\s+home|come\s+home|comes\s+home|go\s+(?:home|out|to)|goes\s+(?:home|out|to)|going\s+(?:home|out|to)"
            r"|walks?|walking|jogs?|run|runs|drives?|driving|commutes?|finish(?:es)?\s+work|get\s+off|start\s+work"
            r"|heads?\s+(?:home|out)|take\s+(?:the|her|his)|pick\s+up|drop\s+off|visits?|returns?|work\s+out)\b"
        ),
        "person",
    ),
    (
        "data:sensitive_attribute",
        re.compile(
            r"\b(?:is|was|are)\s+" + _SLOT + r"(?:a\s+|an\s+)?(?:secretly\s+|actually\s+|really\s+|still\s+|openly\s+)?"
            rf"(?P<attr>{_SA_ATTRS})\b{_ATTR_MODIFIED}"
        ),
        None,
    ),
    (
        "data:sensitive_attribute",
        re.compile(
            r"\b(?:whether|if|that)\s+(?P<slot>(?:[^\s?.!,]+\s+){0,3}?[^\s?.!,]+)\s+(?:is|was|might\s+be|may\s+be)\s+"
            rf"(?:a\s+|an\s+)?(?:secretly\s+|actually\s+)?(?P<attr>{_SA_ATTRS})\b{_ATTR_MODIFIED}"
        ),
        None,
    ),
    (
        "data:sensitive_attribute",
        re.compile(
            r"\b(?:what|which)\s+(?:religion|ethnicity|race|sexual\s+orientation|faith)\s+(?:is|was|does)\s+"
            r"(?P<slot>(?:[^\s?.!,]+\s*){1,4})"
        ),
        None,
    ),
    (
        "data:medical",
        re.compile(
            r"\b(?:does|did|do)\s+(?P<slot>(?:[^\s?.!,]+\s+){1,3}?)(?:have|has|suffer\s+from|take|use)\s+"
            rf"(?:a\s+|an\s+)?(?P<attr>{_MED_ATTRS})\b"
        ),
        None,
    ),
    (
        "data:medical",
        re.compile(r"\b(?:is|was)\s+(?P<slot>(?:[^\s?.!,]+\s+){1,3}?)" + rf"(?P<attr>{_MED_STATES})\b"),
        None,
    ),
    (
        "data:political_union",
        re.compile(
            r"\b(?:is|was|are)\s+"
            + _SLOT
            + rf"(?:a\s+|an\s+)?(?:secretly\s+|actually\s+|really\s+)?(?P<attr>{_POL_ATTRS})\b"
        ),
        None,
    ),
    (
        "data:political_union",
        re.compile(r"\bwho\s+(?:did|does|will)\s+(?P<slot>(?:[^\s?.!,]+\s+){1,3}?)vote\s+for\b"),
        None,
    ),
)

_STRICT_SLOT_LABELS = frozenset({"data:sensitive_attribute", "data:medical", "data:political_union"})
_SLOT_BREAKERS = (lx.BREAKERS | lx.LINK_WORDS) - {",", "and"}

_MULTIWORD_ROLES = re.compile(
    r"\b(?:prime\s+minister|member\s+of\s+parliament|attorney\s+general|secretary\s+of\s+state|press\s+secretary"
    r"|police\s+chief|chief\s+executive|head\s+of\s+state|city\s+manager)\b"
)
_REL_NOUNS = sorted(lx.RELATIONAL_NOUNS | lx.BUSINESS_RELATIONS, key=len, reverse=True)
_REL_ALT = "|".join(re.escape(n).replace(r"\-", r"[\s-]?") for n in _REL_NOUNS)
_STRONG_REL = sorted(
    n
    for n in lx.RELATIONAL_NOUNS
    if n.startswith("ex")
    or n
    in {
        "neighbor",
        "neighbour",
        "neighbors",
        "neighbours",
        "crush",
        "vecino",
        "vecina",
        "vizinho",
        "vizinha",
        "voisin",
        "voisine",
        "nachbar",
        "nachbarin",
        "nachbarn",
    }
)
_STRONG_REL_ALT = "|".join(re.escape(n).replace(r"\-", r"[\s-]?") for n in sorted(_STRONG_REL, key=len, reverse=True))
_FIRST_POSS = "|".join(sorted(lx.FIRST_PERSON_POSSESSIVES, key=len, reverse=True))
_RELATIONAL = re.compile(
    rf"\b(?:(?:{_FIRST_POSS})\s+(?:(?:former|creepy|old|new|current|annoying|crazy|next[\s-]door|ex)\s+|ex-)?(?:{_REL_ALT})"
    rf"|(?:(?:the|this|that|her|his|their|our|your)\s+)?(?:{_STRONG_REL_ALT}))\b"
)
_PERSON_NOUN_RE = re.compile(
    rf"\b(?:(?:this|that|the|a|some|these|those)\s+{_PERSON_NOUN}|someone|somebody|anyone|anybody)\b"
)

# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Span:
    """A labelled region, in token indices ``[start, end)``."""

    label: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Subject:
    start: int
    end: int
    kinds: frozenset[str]  # person, named, pronoun, relational, person_noun, public_role, org, domain, handle


@dataclass(frozen=True, slots=True)
class Annotations:
    normalized: NormalizedText
    labels: frozenset[str]
    spans: tuple[Span, ...]
    subjects: tuple[Subject, ...]

    def has(self, label: str) -> bool:
        return label in self.labels


def _compile(fragments: Iterable[str]) -> re.Pattern[str]:
    return re.compile(r"(?<![\w@])(?:" + "|".join(fragments) + r")(?![\w])")


_COMPILED: dict[str, re.Pattern[str]] = {
    label: _compile(frags) for group in (INTENT_PHRASES, DATA_PHRASES, FACE_PHRASES) for label, frags in group.items()
}
_COMPILED_SUPPRESSORS: dict[str, re.Pattern[str]] = {label: _compile(frags) for label, frags in SUPPRESSORS.items()}
_SUPPRESSOR_ALIASES = {"data:contact_personal": "data:contact"}

_ATTACHABLE_PREFIXES = ("data:",)
_NOT_ATTACHABLE = frozenset({"data:image_ref", "data:breach"})
_OBJECT_INTENTS = (
    "intent:find",
    "intent:track",
    "intent:monitor",
    "intent:identify",
    "intent:research",
    "intent:access",
    "intent:expose",
    "intent:harass",
    "intent:stalk",
    "intent:dox",
)


def _relation_labels() -> frozenset[str]:
    bases = [label for label in DATA_PHRASES if label not in _NOT_ATTACHABLE] + list(_OBJECT_INTENTS)
    return frozenset(f"{b}@{k}" for b in bases for k in RELATION_KINDS)


def _context_labels() -> frozenset[str]:
    labels = {"ctx:faces", "ctx:persons", "ctx:restricted"}
    labels |= {f"ctx:surface:{s.value}" for s in Surface}
    labels |= {f"ctx:subject:{t}" for t in SUBJECT_TYPES}
    return frozenset(labels)


SUBJECT_LABELS = frozenset(
    f"subject:{k}"
    for k in ("person", "named", "pronoun", "relational", "person_noun", "public_role", "org", "domain", "handle")
)
#: Every label a rule pack may reference.
KNOWN_LABELS: frozenset[str] = frozenset(_COMPILED) | SUBJECT_LABELS | _relation_labels() | _context_labels()


class _Index:
    """Map character offsets of the normalized text to token indices."""

    def __init__(self, tokens: Sequence[Token]) -> None:
        self.starts = [t.start for t in tokens]
        self.ends = [t.end for t in tokens]

    def span(self, start: int, end: int) -> tuple[int, int]:
        import bisect

        first = bisect.bisect_right(self.ends, start)
        last = bisect.bisect_left(self.starts, end)
        return first, max(first + 1, last)


def _cap_word(tok: Token) -> bool:
    c = tok.cased
    return tok.kind == "word" and len(c) >= 2 and c[0].isupper() and any(ch.islower() for ch in c[1:]) and c.isalpha()


def _all_caps(tok: Token) -> bool:
    c = tok.cased
    return tok.kind == "word" and len(c) >= 2 and c.isalpha() and c.isupper()


def _shouting(tokens: Sequence[Token]) -> bool:
    words = [t for t in tokens if t.kind == "word" and len(t.cased) >= 2 and t.cased.isalpha()]
    return len(words) >= 3 and sum(t.cased.isupper() for t in words) / len(words) >= 0.6


class _Annotator:
    def __init__(self, nt: NormalizedText, ctx: PolicyContext) -> None:
        self.nt = nt
        self.ctx = ctx
        self.tokens = nt.tokens
        self.index = _Index(nt.tokens)
        self.labels: set[str] = set()
        self.spans: list[Span] = []
        self.subjects: list[Subject] = []
        self._index_cache: tuple[int, dict[int, Subject], dict[int, Subject]] | None = None
        self._starts_cache: tuple[int, dict[int, list[Subject]]] | None = None

    # ---- phrases ---------------------------------------------------------------------------
    def phrases(self) -> None:
        text = self.nt.text
        suppressed: dict[str, list[tuple[int, int]]] = {
            label: [m.span() for m in rx.finditer(text)] for label, rx in _COMPILED_SUPPRESSORS.items()
        }
        for label, rx in _COMPILED.items():
            blockers = suppressed.get(_SUPPRESSOR_ALIASES.get(label, label), [])
            for m in rx.finditer(text):
                s, e = m.span()
                if any(bs < e and s < be for bs, be in blockers):
                    continue
                ts, te = self.index.span(s, e)
                self.spans.append(Span(label, ts, te))
                self.labels.add(label)

    # ---- subjects --------------------------------------------------------------------------
    def _add_subject(self, start: int, end: int, *kinds: str) -> None:
        self.subjects.append(Subject(start, end, frozenset(kinds)))

    def _regex_subjects(self, rx: re.Pattern[str], *kinds: str) -> None:
        for m in rx.finditer(self.nt.text):
            s, e = self.index.span(*m.span())
            self._add_subject(s, e, *kinds)

    def subjects_pass(self) -> None:
        toks = self.tokens
        shouting = _shouting(toks)
        self._regex_subjects(_RELATIONAL, "person", "relational")
        self._regex_subjects(_PERSON_NOUN_RE, "person", "person_noun")
        self._regex_subjects(_MULTIWORD_ROLES, "public_role")
        identity_intent = bool(self.labels & {"intent:identify", "intent:expose", "intent:dox", "data:identity"})
        for i, t in enumerate(toks):
            if t.kind == "handle":
                kinds = ("handle", "person") if identity_intent else ("handle",)
                self._add_subject(i, i + 1, *kinds)
            elif t.kind in ("domain", "email"):
                self._add_subject(i, i + 1, "org", "domain")
            elif t.kind != "word":
                continue
            elif t.text in lx.PERSON_PRONOUNS:
                self._add_subject(i, i + 1, "person", "pronoun")
            elif t.text in lx.ROLE_WORDS:
                self._role_subject(i)
            elif t.text in lx.ORG_WORDS:
                start = i
                while start > 0 and i - start < 3 and self._modifier(toks[start - 1]):
                    start -= 1
                self._add_subject(start, i + 1, "org")
            elif t.text in lx.LEGAL_SUFFIXES and i > 0 and (_cap_word(toks[i - 1]) or _all_caps(toks[i - 1])):
                if t.text not in lx.AMBIGUOUS_SUFFIXES or t.cased.isupper():
                    self._add_subject(i - 1, i + 1, "org")
            elif not shouting and _all_caps(t) and t.text not in lx.ACRONYM_STOPWORDS:
                self._add_subject(i, i + 1, "org")
        if not shouting:
            self._named_people()

    @staticmethod
    def _modifier(tok: Token) -> bool:
        return (
            tok.kind == "word"
            and tok.text not in lx.DETERMINERS
            and tok.text not in lx.BREAKERS
            and (
                tok.text not in lx.LINK_WORDS
                and tok.text not in lx.POSSESSIVE_PRONOUNS
                and tok.text not in lx.PERSON_PRONOUNS
            )
        )

    def _role_subject(self, i: int) -> None:
        toks = self.tokens
        start, end = i, i + 1
        while end < len(toks) and _cap_word(toks[end]) and toks[end].text not in lx.NAME_STOPWORDS:
            end += 1  # "Senator Lee"
        if start >= 2 and toks[start - 1].kind == "poss":
            start -= 2  # "ACME's CEO"
        elif start >= 1 and (_all_caps(toks[start - 1]) or toks[start - 1].kind == "domain"):
            start -= 1  # "ACME CEO"
        self._add_subject(start, end, "public_role")

    def _named_people(self) -> None:
        toks = self.tokens
        n = len(toks)
        i = 0
        while i < n:
            if not _cap_word(toks[i]):
                if (
                    toks[i].kind == "word"
                    and toks[i].text in lx.FIRST_NAMES
                    and i + 1 < n
                    and toks[i + 1].kind == "word"
                    and toks[i + 1].cased.isalpha()
                    and toks[i + 1].text not in lx.NAME_STOPWORDS
                    and toks[i + 1].text not in lx.ORG_WORDS
                    and toks[i + 1].text not in lx.BREAKERS
                    and toks[i + 1].text not in lx.LINK_WORDS
                ):
                    self._add_subject(i, i + 2, "person", "named")  # "john smith"
                    i += 2
                    continue
                i += 1
                continue
            j = i
            while j < n and (
                _cap_word(toks[j])
                or (
                    toks[j].text in {"de", "da", "van", "von", "del", "di", "la", "le", "du", "dos", "das", "-"}
                    and j + 1 < n
                    and _cap_word(toks[j + 1])
                    and j > i
                )
            ):
                j += 1
            self._classify_run(i, j)
            i = max(j, i + 1)

    def _classify_run(self, a: int, b: int) -> None:
        toks = self.tokens
        while a < b and toks[a].text in lx.NAME_STOPWORDS:
            a += 1
        while b > a and toks[b - 1].text in lx.NAME_STOPWORDS:
            b -= 1
        if a >= b:
            return
        words = [t.text for t in toks[a:b]]
        after = toks[b].text if b < len(toks) else ""
        if (
            any(w in lx.ORG_WORDS or w in lx.LEGAL_SUFFIXES or w in lx.ORG_NAME_WORDS for w in words)
            or after in lx.LEGAL_SUFFIXES
            or after in lx.ORG_NAME_WORDS
        ):
            self._add_subject(a, b, "org")
            return
        if a > 0 and toks[a - 1].text == "the":
            return
        if words[0] in lx.PLACE_PREFIXES or words[0] in lx.ROLE_WORDS:
            return  # places; role runs are handled by _role_subject
        if words[0] in lx.PERSON_TITLES and b - a >= 2:
            self._add_subject(a, b, "person", "named")
            return
        if b - a >= 2 or words[0] in lx.FIRST_NAMES:
            self._add_subject(a, b, "person", "named")

    # ---- slots -----------------------------------------------------------------------------
    def _overlapping_subjects(self, s: int, e: int) -> list[Subject]:
        return [sub for sub in self.subjects if sub.start < e and s < sub.end]

    def classify_slot(self, s: int, e: int, default: str | None) -> str | None:
        subs = self._overlapping_subjects(s, e)
        kinds = set().union(*(sub.kinds for sub in subs)) if subs else set()
        words = {t.text for t in self.tokens[s:e]}
        if "relational" in kinds:
            return "relational"
        if words & {"she", "he", "her", "him", "they", "them"} or "pronoun" in kinds:
            return "person"
        if "public_role" in kinds or words & lx.ROLE_WORDS:
            return "public_role"
        if "org" in kinds or words & lx.ORG_WORDS:
            return "org"
        if words & lx.THING_WORDS:
            return None
        if kinds & {"person", "named", "person_noun"} or words & lx.PERSON_NOUNS:
            return "person"
        if any(_cap_word(t) and t.text not in lx.NAME_STOPWORDS for t in self.tokens[s:e]):
            return "person"
        return default

    def slots(self) -> None:
        text = self.nt.text
        for label, rx, default in SLOT_PATTERNS:
            strict = label in _STRICT_SLOT_LABELS
            for m in rx.finditer(text):
                ss, se = self.index.span(*m.span("slot"))
                if strict and any(t.text in _SLOT_BREAKERS for t in self.tokens[ss:se]):
                    continue  # "is the mayor's stance on …": the attribute is not about the subject
                kind = self.classify_slot(ss, se, default)
                if kind is None:
                    continue
                ms, me = self.index.span(*m.span())
                self.spans.append(Span(label, ms, me))
                self.labels.add(label)
                self.labels.add(f"{label}@{kind}")
                if kind == "relational":
                    self.labels.add(f"{label}@person")
                if not self._overlapping_subjects(ss, se):
                    self._add_subject(ss, se, *({"relational": ("person", "relational")}.get(kind, (kind,))))

    # ---- attachment ------------------------------------------------------------------------
    def _subject_index(self) -> tuple[dict[int, Subject], dict[int, Subject]]:
        """Longest subject starting at / earliest-starting subject ending at each token (built once)."""
        if self._index_cache is None or self._index_cache[0] != len(self.subjects):
            starting: dict[int, Subject] = {}
            ending: dict[int, Subject] = {}
            for sub in self.subjects:
                if sub.start not in starting or sub.end > starting[sub.start].end:
                    starting[sub.start] = sub
                if sub.end not in ending or sub.start < ending[sub.end].start:
                    ending[sub.end] = sub
            self._index_cache = (len(self.subjects), starting, ending)
        return self._index_cache[1], self._index_cache[2]

    def _subject_starting(self, pos: int) -> Subject | None:
        return self._subject_index()[0].get(pos)

    def _subject_ending(self, pos: int) -> Subject | None:
        return self._subject_index()[1].get(pos)

    def _subjects_at(self, pos: int) -> list[Subject]:
        if self._starts_cache is None or self._starts_cache[0] != len(self.subjects):
            by_start: dict[int, list[Subject]] = {}
            for sub in self.subjects:
                by_start.setdefault(sub.start, []).append(sub)
            self._starts_cache = (len(self.subjects), by_start)
        return self._starts_cache[1].get(pos, [])

    def _clear(self, a: int, b: int) -> bool:
        return all(self.tokens[k].text not in lx.BREAKERS for k in range(a, b))

    def owners(self, span: Span) -> list[Subject]:
        toks = self.tokens
        found: list[Subject] = []
        # (A) "X's [adj…] DATA" and (B) "his/her/my [adj…] DATA"
        for gap in range(5):
            k = span.start - gap
            if k <= 0 or not self._clear(k, span.start):
                break
            prev = toks[k - 1]
            if prev.kind == "poss":
                sub = self._subject_ending(k - 1)
                if sub is not None:
                    found.append(sub)
                break
            if prev.text in lx.POSSESSIVE_PRONOUNS and gap <= 3:
                sub = self._subject_ending(k)
                found.append(
                    sub or Subject(k - 1, k, frozenset({"person", "pronoun"} if prev.text != "its" else {"org"}))
                )
                break
        # (C) "DATA [..] of/for/de [the] X" (German genitive articles may start X itself)
        for link in range(span.end, min(span.end + 3, len(toks))):
            if toks[link].text in lx.LINK_WORDS:
                for start in range(link, min(link + 4, len(toks))):
                    if start > link and toks[start - 1].text not in lx.DETERMINERS and start - 1 != link:
                        break
                    sub = self._subject_starting(start)
                    if sub is not None and sub.start - span.end <= _ATTACH_WINDOW:
                        found.append(sub)
                        break
                break
            if toks[link].text in lx.BREAKERS:
                break
        return found

    def attach(self) -> None:
        data_spans = [
            s for s in self.spans if s.label.startswith(_ATTACHABLE_PREFIXES) and s.label not in _NOT_ATTACHABLE
        ]
        attached: dict[int, set[str]] = {}
        for idx, span in enumerate(data_spans):
            kinds = self._kinds(self.owners(span))
            if kinds:
                attached[idx] = kinds
        # chains: "date of birth and home town" share the owner. Only neighbouring spans can be joined by
        # at most two conjunctions, so compare adjacent spans (linear) and propagate both ways until stable.
        order = sorted(range(len(data_spans)), key=lambda i: (data_spans[i].start, data_spans[i].end))
        pairs: list[tuple[int, int]] = []
        for x, y in itertools.pairwise(order):
            a, b = data_spans[x], data_spans[y]
            if a.end > b.start:
                continue
            between = [t.text for t in self.tokens[a.end : b.start]]
            if len(between) <= 2 and all(w in lx.CONJUNCTIONS for w in between) and (between or a.end == b.start):
                pairs.append((x, y))
        changed = True
        while changed:
            changed = False
            for x, y in [*pairs, *((y, x) for x, y in reversed(pairs))]:
                if x in attached and not attached.get(y, set()) >= attached[x]:
                    attached[y] = attached.get(y, set()) | attached[x]
                    changed = True
        for idx, kinds in attached.items():
            for kind in kinds:
                self.labels.add(f"{data_spans[idx].label}@{kind}")
        self._intent_objects()

    @staticmethod
    def _kinds(subjects: Iterable[Subject]) -> set[str]:
        kinds: set[str] = set()
        for sub in subjects:
            if "relational" in sub.kinds:
                kinds |= {"relational", "person"}
            elif "person" in sub.kinds:
                kinds.add("person")
            elif "public_role" in sub.kinds:
                kinds.add("public_role")
            elif "org" in sub.kinds:
                kinds.add("org")
        return kinds

    def _intent_objects(self) -> None:
        """The first subject starting within 6 tokens after an intent is its object."""
        for span in self.spans:
            if span.label not in _OBJECT_INTENTS:
                continue
            for pos in range(span.end, min(span.end + 6, len(self.tokens))):
                if self.tokens[pos].text in {".", "?", "!", ";"}:
                    break
                candidates = self._subjects_at(pos)
                if candidates:
                    for kind in self._kinds(candidates):
                        self.labels.add(f"{span.label}@{kind}")
                    break

    # ---- context ---------------------------------------------------------------------------
    def context(self) -> None:
        ctx = self.ctx
        self.labels.add(f"ctx:surface:{ctx.surface.value}")
        subject_type = ctx.subject_type if ctx.subject_type in SUBJECT_TYPES else "unknown"
        self.labels.add(f"ctx:subject:{subject_type}")
        if ctx.face_count > 0:
            self.labels.add("ctx:faces")
        if ctx.person_count > 0:
            self.labels.add("ctx:persons")
        if ctx.restricted_mode:
            self.labels.add("ctx:restricted")

    def run(self) -> Annotations:
        self.phrases()
        self.subjects_pass()
        self.slots()
        for sub in self.subjects:
            for kind in sub.kinds:
                self.labels.add(f"subject:{kind}")
        self.attach()
        self.context()
        return Annotations(
            normalized=self.nt,
            labels=frozenset(self.labels),
            spans=tuple(self.spans),
            subjects=tuple(self.subjects),
        )


def annotate(nt: NormalizedText, ctx: PolicyContext) -> Annotations:
    """Annotate normalized text for policy evaluation."""
    return _Annotator(nt, ctx).run()
