"""Word lists used by the policy annotator (all casefolded and accent-free, like normalized text)."""

from __future__ import annotations


def words(text: str) -> frozenset[str]:
    """A whitespace-separated word list as a frozenset (keeps long vocabularies compact)."""
    return frozenset(text.split())


#: Common given names (EN/ES/PT/FR/DE/IT). Words that are also months, places, brands, virtues or
#: everyday nouns (May, Paris, Grace, Will, Guy, Angel, …) are deliberately excluded.
FIRST_NAMES = words(
    """
    aaron adam adrian adriana agnes aidan aisha alan albert alberto alejandra alejandro alex alexander alexandra
    alfonso alice alicia alison amanda amelia amy ana andrea andreas andrew andy angela anja anna anne annie anthony
    antoine antonio arthur barbara beatriz ben benjamin bernard beth betty bianca bob brandon brenda brian bruno
    caitlin camila carla carlos carmen carol caroline catarina catherine charlie charlotte chloe chris christina
    christine christopher claire clara claudia colin daniel daniela danielle david debbie deborah denise diana diego
    dominic donald dorothy edward elena eleanor elisa elizabeth ella ellen emily emma eric erik ethan eva fatima
    felipe fernanda fernando fiona francesca francesco francisco francois gabriel gabriela gary george gina giorgio
    giovanni giulia giuseppe gonzalo gregory hannah hans harry heather helen helena henry ian ines isabel isabella
    isabelle jack jacob james jan jane janet jason javier jean jeff jeffrey jennifer jenny jeremy jessica jim joan
    joana joao joe johanna john jonathan jorge jose joseph joshua juan julia julian julie julien jurgen karen karl
    kate katherine kathryn katie keith kelly kevin kim klaus laura lauren leon leonardo liam linda lisa lorenzo
    louise lucas lucia luis luisa luka lukas maria mariana marie marina mario marta martha martin mary mateo matteo
    matthew max megan melissa mia michael michelle miguel mike miriam mohamed mohammed monica muhammad nancy natalie
    nathan nicholas nicola nicole nina noah olga oliver olivia omar oscar pablo paolo patricia patrick paul paula
    pedro peter philip pierre rachel rafael raquel rebecca ricardo richard rita robert roberto ryan samantha samuel
    sandra sara sarah sean sebastian sergio sharon simon sofia sophia sophie stefan stephanie stephen steve steven
    susan taylor teresa thomas tiago tim timothy tom tony valentina vanessa vincent walter wolfgang yasmin zoe
    """
)

#: Legal-form suffixes (matched case-insensitively; short ambiguous ones need upper case).
LEGAL_SUFFIXES = words(
    """
    inc ltd llc llp gmbh plc corp corporation company co bv nv oy oyj kk ltda lda srl spa sarl sas sa ag ab se kg
    asa pty limited incorporated lp pte pvt bhd sl
    """
)
#: Short suffixes that are also ordinary words; they only count when written in upper case.
AMBIGUOUS_SUFFIXES = words(
    """
    sa ag ab se kg co sl lp as nv bv oy kk
    """
)

#: Words that make the surrounding noun phrase an organization (or an organizational channel).
ORG_WORDS = words(
    """
    company companies corporation organization organisation business brand firm agency ministry department council
    municipality government office embassy consulate university college school hospital clinic ngo charity
    foundation newspaper magazine publisher broadcaster website site domain app platform startup nonprofit
    association institute institution bank police court parliament authority regulator commission committee museum
    library airport store shop restaurant hotel factory headquarters hq club federation union network studio
    retailer manufacturer supplier vendor contractor registry registrar subsidiary group holding holdings fund hall
    team desk newsroom empresa compania sociedad ayuntamiento ministerio gobierno universidad escuela prefeitura
    camara governo universidade escola entreprise societe mairie ministere gouvernement universite ecole hopital
    firma unternehmen gesellschaft behorde ministerium regierung universitat schule krankenhaus rathaus gemeinde
    """
)

#: Words that, inside a capitalized name, mark a business or institution ("Northwind Coffee Roasters").
ORG_NAME_WORDS = words(
    """
    roasters coffee bakery cafe bar pub brewery foods motors airlines airways pharma pharmaceuticals labs
    laboratories technologies tech systems solutions software media news times post journal gazette herald tribune
    partners associates capital ventures energy electric telecom communications logistics consulting services
    industries international global enterprises studios records entertainment productions publishing books insurance
    financial trust realty properties construction hotels resorts tea kitchen supermarket boutique pharmacy academy
    center centre gallery theatre theater cinema stadium arena park zoo station airport automotive bank bancorp
    wines winery farms dairy apparel fashion cosmetics games networks robotics analytics security health healthcare
    medical dental clinic hospital university college school institute museum library foundation society association
    club
    """
)

#: Public roles: research about the role holder's *public* activity is ordinary journalism.
ROLE_WORDS = words(
    """
    mayor senator governor minister president premier chancellor mp congressman congresswoman congressperson
    representative councillor councilor councilman councilwoman ceo cfo coo cto chairman chairwoman chairperson
    founder cofounder co-founder director executive executives spokesperson spokesman spokeswoman ambassador judge
    prosecutor sheriff commissioner secretary king queen prince princess pope bishop official officials politician
    lawmaker legislator candidate celebrity actor actress singer influencer athlete footballer journalist author
    owner manager board alcalde alcaldesa senador senadora gobernador ministro ministra presidente presidenta
    diputado diputada prefeito prefeita deputado deputada vereador maire ministre depute senateur burgermeister
    burgermeisterin abgeordnete prasident
    """
)
#: Personal titles that mark the following capitalized word as a person.
PERSON_TITLES = words(
    """
    mr mrs ms miss mx dr prof sir dame lord lady sr sra mme mlle herr frau
    """
)

#: Third-person and first-person singular pronouns that refer to a person.
PERSON_PRONOUNS = words(
    """
    he she him her his hers himself herself ella ele ela elle lui lei
    """
)
#: Possessive determiners that attach the following data to their owner.
POSSESSIVE_PRONOUNS = words(
    """
    his her their my its su sus seu sua son sa ses sein seine seines seiner ihr ihre ihres ihrer
    """
)
FIRST_PERSON_POSSESSIVES = words(
    """
    my mi mis minha meu minhas meus mon ma mes mein meine meines meiner meinem meinen mio mia miei mie
    """
)

#: Relationship nouns. Those in BUSINESS_RELATIONS only count after a first-person possessive.
RELATIONAL_NOUNS = words(
    """
    ex ex-girlfriend ex-boyfriend ex-wife ex-husband ex-partner exgirlfriend exboyfriend exwife exhusband spouse
    wife husband girlfriend boyfriend gf bf crush neighbor neighbour neighbors neighbours classmate roommate
    flatmate housemate friend bestie sister brother mother mom mum father dad son daughter cousin aunt uncle niece
    nephew stepmother stepfather stepdaughter stepson grandmother grandfather teacher student exnovia exnovio
    expareja exmujer exesposa exmarido vecino vecina novia novio pareja esposa esposo marido mujer vizinho vizinha
    namorada namorado ex-namorada ex-namorado voisin voisine copine copain femme mari ex-copine ex-copain ex-femme
    ex-mari nachbar nachbarin nachbarn freundin freund exfreundin exfreund
    """
)
BUSINESS_RELATIONS = words(
    """
    partner partners boss employee employees colleague colleagues coworker co-worker coworkers landlord landlady
    tenant client jefe jefa companero companera chefe colega patron patronne collegue partenaire chef chefin kollege
    kollegin frau mann
    """
)
#: Generic nouns for an unnamed person.
PERSON_NOUNS = words(
    """
    person guy girl woman man kid child boy lady individual people teen teenager user dude persons women men persona
    pessoa personne
    """
)

#: Capitalized words that never start a person name (sentence starters, months, platforms, …).
NAME_STOPWORDS = words(
    """
    what where who whose when why how which is are was were does did do can could would should will please find show
    tell give get research investigate track trace monitor alert identify search look make create verify compare map
    list check the a an this that these those my our your his her their i we you he she they it in on at for of and
    or but if with from to by about after before since until while during all any every each some no not yes hi
    hello dear thanks thank ok okay also then now today monday tuesday wednesday thursday friday saturday sunday
    january february march april may june july august september october november december note notes summary report
    section source sources evidence finding findings timeline image photo picture video case investigation subject
    purpose query question answer google facebook instagram twitter linkedin tiktok youtube reddit telegram whatsapp
    wikipedia wayback machine street view maps earth archive internet microsoft apple amazon meta tesla unmask dox
    expose help send post write draft summarize analyze analyse explain describe has have had be been let use using
    via per re fw fwd attn ps
    """
)
PLACE_PREFIXES = words(
    """
    new san santa santo sao los las saint st fort port mount lake north south east west upper lower great little rio
    el le la puerto porto buenos costa hong kuala tel abu
    """
)
#: All-caps tokens that are not organization names.
ACRONYM_STOPWORDS = words(
    """
    i gps id dob ssn url ip pdf ceo cfo cto coo mp ngo uk us usa eu un ok am pm tv lgbt lgbtq hiv aids isp vpn api
    faq pr hr it dm dms irl asap fyi aka nb vs etc a ii iii iv
    """
)

#: Words that make a slot ("where does X live", "when does X leave") a thing rather than a person.
THING_WORDS = words(
    """
    store shop train bus flight plane ship ferry museum office restaurant bank library market mall event show
    concert game match festival conference meeting parade sun moon iss satellite package parcel shipment order
    delivery species animal animals bird birds fish plant plants bear bears whale wolf tiger insect bacteria virus
    money data file files app website server company school class course season sale shift session hearing trial
    vote election launch release embargo deadline summit keynote webinar service tour exhibition
    """
)

DETERMINERS = words(
    """
    the a an this that these those el la los las le les o os as un una um uma der die das den dem des lo il gli i
    """
)
#: Words linking data to its owner ("address OF", "dirección DE", German genitive articles, …).
LINK_WORDS = words(
    """
    of for de da do das dos des du del della di von vom der meines meiner seines seiner ihres ihrer deines deiner
    unseres unserer belonging
    """
)
#: Words that end the noun phrase between an owner and a data item.
BREAKERS = words(
    """
    on about regarding towards toward against with without in at to from by into onto over under after before during
    than as like vs versus is are was were be been has have had does do did will would can could should may might
    must and or but . ? ! ; : ( ) ,
    """
)
CONJUNCTIONS = words(
    """
    and or , & / y e et und ou o plus
    """
)
