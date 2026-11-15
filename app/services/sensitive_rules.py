# ============================================================
# app/services/sensitive_rules.py
# Rule layer of the hybrid detection engine:
#   - structural regexes with checksum validators
#   - context-gated extractors (DOB, address, account, username, ...)
#   - Indian name / organisation / medical gazetteers
#
# All spans returned by this module are offsets into the text that is
# passed in (the detection engine passes its normalised view and maps
# the offsets back to the original document).
# ============================================================
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from app.services import validators as V


@dataclass
class RuleHit:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float
    method: str = "regex"


# ── Gazetteers ────────────────────────────────────────────────
FIRST_NAMES = [
    "Ajit", "Ajay", "Abhishek", "Abhinav", "Aditya", "Aarav", "Aisha", "Amit",
    "Ananya", "Anil", "Anjali", "Anjali", "Arjun", "Arun", "Arif", "Ashok",
    "Ashwini", "Aparna", "Aarti", "Asha", "Bharti", "Deepak", "Dinesh", "Divya",
    "Fatima", "Ganesh", "Gaurav", "Gauri", "Geeta", "Harsh", "Imran", "Isha",
    "Karan", "Kavita", "Kiran", "Kunal", "Lakshmi", "Madhuri", "Mahendra",
    "Manisha", "Manoj", "Mansi", "Mayur", "Meera", "Mukesh", "Neha", "Nikhil",
    "Nilesh", "Nisha", "Nitin", "Omkar", "Pankaj", "Pooja", "Pournima", "Prakash",
    "Pranali", "Pratik", "Priya", "Rajesh", "Rajeshwari", "Rakesh", "Ramesh",
    "Ravi", "Rekha", "Ritu", "Rohan", "Rohit", "Rupali", "Sachin", "Sandeep",
    "Sanjay", "Seema", "Shalini", "Shrikant", "Shweta", "Siddharth", "Siddhi",
    "Sneha", "Snehal", "Sonali", "Sunil", "Sunita", "Suresh", "Swapnil", "Swati",
    "Tanvi", "Tarun", "Tejas", "Usha", "Vandana", "Varun", "Vijay", "Vikram",
    "Vinod", "Vishal", "Yash", "Yogesh", "Krishna", "Rahul", "Anand", "Anup",
    "Bhavna", "Chaitanya", "Charu", "Darshan", "Devendra", "Girish", "Harish",
    "Hemant", "Jitendra", "Kailash", "Kamal", "Madhav", "Mohan", "Nandini",
    "Naveen", "Pallavi", "Pravin", "Raghav", "Rajendra", "Ram", "Sagar",
    "Sameer", "Shashank", "Shivam", "Shruti", "Smita", "Sudhir", "Sumit",
    "Vaishali", "Varsha", "Vidya", "Vivek",
]

SURNAMES = [
    "Birajdar", "Krishnamurthy", "Patil", "Joshi", "Deshpande", "Deshmukh",
    "Rathore", "Rane", "Sharma", "Verma", "Gupta", "Agarwal", "Mehta", "Shah",
    "Patel", "Iyer", "Nair", "Menon", "Reddy", "Rao", "Naidu", "Choudhary",
    "Yadav", "Kumar", "Mishra", "Pandey", "Tiwari", "Dubey", "Shukla",
    "Awasthi", "Kulkarni", "Gokhale", "Chavan", "Jadhav", "Shinde", "Pawar",
    "More", "Sawant", "Kadam", "Salunkhe", "Bhosale", "Gaikwad", "Wagh",
    "Kaur", "Gill", "Sandhu", "Khan", "Sheikh", "Sayed", "Ansari", "Qureshi",
    "Siddiqui", "Malhotra", "Chopra", "Kapoor", "Khanna", "Sethi", "Arora",
    "Bhatia", "Bansal", "Jain", "Goel", "Mittal", "Sinha", "Bose", "Chatterjee",
    "Banerjee", "Mukherjee", "Ghosh", "Dutta", "Sen", "Das", "Roy", "Saha",
    "Nambiar", "Pillai", "Kurup", "Hegde", "Shetty", "Pai", "Kamath", "Bhat",
    "Upadhyay", "Trivedi", "Pandit", "Majumdar", "Bhattacharya", "Singh",
    "Chauhan", "Rathod", "Solanki", "Thakur", "Vyas", "Waghmare", "Kale",
]

KNOWN_ORGS = [
    "Infosys Limited", "Infosys", "Tata Consultancy Services", "TCS",
    "State Bank of India", "HDFC Bank", "ICICI Bank", "Axis Bank",
    "Punjab National Bank", "Bank of Baroda", "Canara Bank", "Kotak Mahindra Bank",
    "Unique Identification Authority of India", "Income Tax Department",
    "Reserve Bank of India", "SEBI", "Life Insurance Corporation of India",
    "LIC", "Bharat Petroleum", "Indian Oil Corporation", "Reliance Industries",
    "Wipro", "HCL Technologies", "Tech Mahindra", "Larsen & Toubro",
    "Bajaj Finance", "HDFC Life", "ICICI Lombard", "Apollo Hospitals",
    "Fortis Healthcare", "Ruby Hall Clinic", "AIIMS", "Google", "Microsoft",
    "Amazon", "Flipkart", "Paytm", "Zomato", "Swiggy", "Meta", "Oracle",
    "SAP", "Accenture", "Deloitte", "KPMG", "PwC", "Ernst & Young",
]

CITIES = [
    "Mumbai", "Pune", "Nagpur", "Nashik", "Thane", "Delhi", "New Delhi",
    "Bengaluru", "Bangalore", "Hyderabad", "Chennai", "Kolkata", "Ahmedabad",
    "Jaipur", "Surat", "Indore", "Bhopal", "Lucknow", "Kanpur", "Patna",
    "Kochi", "Coimbatore", "Chandigarh", "Gurgaon", "Gurugram", "Noida",
    "Visakhapatnam", "Vijayawada", "Mysuru", "Mysore", "Ranchi", "Raipur",
    "Guwahati", "Bhubaneswar", "Dehradun", "Srinagar", "Aurangabad", "Kolhapur",
    "Solapur", "Amravati", "Tiruchirappalli", "Madurai", "Salem", "Warangal",
    "London", "New York", "Singapore", "Dubai", "Toronto", "Sydney",
]

INDIAN_STATES = [
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
    "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka",
    "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya",
    "Mizoram", "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim",
    "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand",
    "West Bengal", "Jammu and Kashmir", "Ladakh", "Puducherry",
]

MEDICAL_CONDITIONS = [
    "type 2 diabetes mellitus", "type 1 diabetes mellitus", "diabetes mellitus",
    "diabetes", "hypertension", "breast cancer", "lung cancer", "colon cancer",
    "cervical cancer", "prostate cancer", "cancer", "tuberculosis", "asthma",
    "copd", "chronic kidney disease", "kidney failure", "heart disease",
    "coronary artery disease", "hepatitis b", "hepatitis c", "hiv", "aids",
    "covid-19", "dengue", "malaria", "typhoid", "rheumatoid arthritis",
    "arthritis", "depression", "anxiety", "migraine", "epilepsy", "pneumonia",
    "anemia", "thyroid disorder", "hypothyroidism", "hyperthyroidism",
    "मधुमेह", "उच्च रक्तदाब", "क्षयरोग",
    "obesity", "psoriasis", "dementia", "alzheimer's disease",
    "parkinson's disease", "multiple sclerosis", "leukemia", "sickle cell disease",
    "thalassemia", "cirrhosis", "ulcerative colitis", "crohn's disease",
]

MEDICAL_TREATMENTS = [
    "chemotherapy", "radiotherapy", "radiation therapy", "dialysis",
    "physiotherapy", "angioplasty", "bypass surgery", "organ transplant",
    "vaccination", "immunotherapy",
]

MEDICATIONS = [
    "metformin", "insulin", "penicillin", "amoxicillin", "azithromycin",
    "paracetamol", "acetaminophen", "ibuprofen", "aspirin", "atorvastatin",
    "omeprazole", "cetirizine", "levothyroxine", "amlodipine", "losartan",
    "metoprolol", "prednisolone", "warfarin", "clopidogrel", "pantoprazole",
    "dolo 650", "crocin", "augmentin", "azee", "glycomet", "telma",
    "hydroxychloroquine", "remdesivir", "morphine", "tramadol",
]

MEDICAL_CONTEXT_WORDS = [
    "patient", "diagnosis", "diagnosed", "prescription", "prescribed",
    "treatment", "medication", "medicine", "dosage", "allergy", "allergies",
    "hospital", "clinic", "doctor", "physician", "symptom", "disease",
    "disorder", "blood group", "blood type", "clinical", "therapy", "health",
    "medical", "surgery", "dosage", "mg twice", "mg once",
    "रोगी", "रुग्ण", "निदान", "औषध", "इलाज", "उपचार",
]


def _alternation(items: list[str]) -> str:
    ordered = sorted(set(items), key=len, reverse=True)
    return "|".join(re.escape(x) for x in ordered)


_FIRST_RE = _alternation(FIRST_NAMES)
_SUR_RE = _alternation(SURNAMES)
_NAME_GAZETTEER_RE = re.compile(
    rf"\b(?:{_FIRST_RE})[ \t]+(?:[A-Z][a-z]+[ \t]+){{0,2}}(?:{_SUR_RE})\b"
)

_ORG_SUFFIX_RE = re.compile(
    r"\b(?:[A-Z][A-Za-z&.'\-]*[ \t]+){0,5}"
    r"(?:Private Limited|Pvt\.?[ \t]*Ltd\.?|Pvt[ \t]+Limited|Limited|Ltd\.?|"
    r"Corporation|Corp\.?|Company|Co\.?|Inc\.?|LLC|LLP|Bank|Technologies|"
    r"Technology|Solutions|Systems|Services|Consultancy|Consulting|Enterprises|"
    r"Industries|University|Institute|College|Hospital|Clinic|Authority|"
    r"Department|Ministry|Council|Board|Trust|Foundation|Laboratories|Labs|"
    r"Holdings|Group)\b"
)
_ORG_GAZETTEER_RE = re.compile(
    rf"(?<![A-Za-z])(?:{_alternation(KNOWN_ORGS)})(?![A-Za-z])"
)

_ADDRESS_LABEL_RE = re.compile(
    r"(?im)^[ \t]*(?:shipping address|billing address|permanent address|"
    r"residential address|mailing address|address|residence)[ \t]*[:\-][ \t]*(.*?)[ \t]*$"
)
_ADDRESS_CONTINUATION_RE = re.compile(
    r"(?i)(road|street|st\.|lane|nagar|colony|society|apartment|apartments|flat|"
    r"house|sector|block|layout|extension|cross|main|park|villa|plot|"
    r"maharashtra|karnataka|delhi|tamil nadu|telangana|gujarat|rajasthan|"
    r"uttar pradesh|west bengal|punjab|haryana|kerala|goa|\b\d{6}\b)"
)

_NAME_LABEL_RE = re.compile(
    r"(?im)^[ \t]*(?:name(?:[ \t]+of[ \t]+(?:the[ \t]+)?(?:applicant|patient|"
    r"customer|employee))?|applicant|patient(?:[ \t]+name)?|employee(?:[ \t]+name)?|"
    r"account holder|father'?s[ \t]+name|mother'?s[ \t]+name|guardian|holder|"
    r"contact person|regards|sincerely|yours faithfully)[ \t]*[:\-]?[,\s]*"
    r"([A-Z][A-Za-z.'\-]+(?:[ \t]+[A-Z][A-Za-z.'\-]+){0,3})"
)
_NAME_SIGNED_RE = re.compile(
    r"(?i)\b(?:signed by|authorized by|authorised by|verified by|reviewed by|"
    r"approved by)[ \t]+([A-Z][A-Za-z.'\-]+(?:[ \t]+[A-Z][A-Za-z.'\-]+){0,3})"
)
# Mid-sentence name cues in English, Hindi, Marathi, and romanized forms.
# Latin names still pass looks_like_person_name(); Devanagari names need
# at least two script tokens so a single adjective is not treated as a name.
_CONTEXT_NAME_LATIN_RE = re.compile(
    r"(?:\b[Mm]y|\b[Mm]era|\b[Mm]eri|\b[Mm]aza|\b[Mm]ajha|\b[Mm]ajhe|"
    r"मेरा|मेरी|माझा|माझी|माझे|माझं)"
    r"[ \t]+(?:[Nn]ame|[Nn]aam|[Nn]av|नाम|नाव)"
    r"(?:[ \t]+(?:[Ii]s|[Hh]ai|[Aa]ahe|[Aa]he|है|आहे))?"
    r"[ \t]*[:\-]?[ \t]*"
    r"([A-Z][A-Za-z.'\-]+(?:[ \t]+[A-Z][A-Za-z.'\-]+){0,3})"
)
_CONTEXT_NAME_DEV_RE = re.compile(
    r"(?:मेरा|मेरी|माझा|माझी|माझे|माझं)[ \t]+(?:नाम|नाव)"
    r"(?:[ \t]+(?:है|आहे))?[ \t]*[:\-]?[ \t]*"
    r"((?:[\u0900-\u097F]{2,}[ \t]+){1,3}[\u0900-\u097F]{2,})"
)
_DEV_NAME_STOP = {"है", "हैं", "आहे", "आहेत", "का", "की", "के", "में", "और"}
_TITLE_RE = re.compile(r"^(?:Dr|Mr|Mrs|Ms|Prof|Shri|Smt|Sri)\.?[ \t]+", re.IGNORECASE)

_NAME_BLOCKLIST = {
    "email", "phone", "mobile", "address", "bank", "account", "holder", "name",
    "patient", "applicant", "manager", "director", "department", "limited",
    "pvt", "ltd", "india", "government", "hospital", "clinic", "diagnosis",
    "treatment", "password", "username", "resume", "curriculum", "vitae",
    "road", "street", "nagar", "society", "apartment", "apartments", "flat",
    "bank", "branch", "clinic", "doctor", "senior", "junior", "report",
    "invoice", "claim", "amount", "total", "gstin", "aadhaar", "pan",
    "age", "sex", "gender", "customer", "kyc", "confidential", "blood",
    "group", "client", "ip", "date", "birth", "father", "mother",
}
_ORG_TOKENS = {
    "limited", "ltd", "pvt", "private", "bank", "clinic", "hospital",
    "technologies", "technology", "services", "solutions", "systems",
    "corporation", "company", "department", "authority", "university",
    "institute", "college", "foundation", "trust", "group", "industries",
    "consultancy", "consulting", "laboratories", "labs", "holdings",
}

_MONTHS = (
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|"
    r"aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
)

_DOB_RE = re.compile(
    rf"(?i)(?<![A-Za-z])(?:date[ \t]*of[ \t]*birth|d\.?\s?o\.?\s?b\.?|birth[ \t]*date|birthday|"
    rf"born(?:[ \t]+on)?|जन्म[ \t]*तारीख|जन्मतारीख|जन्म[ \t]*दिनांक)"
    rf"[ \t]*(?:is|was|on)?[ \t]*[:\-]?[ \t]*"
    rf"(\d{{1,2}}[/\-.]\d{{1,2}}[/\-.]\d{{2,4}}|\d{{4}}-\d{{2}}-\d{{2}}|"
    rf"(?:\d{{1,2}}[ \t]+(?:{_MONTHS})[,\s]+\d{{4}})|"
    rf"(?:(?:{_MONTHS})[ \t]+\d{{1,2}},?[ \t]+\d{{4}}))"
)

_USERNAME_RE = re.compile(
    r"(?i)\b(?:user[ \t_\-]?name|user[ \t_\-]?id|login[ \t_\-]?id|login)[ \t]*[:=][ \t]*"
    r"([A-Za-z0-9._\-]{3,32})"
)

_LABELLED_ID_RE = re.compile(
    r"(?i)\b(employee|emp|staff|customer|cust|client|member)[ \t]*(?:id|code|no|number)"
    r"[ \t]*[:#\-]?[ \t]*([A-Z]{0,4}[-/]?\d{3,10})(?![A-Za-z0-9])"
)

_UPI_RE = re.compile(
    r"(?i)\b[A-Za-z0-9._\-]{2,64}@(?:okhdfcbank|okicici|okaxis|oksbi|"
    r"ybl|paytm|apl|upi|ibl|axl|jupiteraxis|airtel)\b"
)

_BANK_RE = re.compile(
    r"(?i)\b(?:account[ \t]*(?:no|number)?|a/c[ \t]*(?:no|number)?|acc[ \t]*(?:no|number))"
    r"[ \t]*[:#]?[ \t]*(\d[\d \t\-]{7,22}\d)"
)

_AADHAAR_RE = re.compile(r"(?<![A-Za-z0-9+])(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})(?![A-Za-z0-9])")
_AADHAAR_CONTEXT = ("aadhaar", "adhar", "uid", "unique identification", "आधार")
_AADHAAR_NEGATIVE_CONTEXT = (
    "order", "ticket", "invoice", "reference", "ref no", "serial", "enrolment",
    "enrollment", "tracking", "awb",
)

_PAN_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{5}[0-9]{4}[A-Z])(?![A-Z0-9])")
_GSTIN_RE = re.compile(r"(?<![A-Z0-9])([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9]Z[A-Z0-9])(?![A-Z0-9])")
_IFSC_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])")
_PASSPORT_RE = re.compile(
    r"(?i)\bpassport(?:[ \t]*(?:no|number))?[ \t]*[:\-]?[ \t]*([A-Z][1-9]\d{6})\b"
)
_PASSPORT_PLAIN_RE = re.compile(r"(?<![A-Z0-9])([A-Z][1-9]\d{6})(?![A-Z0-9])")
_PASSPORT_CONTEXT = (
    "passport", "travel document", "immigration", "visa", "nationality",
    "place of issue", "issued at", "issued by",
)
_VOTER_RE = re.compile(
    r"(?i)\b(?:voter(?:[ \t]*id)?|epic(?:[ \t]*number)?)[ \t]*[:\-]?[ \t]*([A-Z]{3}\d{7})\b"
)
_DL_RE = re.compile(
    r"(?i)\b(?:driving[ \t]*licen[cs]e|dl(?:[ \t]*no)?)[ \t]*[:\-]?[ \t]*"
    r"([A-Z]{2}[0-9]{2}[ \t]?[0-9]{11})\b"
)
_PIN_RE = re.compile(
    r"(?i)\b(?:pin(?:[ \t]*code)?|postal[ \t]*code|zip(?:[ \t]*code)?)[ \t]*[:\-]?[ \t]*"
    r"([1-9]\d{5})\b"
)

_IP_RE = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)")

_EMAIL_RE = re.compile(
    r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?![\w\-])"
)

_PHONE_IN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+?91[\s\-]?)?(?:0)?[6-9]\d{4}[\s\-]?\d{5}(?![A-Za-z0-9])"
)
_PHONE_GENERIC_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+\d{1,3}[\s\-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s\-]\d{3,4}[\s\-]?\d{3,5}(?![A-Za-z0-9])"
)
_TOLL_FREE_PREFIXES = ("1800", "1860", "1900", "1600")

_CARD_RE = re.compile(
    r"(?<!\d)(?:(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))(?:[ \-]?\d{4}){3}|"
    r"3[47]\d{2}[ \-]?\d{6}[ \-]?\d{5})(?!\d)"
)

_API_KEY_RE = re.compile(
    r"(?i)(?:api[_\-]?key|client[_\-]?secret|access[_\-]?token|auth[_\-]?token|token|secret)"
    r"[_\-\s]*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"
)
_PASSWORD_RE = re.compile(
    r"(?i)(?:password|passwd|pwd)[_\-\s]*[:=]\s*['\"]?(\S{6,})['\"]?"
)

_BLOOD_RE = re.compile(
    r"(?i)\b(?:blood[ \t]*(?:group|type))[ \t]*[:\-]?[ \t]*((?:AB|A|B|O)[ \t]?[+\-])"
)

_CURRENCY_RE = re.compile(
    r"(?:INR|Rs\.?|₹)[ \t]?([0-9][0-9,]*(?:\.[0-9]{1,2})?)"
)
_AMOUNT_CONTEXT_RE = re.compile(
    r"(?i)\b(?:salary|ctc|annual income|monthly income|income|amount|invoice total|"
    r"total|balance|payment|fee|price|cost|credited|revenue|compensation|stipend|"
    r"claim|earn(?:s|ing)?|paid|wage(?:s)?|receives?|earnings)\b"
    r"[^.\n]{0,30}?((?:\d{1,3}(?:,\d{2}){1,3}|\d{2,})(?:\.[0-9]{1,2})?)"
)

_LOCATION_CUE_RE = re.compile(
    r"(?i)\b(?:resident of|resident at|located (?:in|at|near)|based in|"
    r"lives? (?:in|at)|stays? (?:in|at)|native of|city of|moved to|"
    r"shifted to|settled in)\b[ \t]*[:\-]?[ \t]*"
)
_LOCATION_CONTEXT_RE = _LOCATION_CUE_RE  # backwards-compatible name
_CITY_RE = re.compile(rf"(?<![A-Za-z])(?:{_alternation(CITIES)})(?![A-Za-z])")
_PLACE_RE = re.compile(
    rf"(?<![A-Za-z])(?:{_alternation(CITIES + INDIAN_STATES)})(?![A-Za-z])"
)

# Natural-sentence addresses: "I live at 123 MG Road, Kolhapur."
_ADDRESS_CUE_RE = re.compile(
    r"(?i)\b(?:live|stay|reside|lives|stays|resides)[ \t]+(?:at|in|near)[ \t]+"
    r"|\b(?:located|situated|based)[ \t]+(?:at|in|near)[ \t]+"
)
_ADDRESS_STREET_RE = re.compile(
    r"(?i)\b(?:road|street|st\.?|lane|nagar|colony|society|apartment|apartments|"
    r"flat|house|sector|block|layout|extension|cross|park|villa|plot|chowk|"
    r"residency|lake|marg)\b"
)
_STRUCT_ADDRESS_RE = re.compile(
    r"(?<![A-Za-z0-9])(\d{1,4}[A-Za-z]?(?:[/\-]\d{1,4})?[ \t,]+"
    r"(?:[A-Z][A-Za-z.'\-]*[ \t]+){0,5}"
    r"(?:Road|Street|Lane|Nagar|Colony|Society|Apartments?|Residency|Villa|"
    r"Layout|Extension|Chowk|Marg))\b"
)

# Unlabelled single-token Indian first names (spaCy often misses these).
_SINGLE_NAME_RE = re.compile(r"(?<![A-Za-z])([A-Z][a-z]{2,})(?![A-Za-z])")
_NAME_FOLLOWERS = {
    "river", "lake", "road", "street", "nagar", "colony", "society",
    "hospital", "bank", "technologies", "technology", "limited", "ltd",
    "pvt", "private", "university", "institute", "college",
}


# ── Helpers ──────────────────────────────────────────────────
_LOCATION_TOKENS = {c.lower() for c in CITIES} | {s.lower() for s in INDIAN_STATES}
_GEO_WORDS = {
    "lake", "river", "hill", "valley", "district", "state", "india", "nagar",
    "colony", "society", "apartment", "apartments", "residency", "chowk",
}


def looks_like_person_name(value: str) -> bool:
    raw = (value or "").strip().strip(",.;:")
    raw = _TITLE_RE.sub("", raw)
    if not raw or len(raw) > 60 or any(ch.isdigit() for ch in raw):
        return False
    tokens = raw.split()
    if not 1 <= len(tokens) <= 4:
        return False
    for tok in tokens:
        core = tok.rstrip(".")
        if not core or len(core) < 2:
            return False
        if not re.fullmatch(r"[A-Za-z][A-Za-z'\-\.]*", core):
            return False
        if core.lower() in _NAME_BLOCKLIST:
            return False
        if core.lower() in _ORG_TOKENS:
            return False
        # spaCy frequently tags Indian place names as PERSON; reject them.
        if core.lower() in _LOCATION_TOKENS or core.lower() in _GEO_WORDS:
            return False
    if len(tokens) == 1:
        return tokens[0].capitalize() in FIRST_NAMES or tokens[0] in FIRST_NAMES
    return True


_NON_ORG_PHRASES = {
    "blood group", "age group", "user group", "working group", "employee group",
    "customer group", "product group", "interest group", "support group",
    "control group", "billing address", "client ip",
}


def valid_org_span(value: str) -> bool:
    raw = (value or "").strip().rstrip(":").strip()
    if len(raw) < 3 or "\n" in raw:
        return False
    if raw.lower() in _NON_ORG_PHRASES:
        return False
    tokens = raw.replace(".", "").split()
    if len(tokens) == 1:
        # A bare generic word is not an organisation; a known brand may be.
        if tokens[0].lower() in _ORG_TOKENS:
            return False
        if tokens[0].lower() in {"bank", "pan", "email", "address", "phone",
                                  "company", "department", "limited", "gstin",
                                  "aadhaar", "hospital", "clinic"}:
            return False
    return True


_ORG_GAZETTEER_LOWER = {org.lower() for org in KNOWN_ORGS}


def is_org_like(value: str) -> bool:
    """Strict acceptance test for NER-organisation entities."""
    cleaned = (value or "").strip().rstrip(":").strip()
    if not valid_org_span(cleaned):
        return False
    if cleaned.lower() in _ORG_GAZETTEER_LOWER:
        return True
    return bool(_ORG_SUFFIX_RE.fullmatch(cleaned))


def _line_bounds(text: str, pos: int) -> tuple[int, int]:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return start, end


def _has_medical_context(text: str) -> bool:
    lowered = text.lower()
    hits = sum(1 for w in MEDICAL_CONTEXT_WORDS if w in lowered)
    return hits >= 2


def _medical_line_context(text: str, pos: int) -> bool:
    line_start, line_end = _line_bounds(text, pos)
    line = text[line_start:line_end].lower()
    return any(w in line for w in MEDICAL_CONTEXT_WORDS) or _has_medical_context(text)


def _valid_date(day: int, month: int, year: int) -> bool:
    try:
        date(year, month, day)
        return 1900 <= year <= 2100
    except ValueError:
        return False


def _dob_is_valid(value: str) -> bool:
    value = value.strip()
    m = re.fullmatch(r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})", value)
    if m:
        d, mo, y = (int(x) for x in m.groups())
        if y < 100:
            y += 1900 if y > 30 else 2000
        return _valid_date(d, mo, y)
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", value)
    if m:
        y, mo, d = (int(x) for x in m.groups())
        return _valid_date(d, mo, y)
    return True  # month-name formats are validated by the regex shape


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _context_window(text: str, start: int, size: int = 60) -> str:
    return text[max(0, start - size):start].lower()


def _nearest_cue_distance(ctx: str, cues: tuple[str, ...]) -> int | None:
    """Characters between the closest cue occurrence and the end of the window."""
    best: int | None = None
    for cue in cues:
        idx = ctx.rfind(cue)
        if idx != -1:
            distance = len(ctx) - (idx + len(cue))
            if best is None or distance < best:
                best = distance
    return best


def _looks_like_address(value: str) -> bool:
    value = value.strip().strip(" .,;:-\t")
    if not (8 <= len(value) <= 140) or "\n" in value:
        return False
    has_street = bool(_ADDRESS_STREET_RE.search(value))
    has_number = bool(re.search(r"\b\d{1,4}\b", value))
    has_city = bool(_CITY_RE.search(value))
    has_pin = bool(re.search(r"\b[1-9]\d{5}\b", value))
    return has_street or (has_number and (has_city or has_pin))


# ── Extractors ───────────────────────────────────────────────
def _emails(text: str) -> list[RuleHit]:
    return [
        RuleHit("EMAIL", m.group(0), m.start(), m.end(), 0.97)
        for m in _EMAIL_RE.finditer(text)
    ]


def _phones(text: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    occupied: list[tuple[int, int]] = []

    for m in _PHONE_IN_RE.finditer(text):
        value = m.group(0)
        if not V.phone_in_valid(value):
            continue
        ctx = _context_window(text, m.start(), 40)
        conf = 0.9 if re.search(
            r"(mobile|phone|whatsapp|call|contact|mob\b|nambar|namber|"
            r"मोबाइल|मोबाईल|नंबर|नम्बर|फोन|दूरध्वनी)",
            ctx,
        ) else 0.85
        hits.append(RuleHit("PHONE_IN", value, m.start(), m.end(), conf))
        occupied.append((m.start(), m.end()))

    for m in _PHONE_GENERIC_RE.finditer(text):
        value = m.group(0)
        digits = _digits(value)
        local = digits[2:] if digits.startswith("91") and len(digits) == 12 else digits
        if not (len(digits) in (10, 11) or (len(digits) == 12 and digits.startswith("91"))):
            continue
        if local.startswith(_TOLL_FREE_PREFIXES):
            continue
        # 4-4-4 grouped 12-digit numbers are Aadhaar candidates, not phones
        if re.fullmatch(r"\d{4}[ \t\-]\d{4}[ \t\-]\d{4}", value):
            continue
        if any(m.start() < e and s < m.end() for s, e in occupied):
            continue
        if any(s <= m.start() and m.end() <= e for s, e in occupied):
            continue
        hits.append(RuleHit("PHONE_GENERIC", value, m.start(), m.end(), 0.78))

    return hits


def _aadhaar(text: str) -> list[RuleHit]:
    """
    Label-free Aadhaar detection.

    The numeric candidate is always considered first; context only decides
    how strongly it is classified:
      - Verhoeff-valid            → AADHAAR (verified checksum)
      - unverified + identity cue → AADHAAR_FORMAT (higher confidence)
      - unverified, no cue        → AADHAAR_FORMAT (low confidence)
    Only explicit non-identity context (order/invoice/reference/serial)
    suppresses a checksum-invalid candidate.
    """
    hits: list[RuleHit] = []
    for m in _AADHAAR_RE.finditer(text):
        value = m.group(1)
        start, end = m.start(1), m.end(1)
        if not V.aadhaar_format_valid(value):
            continue

        ctx = _context_window(text, start)
        positive = _nearest_cue_distance(ctx, _AADHAAR_CONTEXT)
        id_match = re.search(r"\bid\b", ctx)
        if id_match:
            id_distance = len(ctx) - id_match.end()
            positive = id_distance if positive is None else min(positive, id_distance)
        negative = _nearest_cue_distance(ctx, _AADHAAR_NEGATIVE_CONTEXT)

        # Nearest cue wins, so a label on a previous line cannot rescue a value
        # that is explicitly introduced as an order/reference number.
        negative_wins = negative is not None and (positive is None or negative < positive)

        if V.aadhaar_valid(value):
            hits.append(RuleHit("AADHAAR", value, start, end, 0.95))
        elif negative_wins:
            continue
        elif positive is not None:
            hits.append(RuleHit("AADHAAR_FORMAT", value, start, end, 0.75))
        else:
            hits.append(RuleHit("AADHAAR_FORMAT", value, start, end, 0.55))
    return hits


def _pan(text: str) -> list[RuleHit]:
    return [
        RuleHit("PAN", m.group(0), m.start(), m.end(), 0.9)
        for m in _PAN_RE.finditer(text)
        if V.pan_valid(m.group(0))
    ]


def _gstin(text: str) -> list[RuleHit]:
    return [
        RuleHit("GSTIN", m.group(0), m.start(), m.end(), 0.95)
        for m in _GSTIN_RE.finditer(text)
        if V.gstin_valid(m.group(0))
    ]


def _ifsc(text: str) -> list[RuleHit]:
    return [
        RuleHit("IFSC", m.group(0), m.start(), m.end(), 0.94)
        for m in _IFSC_RE.finditer(text)
        if V.ifsc_valid(m.group(0))
    ]


def _passport(text: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    seen: set[tuple[int, int]] = set()

    for m in _PASSPORT_RE.finditer(text):
        if V.passport_valid(m.group(1)):
            hits.append(RuleHit("PASSPORT", m.group(1), m.start(1), m.end(1), 0.9))
            seen.add((m.start(1), m.end(1)))

    # Label-free: an Indian passport-shaped code is only accepted when a
    # travel-document context appears nearby, to avoid flagging random codes.
    for m in _PASSPORT_PLAIN_RE.finditer(text):
        if (m.start(1), m.end(1)) in seen:
            continue
        if not V.passport_valid(m.group(1)):
            continue
        ctx = _context_window(text, m.start(1), 80)
        if not any(w in ctx for w in _PASSPORT_CONTEXT):
            continue
        hits.append(RuleHit("PASSPORT", m.group(1), m.start(1), m.end(1), 0.8))
    return hits


def _voter(text: str) -> list[RuleHit]:
    return [
        RuleHit("VOTER_ID", m.group(1), m.start(1), m.end(1), 0.9)
        for m in _VOTER_RE.finditer(text)
    ]


def _drivers_license(text: str) -> list[RuleHit]:
    return [
        RuleHit("DRIVERS_LICENSE", m.group(1), m.start(1), m.end(1), 0.9)
        for m in _DL_RE.finditer(text)
    ]


def _bank_accounts(text: str) -> list[RuleHit]:
    hits = []
    for m in _BANK_RE.finditer(text):
        value = m.group(1)
        ctx = _context_window(text, m.start(), 40)
        if any(w in ctx for w in ("sample", "example", "dummy", "placeholder", "format")):
            continue
        if not V.bank_account_valid(value):
            continue
        hits.append(RuleHit("BANK_ACCOUNT", value, m.start(1), m.end(1), 0.9))
    return hits


def _cards(text: str) -> list[RuleHit]:
    hits = []
    for m in _CARD_RE.finditer(text):
        if not V.luhn_valid(m.group(0)):
            continue
        hits.append(RuleHit("CREDIT_CARD", m.group(0), m.start(), m.end(), 0.95))
    return hits


def _upi(text: str) -> list[RuleHit]:
    return [
        RuleHit("UPI_ID", m.group(0), m.start(), m.end(), 0.9)
        for m in _UPI_RE.finditer(text)
    ]


def _ips(text: str) -> list[RuleHit]:
    hits = []
    for m in _IP_RE.finditer(text):
        ctx = _context_window(text, m.start(), 20)
        if "version" in ctx or "build" in ctx:
            continue
        hits.append(RuleHit("IP_ADDRESS", m.group(0), m.start(), m.end(), 0.92))
    return hits


def _usernames(text: str) -> list[RuleHit]:
    hits = []
    for m in _USERNAME_RE.finditer(text):
        value = m.group(1)
        if len(set(value)) < 3:
            continue
        hits.append(RuleHit("USERNAME", value, m.start(1), m.end(1), 0.85))
    return hits


def _labelled_ids(text: str) -> list[RuleHit]:
    """Employee/customer identifiers require an explicit label."""
    hits: list[RuleHit] = []
    for m in _LABELLED_ID_RE.finditer(text):
        label = m.group(1).lower()
        value = m.group(2)
        digits = _digits(value)
        if len(digits) < 3 or len(set(digits)) == 1:
            continue
        entity_type = "EMPLOYEE_ID" if label in ("employee", "emp", "staff") else "CUSTOMER_ID"
        hits.append(RuleHit(entity_type, value, m.start(2), m.end(2), 0.82))
    return hits


def _pincodes(text: str) -> list[RuleHit]:
    hits = []
    for m in _PIN_RE.finditer(text):
        if not V.pincode_valid(m.group(1)):
            continue
        hits.append(RuleHit("PIN_CODE", m.group(1), m.start(1), m.end(1), 0.9))
    return hits


def _blood_groups(text: str) -> list[RuleHit]:
    return [
        RuleHit("BLOOD_GROUP", m.group(1), m.start(1), m.end(1), 0.95)
        for m in _BLOOD_RE.finditer(text)
    ]


def _dob(text: str) -> list[RuleHit]:
    hits = []
    for m in _DOB_RE.finditer(text):
        value = m.group(1)
        if not _dob_is_valid(value):
            continue
        hits.append(RuleHit("DATE_OF_BIRTH", value, m.start(1), m.end(1), 0.93))
    return hits


def _api_keys(text: str) -> list[RuleHit]:
    return [
        RuleHit("API_KEY", m.group(0), m.start(), m.end(), 0.85)
        for m in _API_KEY_RE.finditer(text)
        if re.search(r"[0-9]", m.group(1)) and re.search(r"[A-Za-z]", m.group(1))
    ]


def _passwords(text: str) -> list[RuleHit]:
    hits = []
    for m in _PASSWORD_RE.finditer(text):
        value = m.group(1)
        if value.lower() in {"password", "passwd", "secret"}:
            continue
        hits.append(RuleHit("PASSWORD", m.group(0), m.start(), m.end(), 0.85))
    return hits


def _financial(text: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for m in _CURRENCY_RE.finditer(text):
        hits.append(RuleHit("FINANCIAL_VALUE", m.group(0), m.start(), m.end(), 0.88))
    for m in _AMOUNT_CONTEXT_RE.finditer(text):
        value = m.group(1)
        digits = _digits(value)
        if len(digits) >= 10:  # phone-like, not a monetary amount
            continue
        if re.fullmatch(r"(?:19|20)\d{2}", digits):  # bare year
            continue
        hits.append(RuleHit("FINANCIAL_VALUE", value, m.start(1), m.end(1), 0.8))
    return hits


def _medical(text: str) -> list[RuleHit]:
    # A single strong cue on the line (e.g. "the patient has ...") is enough;
    # the line-level check below still rejects uncued mentions.
    hits: list[RuleHit] = []

    def scan(items: list[str], etype: str, confidence: float) -> None:
        pattern = re.compile(rf"\b(?:{_alternation(items)})\b", re.IGNORECASE)
        for m in pattern.finditer(text):
            if not _medical_line_context(text, m.start()):
                continue
            hits.append(RuleHit(etype, m.group(0), m.start(), m.end(), confidence))

    scan(MEDICAL_CONDITIONS, "MEDICAL_CONDITION", 0.85)
    scan(MEDICAL_TREATMENTS, "MEDICAL_TREATMENT", 0.82)
    scan(MEDICATIONS, "MEDICATION", 0.82)
    return hits


def _gazetteer_names(text: str) -> list[RuleHit]:
    hits = []
    for m in _NAME_GAZETTEER_RE.finditer(text):
        value = m.group(0)
        if looks_like_person_name(value):
            hits.append(RuleHit("PERSON_NAME", value, m.start(), m.end(), 0.82))
    return hits


def looks_like_devanagari_name(value: str) -> bool:
    tokens = [t for t in (value or "").split() if t not in _DEV_NAME_STOP]
    if not 2 <= len(tokens) <= 4:
        return False
    return all(re.fullmatch(r"[\u0900-\u097F]{2,}", tok) for tok in tokens)


def _contextual_names(text: str) -> list[RuleHit]:
    """Names introduced by a name cue, including Hindi and Marathi cues."""
    hits: list[RuleHit] = []
    for m in _CONTEXT_NAME_LATIN_RE.finditer(text):
        value = m.group(1).rstrip(".,;:").strip()
        if looks_like_person_name(value):
            hits.append(RuleHit(
                "PERSON_NAME", value, m.start(1), m.start(1) + len(value), 0.84,
            ))
    for m in _CONTEXT_NAME_DEV_RE.finditer(text):
        value = m.group(1).strip().strip(".,;:")
        parts = [t for t in value.split() if t not in _DEV_NAME_STOP]
        value = " ".join(parts)
        if not looks_like_devanagari_name(value):
            continue
        start = text.find(value, m.start(1), m.end(1) + 1)
        if start == -1:
            continue
        hits.append(RuleHit("PERSON_NAME", value, start, start + len(value), 0.72))
    return hits


def _labelled_names(text: str) -> list[RuleHit]:
    hits = []
    for regex, confidence in ((_NAME_LABEL_RE, 0.9), (_NAME_SIGNED_RE, 0.85)):
        for m in regex.finditer(text):
            value = m.group(1).rstrip(".,;:").strip()
            if looks_like_person_name(value):
                hits.append(RuleHit("PERSON_NAME", value, m.start(1), m.start(1) + len(value), confidence))
    return hits


def _organizations(text: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for m in _ORG_GAZETTEER_RE.finditer(text):
        hits.append(RuleHit("ORGANIZATION", m.group(0), m.start(), m.end(), 0.88))
    for m in _ORG_SUFFIX_RE.finditer(text):
        value = m.group(0).strip()
        if valid_org_span(value):
            hits.append(RuleHit("ORGANIZATION", value, m.start(), m.end(), 0.8))
    return hits


def _sentence_addresses(text: str) -> list[RuleHit]:
    """Addresses expressed inside a sentence, without an "Address:" label."""
    hits: list[RuleHit] = []
    seen: set[tuple[int, int]] = set()
    sentence_stops = (".", "\n", ";", "!", "?")

    for m in _ADDRESS_CUE_RE.finditer(text):
        end = len(text)
        for stop in sentence_stops:
            idx = text.find(stop, m.end())
            if idx != -1:
                end = min(end, idx)
        end = min(end, m.end() + 140)
        value = text[m.end():end].strip().strip(",;:- ")
        # Stop at a clause connector; the next clause usually holds other data.
        value = re.split(r"(?i)\s+(?:and|but|while)\s+", value, maxsplit=1)[0]
        value = value.strip().strip(",;:- ")
        if not value or not _looks_like_address(value):
            continue
        start = text.find(value, m.end(), end + 1)
        if start == -1:
            continue
        key = (start, start + len(value))
        if key in seen:
            continue
        seen.add(key)
        hits.append(RuleHit("ADDRESS", value, start, start + len(value), 0.8))

    for m in _STRUCT_ADDRESS_RE.finditer(text):
        value = m.group(1).strip().strip(",;:- ")
        if not _looks_like_address(value):
            continue
        key = (m.start(1), m.start(1) + len(value))
        if key in seen:
            continue
        seen.add(key)
        hits.append(RuleHit("ADDRESS", value, m.start(1), m.start(1) + len(value), 0.78))

    return hits


def _addresses(text: str) -> list[RuleHit]:
    hits: list[RuleHit] = _sentence_addresses(text)
    for m in _ADDRESS_LABEL_RE.finditer(text):
        if m.group(1).strip():
            start = m.start(1)
            end = m.end(1)
        else:
            # "Shipping Address:" on its own line — the address starts below.
            newline = text.find("\n", m.end())
            if newline == -1:
                continue
            start = newline + 1
            while start < len(text) and text[start] in " \t":
                start += 1
            if start >= len(text) or text[start] == "\n":
                continue
            end = text.find("\n", start)
            if end == -1:
                end = len(text)

        value = text[start:end].strip()
        # Extend multi-line addresses (shipping labels, KYC forms)
        extended = end
        for _ in range(3):
            next_nl = text.find("\n", extended)
            if next_nl == -1:
                break
            line_start = next_nl + 1
            line_end = text.find("\n", line_start)
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end].strip()
            if not line:
                break
            if re.match(r"^[A-Za-z][A-Za-z ]{1,24}:", line):
                break
            looks_like_address = (
                _ADDRESS_CONTINUATION_RE.search(line)
                or "," in line
                or _CITY_RE.search(line)
            )
            if not looks_like_address:
                break
            extended = line_end
            value = text[start:extended].strip()
        if len(value) < 8:
            continue
        if not re.search(r"[\d,]", value):
            continue
        hits.append(RuleHit("ADDRESS", value, start, start + len(value), 0.85))
    return hits


def _locations(text: str) -> list[RuleHit]:
    """Locations introduced by locative grammar (lives in, resident of, ...)."""
    hits: list[RuleHit] = []
    seen: set[tuple[int, int]] = set()

    for m in _LOCATION_CUE_RE.finditer(text):
        end = len(text)
        for stop in (".", "\n", ";", "!", "?"):
            idx = text.find(stop, m.end())
            if idx != -1:
                end = min(end, idx)
        tail = text[m.end():min(end, m.end() + 90)]
        for pm in _PLACE_RE.finditer(tail):
            start = m.end() + pm.start()
            stop = start + len(pm.group(0))
            if (start, stop) in seen:
                continue
            seen.add((start, stop))
            hits.append(RuleHit("LOCATION", pm.group(0), start, stop, 0.7))
    return hits


def _single_token_names(text: str) -> list[RuleHit]:
    """Known Indian first names used alone ("Priya visited ...")."""
    hits: list[RuleHit] = []
    for m in _SINGLE_NAME_RE.finditer(text):
        token = m.group(1)
        if token not in FIRST_NAMES:
            continue
        follower = text[m.end():m.end() + 20].strip().split(" ", 1)[0].lower()
        if follower in _NAME_FOLLOWERS:
            continue
        hits.append(RuleHit("PERSON_NAME", token, m.start(1), m.end(1), 0.68))
    return hits


# ── Public entry point ───────────────────────────────────────
def extract_all(text: str) -> list[RuleHit]:
    """Run every rule layer and return raw (unmerged) hits."""
    if not text:
        return []
    hits: list[RuleHit] = []
    hits += _addresses(text)
    hits += _emails(text)
    hits += _cards(text)
    hits += _gstin(text)
    hits += _aadhaar(text)
    hits += _pan(text)
    hits += _ifsc(text)
    hits += _passport(text)
    hits += _voter(text)
    hits += _drivers_license(text)
    hits += _bank_accounts(text)
    hits += _upi(text)
    hits += _ips(text)
    hits += _pincodes(text)
    hits += _dob(text)
    hits += _blood_groups(text)
    hits += _usernames(text)
    hits += _phones(text)
    hits += _api_keys(text)
    hits += _passwords(text)
    hits += _financial(text)
    hits += _medical(text)
    hits += _labelled_ids(text)
    hits += _labelled_names(text)
    hits += _contextual_names(text)
    hits += _gazetteer_names(text)
    hits += _single_token_names(text)
    hits += _organizations(text)
    hits += _locations(text)
    return hits


def location_allowed(text: str, start: int, end: int) -> bool:
    """Only emit standalone location entities when explicitly cued."""
    window = _context_window(text, start, 40)
    return bool(re.search(
        r"(resident of|resident at|located in|located at|located near|based in|"
        r"lives? in|lives? at|stays? in|stays? at|native of|city of|moved to|"
        r"shifted to|settled in|city:|state:)\s*$",
        window,
    ))
