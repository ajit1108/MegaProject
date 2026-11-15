from app.services.detection_engine import detect
from app.services.sanitization import sanitize
from app.services.rag import extractive_answer, tokenize

samples = [
    "9876543210",
    "Call me at +91 9876543210 tomorrow.",
    "My number is 98765-43210.",
    "1234 5678 9012",
    "ajitbirajdar@gmail.com",
    "Ajit Birajdar is studying Computer Science and Business Systems.",
    "123 Main Street",
    "मेरा मोबाइल नंबर 9876543210 है।",
    "माझा मोबाईल नंबर 9876543210 आहे।",
    "My mobile number is 9876543210.",
    "Maza mobile number 9876543210 aahe.",
    "मेरा नाम Ajit Birajdar है।",
    "माझं नाव Ajit Birajdar आहे।",
    "He lives at 123 Main Street, Pune.",
    "Invalid phone 12345 and aadhaar 1234 567.",
    "The order reference is 1234 5678 9012.",
    "Patient has diabetes and takes metformin.",
    "IFSC HDFC0001234 account 123456789012",
    "UPI ajit@okhdfcbank PAN ABCDE1234F",
]
for s in samples:
    dets = detect(s)
    print("---", s)
    for d in dets:
        print(f"  {d.entity_type:16} {d.confidence:.2f} {d.matched_value!r}")

doc = (
    "Ajit Birajdar is studying Computer Science and Business Systems. "
    "He developed RetailX, CalmPulse, and Keystones."
)
dets = detect(doc)
print("DOC DETS")
for d in dets:
    print(f"  {d.entity_type:16} {d.matched_value!r}")
safe = sanitize(doc, [d.to_dict() for d in dets], mode="redact")
print("SAFE", safe)
qs = [
    "Which projects are mentioned?",
    "What is Ajit's course?",
    "Which project is related to grocery inventory?",
    "What projects are mentioned in this document?",
    "When does Project Falcon launch?",
]
raw_chunks = [{"sanitized_text": doc}]
safe_chunks = [{"sanitized_text": safe}]
for q in qs:
    print("Q", q, "TOK", tokenize(q))
    print(" RAW", extractive_answer(q, raw_chunks))
    print(" SAFE", extractive_answer(q, safe_chunks))
