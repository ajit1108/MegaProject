"""One-shot end-to-end check. Creates and deletes only its own user."""
import io
import os
from bson import ObjectId
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.services.detection_engine import detect
from app.services.text_extraction import extract_text

client = TestClient(app)
db = get_db()
tag = str(ObjectId())
email = f"e2e_{tag}@example.com"
password = "TestPass@123"
report = []

def check(name, ok, detail=""):
    report.append((ok, name, detail))
    print(("PASS" if ok else "FAIL"), name, detail)

# health
h = client.get("/api/health")
body = h.json()
check("health", h.status_code == 200 and body.get("database") == "ok" and body.get("nlp_available") is True,
      f"db={body.get('database')} nlp={body.get('nlp_available')}")

# auth
reg = client.post("/api/auth/register", json={"name": "E2E User", "email": email, "password": password})
check("register", reg.status_code == 201, str(reg.status_code))
dup = client.post("/api/auth/register", json={"name": "E2E User", "email": email, "password": password})
check("duplicate register rejected", dup.status_code == 409 or dup.status_code == 400, str(dup.status_code))
bad = client.post("/api/auth/login", json={"email": email, "password": "wrong-password"})
check("invalid login rejected", bad.status_code == 401, str(bad.status_code))
login = client.post("/api/auth/login", json={"email": email, "password": password})
check("login", login.status_code == 200 and "access_token" in login.json(), str(login.status_code))
token = login.json().get("access_token", "")
headers = {"Authorization": f"Bearer {token}"}
me = client.get("/api/auth/me", headers=headers)
check("me", me.status_code == 200 and me.json().get("email") == email)
unauth = client.get("/api/documents")
check("unauthenticated documents blocked", unauth.status_code == 401, str(unauth.status_code))

DOC = (
    "Ajit Birajdar is studying Computer Science and Business Systems. "
    "He developed RetailX, CalmPulse, and Keystones. "
    "Project Falcon is scheduled to launch in March 2027. "
    "The approved budget is 4.5 crore rupees. "
    "The deployment region is Pune. "
    "Contact ajitbirajdar@gmail.com or 9876543210. "
    "Aadhaar 2345 6789 0124. PAN ABCDE1234F. "
    "मेरा मोबाइल नंबर 9876543210 है। "
    "Patient has diabetes and takes metformin.\n"
)

samples = [
    "9876543210",
    "1234 5678 9012",
    "ajitbirajdar@gmail.com",
    "मेरा मोबाइल नंबर 9876543210 है।",
    "माझा मोबाईल नंबर 9876543210 आहे।",
    "Maza mobile number 9876543210 aahe.",
    "मेरा नाम Ajit Birajdar है।",
    "He lives at 123 Main Street, Pune.",
    "Patient has diabetes and takes metformin.",
    "IFSC HDFC0001234 account 123456789012",
]
print("--- detection samples ---")
for s in samples:
    types = sorted({d.entity_type for d in detect(s)})
    print(repr(s), "->", types)

up = client.post("/api/documents/upload", headers=headers, files={"file": ("facts.txt", DOC.encode(), "text/plain")})
check("upload txt", up.status_code == 201, str(up.status_code))
doc_id = up.json().get("id")
bad_type = client.post("/api/documents/upload", headers=headers, files={"file": ("x.exe", b"MZ", "application/octet-stream")})
check("reject bad type", bad_type.status_code == 400 or bad_type.status_code == 415, str(bad_type.status_code))
empty = client.post("/api/documents/upload", headers=headers, files={"file": ("empty.txt", b"   \n", "text/plain")})
check("empty file response", empty.status_code in (201, 400), str(empty.status_code))

an = client.post(f"/api/analysis/analyze/{doc_id}", headers=headers)
check("analyze", an.status_code == 200, an.text[:240] if an.status_code != 200 else "")
analysis = an.json()
aid = analysis.get("id")
types = {d.get("entity_type") for d in analysis.get("detections", [])}
check("email detected", "EMAIL" in types, str(sorted(types)))
check("phone detected", any(t.startswith("PHONE") for t in types))
check("pan detected", "PAN" in types)
check("risk present", isinstance(analysis.get("risk_score"), (int, float)) and analysis.get("risk_level"))
print("risk", analysis.get("risk_score"), analysis.get("risk_level"), "detections", len(analysis.get("detections", [])))

chunks = db.rag_chunks.count_documents({"analysis_id": ObjectId(aid)})
embedded = db.rag_chunks.count_documents({"analysis_id": ObjectId(aid), "embedding_status": "ok"})
check("indexed chunks", chunks >= 1, f"chunks={chunks} embedded={embedded}")

san = client.post(f"/api/analysis/{aid}/sanitize?mode=redact", headers=headers)
check("sanitize", san.status_code == 200, str(san.status_code))
san_body = san.json()
clean = san_body.get("sanitized_text") or ""
for secret in ("ajitbirajdar@gmail.com", "9876543210", "ABCDE1234F", "2345 6789 0124"):
    check(f"removed {secret.split('@')[0][:12]}", secret not in clean)

dl = client.get(f"/api/analysis/{aid}/sanitized-download", headers=headers)
check("download sanitized", dl.status_code == 200 and b"9876543210" not in dl.content, str(dl.status_code))

q = client.post("/api/rag/query", headers=headers, json={"question": "When does Project Falcon launch?", "debug": True})
qb = q.json()
check("rag launch", q.status_code == 200 and "March 2027" in qb.get("answer", ""), qb.get("answer", "")[:180])
check("citation page", bool(qb.get("citations")) and qb["citations"][0].get("page") == 1)
check("citation hides email", "ajitbirajdar@gmail.com" not in str(qb.get("citations")))
missing = client.post("/api/rag/query", headers=headers, json={"question": "What is the submarine hull thickness?"})
mb = missing.json()
check("unanswerable", "March 2027" not in mb.get("answer", "") and mb.get("citations") == [], mb.get("retrieval_status"))

# second user
other_email = f"e2e_other_{tag}@example.com"
oreg = client.post("/api/auth/register", json={"name": "Other", "email": other_email, "password": password})
ologin = client.post("/api/auth/login", json={"email": other_email, "password": password})
oheaders = {"Authorization": f"Bearer {ologin.json()['access_token']}"}
leak = client.post("/api/rag/query", headers=oheaders, json={"question": "When does Project Falcon launch?", "document_ids": [doc_id]})
check("other user cannot retrieve", leak.status_code == 200 and leak.json().get("citations") == [])
forbidden = client.get(f"/api/analysis/{aid}", headers=oheaders)
check("other user cannot read analysis", forbidden.status_code == 404, str(forbidden.status_code))

# pdf + docx generation
import fitz
pdf = fitz.open()
page = pdf.new_page()
page.insert_text((72, 72), "Project Falcon launches in March 2027. Email pdfuser@example.com")
buf = io.BytesIO()
pdf.save(buf)
pdf.close()
pup = client.post("/api/documents/upload", headers=headers, files={"file": ("facts.pdf", buf.getvalue(), "application/pdf")})
check("upload pdf", pup.status_code == 201, str(pup.status_code))
if pup.status_code == 201:
    pan = client.post(f"/api/analysis/analyze/{pup.json()['id']}", headers=headers)
    ptypes = {d.get("entity_type") for d in pan.json().get("detections", [])} if pan.status_code == 200 else set()
    check("pdf email", pan.status_code == 200 and "EMAIL" in ptypes, str(sorted(ptypes)))
    pq = client.post("/api/rag/query", headers=headers, json={
        "question": "When does Project Falcon launch?",
        "document_ids": [pup.json()["id"]],
    })
    check("pdf rag scoped", pq.status_code == 200 and "March 2027" in pq.json().get("answer", ""), pq.json().get("answer", "")[:160])

from docx import Document
d = Document()
d.add_paragraph("The deployment region is Nashik. Contact docxuser@example.com.")
dbuf = io.BytesIO()
d.save(dbuf)
dup = client.post("/api/documents/upload", headers=headers, files={"file": ("facts.docx", dbuf.getvalue(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")})
check("upload docx", dup.status_code == 201, str(dup.status_code))
if dup.status_code == 201:
    dan = client.post(f"/api/analysis/analyze/{dup.json()['id']}", headers=headers)
    dtypes = {d.get("entity_type") for d in dan.json().get("detections", [])} if dan.status_code == 200 else set()
    check("docx email", dan.status_code == 200 and "EMAIL" in dtypes)

# corrupt pdf
badpdf = client.post("/api/documents/upload", headers=headers, files={"file": ("bad.pdf", b"%PDF-1.4 not a real pdf", "application/pdf")})
check("corrupt pdf upload status", badpdf.status_code in (201, 400), str(badpdf.status_code))
if badpdf.status_code == 201:
    ban = client.post(f"/api/analysis/analyze/{badpdf.json()['id']}", headers=headers)
    check("corrupt pdf handled", ban.status_code in (200, 400, 422, 500), str(ban.status_code))

# delete and confirm chunks gone
deleted = client.delete(f"/api/documents/{doc_id}", headers=headers)
left = db.rag_chunks.count_documents({"document_id": ObjectId(doc_id)})
check("delete document", deleted.status_code == 200 and left == 0, f"status={deleted.status_code} chunks_left={left}")

# logout revocation
out = client.post("/api/auth/logout", headers=headers)
after = client.get("/api/auth/me", headers=headers)
check("logout revokes token", out.status_code == 200 and after.status_code == 401, f"{out.status_code}/{after.status_code}")

# cleanup remaining docs for both users
for em in (email, other_email):
    user = db.users.find_one({"email": em})
    if not user:
        continue
    uid = user["_id"]
    for doc in db.documents.find({"user_id": uid}):
        path = doc.get("file_path")
        if path and os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
        db.rag_chunks.delete_many({"document_id": doc["_id"]})
    aids = [a["_id"] for a in db.analyses.find({"user_id": uid}, {"_id": 1})]
    for rec in db.sanitized_documents.find({"user_id": uid}):
        path = rec.get("sanitized_file_path")
        if path and os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
    db.documents.delete_many({"user_id": uid})
    db.analyses.delete_many({"user_id": uid})
    db.sanitized_documents.delete_many({"user_id": uid})
    db.pseudonym_maps.delete_many({"user_id": uid})
    db.rag_chunks.delete_many({"user_id": uid})
    db.rag_conversations.delete_many({"user_id": uid})
    db.audit_logs.delete_many({"user_id": uid})
    db.users.delete_one({"_id": uid})

failed = [r for r in report if not r[0]]
print("SUMMARY", len(report) - len(failed), "passed", len(failed), "failed")
raise SystemExit(1 if failed else 0)
