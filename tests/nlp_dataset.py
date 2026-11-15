# ============================================================
# tests/nlp_dataset.py
# Hand-labelled gold dataset for honest before/after measurement
# of the sensitive-data detection engine.
#
# Gold spans are declared as (entity_type, surface_text). Offsets are
# resolved against the raw document text at load time, in declaration
# order, so the labels are human-readable and cannot silently drift.
#
# Entity types used in gold labels are canonical. The scorer treats
# a small set of legacy names as compatible (PHONE_GENERIC, PERSON, ...).
# ============================================================

DOCS: list[dict] = [
    {
        "id": "resume_01",
        "genre": "resume / plain text",
        "text": (
            "CURRICULUM VITAE\n"
            "Name: Ajit Birajdar\n"
            "Email: ajit.birajdar@example.com\n"
            "Mobile: +91 98765 43210\n"
            "Address: Flat 4B, Sunrise Apartments, MG Road, Pune, Maharashtra 411001\n"
            "Date of Birth: 15/08/1995\n"
            "PAN: ABCDE1234F\n"
            "Aadhaar: 2345 6789 0124\n"
        ),
        "gold": [
            ("PERSON_NAME", "Ajit Birajdar"),
            ("EMAIL", "ajit.birajdar@example.com"),
            ("PHONE_IN", "+91 98765 43210"),
            ("ADDRESS", "Flat 4B, Sunrise Apartments, MG Road, Pune, Maharashtra 411001"),
            ("DATE_OF_BIRTH", "15/08/1995"),
            ("PAN", "ABCDE1234F"),
            ("AADHAAR", "2345 6789 0124"),
        ],
    },
    {
        "id": "email_signature_02",
        "genre": "email body",
        "text": (
            "Subject: Vendor onboarding\n\n"
            "Hi team,\n\n"
            "Please coordinate with our new vendor for the annual audit.\n\n"
            "Regards,\n"
            "Rajeshwari Krishnamurthy\n"
            "Senior Manager, Megacorp Technologies Pvt Ltd\n"
            "Direct: 020-2456-7890\n"
            "Mobile: 9822011223\n"
            "Email: rajeshwari.k@megacorp.co.in\n"
        ),
        "gold": [
            ("PERSON_NAME", "Rajeshwari Krishnamurthy"),
            ("ORGANIZATION", "Megacorp Technologies Pvt Ltd"),
            ("PHONE_GENERIC", "020-2456-7890"),
            ("PHONE_IN", "9822011223"),
            ("EMAIL", "rajeshwari.k@megacorp.co.in"),
        ],
    },
    {
        "id": "aadhaar_letter_03",
        "genre": "government letter",
        "text": (
            "Unique Identification Authority of India\n"
            "Aadhaar No: 9876 5432 1012\n"
            "Enrolment ID: 1234/56789/01234\n"
        ),
        "gold": [
            ("ORGANIZATION", "Unique Identification Authority of India"),
            ("AADHAAR", "9876 5432 1012"),
        ],
    },
    {
        "id": "tax_passport_04",
        "genre": "tax form",
        "text": (
            "Income Tax Department\n"
            "PAN: BKLPA2345C\n"
            "Passport No: M1234567\n"
        ),
        "gold": [
            ("ORGANIZATION", "Income Tax Department"),
            ("PAN", "BKLPA2345C"),
            ("PASSPORT", "M1234567"),
        ],
    },
    {
        "id": "bank_details_05",
        "genre": "bank / reimbursement form",
        "text": (
            "Bank account details for reimbursement\n"
            "Account Holder: Suresh Patil\n"
            "Account Number: 1234567890123\n"
            "IFSC Code: HDFC0001234\n"
            "Bank: HDFC Bank\n"
            "Branch: Kothrud, Pune\n"
        ),
        "gold": [
            ("PERSON_NAME", "Suresh Patil"),
            ("BANK_ACCOUNT", "1234567890123"),
            ("IFSC", "HDFC0001234"),
            ("ORGANIZATION", "HDFC Bank"),
        ],
    },
    {
        "id": "card_06",
        "genre": "payment confirmation",
        "text": (
            "Payment received successfully.\n"
            "Card Number: 4111 1111 1111 1111\n"
            "Expiry: 09/28\n"
            "Billing Address: 22 Baker Street, London NW1 6XE\n"
        ),
        "gold": [
            ("CREDIT_CARD", "4111 1111 1111 1111"),
            ("ADDRESS", "22 Baker Street, London NW1 6XE"),
        ],
    },
    {
        "id": "phones_07",
        "genre": "contact sheet",
        "text": (
            "Reach the helpdesk at (020) 2456 7890 or 020-24567890.\n"
            "Alternate mobile: +91-98765-43210.\n"
            "International desk: +1 (415) 555-0132.\n"
        ),
        "gold": [
            ("PHONE_GENERIC", "(020) 2456 7890"),
            ("PHONE_GENERIC", "020-24567890"),
            ("PHONE_IN", "+91-98765-43210"),
            ("PHONE_GENERIC", "+1 (415) 555-0132"),
        ],
    },
    {
        "id": "dob_08",
        "genre": "HR record",
        "text": (
            "Employee record\n"
            "Date of Birth: 15-08-1995\n"
            "Joining Date: 01/04/2021\n"
        ),
        "gold": [
            ("DATE_OF_BIRTH", "15-08-1995"),
        ],
    },
    {
        "id": "medical_09",
        "genre": "clinical note",
        "text": (
            "Patient Name: Meera Joshi\n"
            "Age: 42\n"
            "Diagnosis: Type 2 Diabetes Mellitus\n"
            "Prescription: Metformin 500 mg twice daily\n"
            "Blood Group: O+\n"
            "Allergies: Penicillin\n"
        ),
        "gold": [
            ("PERSON_NAME", "Meera Joshi"),
            ("MEDICAL_CONDITION", "Type 2 Diabetes Mellitus"),
            ("MEDICATION", "Metformin"),
            ("BLOOD_GROUP", "O+"),
            ("MEDICATION", "Penicillin"),
        ],
    },
    {
        "id": "salary_10",
        "genre": "offer letter",
        "text": (
            "Offer letter\n"
            "Annual CTC: INR 12,50,000\n"
            "Monthly salary of 45000 is credited on the 1st of every month.\n"
            "The invoice total is 45678.00 including GST.\n"
        ),
        "gold": [
            ("FINANCIAL_VALUE", "INR 12,50,000"),
            ("FINANCIAL_VALUE", "45000"),
            ("FINANCIAL_VALUE", "45678.00"),
        ],
    },
    {
        "id": "address_11",
        "genre": "shipping label",
        "text": (
            "Shipping Address:\n"
            "Flat 7, Green Park Society\n"
            "Andheri West, Mumbai\n"
            "Maharashtra 400053\n"
        ),
        "gold": [
            ("ADDRESS", "Flat 7, Green Park Society\nAndheri West, Mumbai\nMaharashtra 400053"),
        ],
    },
    {
        "id": "ids_12",
        "genre": "KYC identifiers",
        "text": (
            "GSTIN: 27AAPFU0939F1ZV\n"
            "Voter ID: ABC1234567\n"
            "Driving Licence: MH12 20150012345\n"
            "UPI ID: ajit.birajdar@okhdfcbank\n"
            "Username: ajit_b95\n"
        ),
        "gold": [
            ("GSTIN", "27AAPFU0939F1ZV"),
            ("VOTER_ID", "ABC1234567"),
            ("DRIVERS_LICENSE", "MH12 20150012345"),
            ("UPI_ID", "ajit.birajdar@okhdfcbank"),
            ("USERNAME", "ajit_b95"),
        ],
    },
    {
        "id": "ip_log_13",
        "genre": "server log",
        "text": (
            "Access log\n"
            "Client IP: 203.0.113.77\n"
            "Internal host: 192.168.1.100\n"
            "Build version 1.2.3.4 deployed.\n"
        ),
        "gold": [
            ("IP_ADDRESS", "203.0.113.77"),
            ("IP_ADDRESS", "192.168.1.100"),
        ],
    },
    {
        "id": "negative_numbers_14",
        "genre": "negative / ordinary numbers",
        "text": (
            "Quarterly report\n"
            "The order contains 12 items and weighs 4500 grams.\n"
            "The year 2024 had 366 days.\n"
            "Ticket reference: 889900.\n"
            "Call extension 4567.\n"
            "Order number 1234 5678 9012 was shipped.\n"
        ),
        "gold": [],
    },
    {
        "id": "names_15",
        "genre": "names with titles",
        "text": (
            "Dr. Ananya Deshpande reviewed the case with Mr. Suresh Patil.\n"
            "Shrikant Gopalrao Deshmukh approved the budget.\n"
        ),
        "gold": [
            ("PERSON_NAME", "Ananya Deshpande"),
            ("PERSON_NAME", "Suresh Patil"),
            ("PERSON_NAME", "Shrikant Gopalrao Deshmukh"),
        ],
    },
    {
        "id": "orgs_16",
        "genre": "vendor list",
        "text": (
            "Vendors: Infosys Limited, Tata Consultancy Services and State Bank of India.\n"
        ),
        "gold": [
            ("ORGANIZATION", "Infosys Limited"),
            ("ORGANIZATION", "Tata Consultancy Services"),
            ("ORGANIZATION", "State Bank of India"),
        ],
    },
    {
        "id": "negative_placeholder_17",
        "genre": "negative / documentation example",
        "text": (
            "The PAN format is AAAAA9999A and every citizen should know it.\n"
            "Sample account number 0000 0000 0000 is printed on the form.\n"
        ),
        "gold": [],
    },
    {
        "id": "kyc_mixed_18",
        "genre": "KYC form",
        "text": (
            "CONFIDENTIAL - KYC FORM\n"
            "Applicant: Vikram Singh Rathore\n"
            "Father's Name: Mahendra Singh Rathore\n"
            "DOB: 03/11/1988\n"
            "Mobile: 9988776655\n"
            "Email: vikram.rathore@mail.in\n"
            "Aadhaar: 5551 2345 6781\n"
            "PAN: QWERT5678Y\n"
            "Address: 101, Lake View Residency, Baner Road, Pune 411045\n"
        ),
        "gold": [
            ("PERSON_NAME", "Vikram Singh Rathore"),
            ("PERSON_NAME", "Mahendra Singh Rathore"),
            ("DATE_OF_BIRTH", "03/11/1988"),
            ("PHONE_IN", "9988776655"),
            ("EMAIL", "vikram.rathore@mail.in"),
            ("AADHAAR", "5551 2345 6781"),
            ("PAN", "QWERT5678Y"),
            ("ADDRESS", "101, Lake View Residency, Baner Road, Pune 411045"),
        ],
    },
    {
        "id": "negative_article_19",
        "genre": "negative / general article",
        "text": (
            "This is a general awareness article about saving water.\n"
            "It discusses rainfall patterns and public policy.\n"
        ),
        "gold": [],
    },
    {
        "id": "aadhaar_ungrouped_20",
        "genre": "KYC update",
        "text": (
            "KYC update request\n"
            "Aadhaar: 234567890124\n"
            "Mobile: 09876543210\n"
        ),
        "gold": [
            ("AADHAAR", "234567890124"),
            ("PHONE_IN", "09876543210"),
        ],
    },
    {
        "id": "medical_insurance_21",
        "genre": "insurance claim",
        "text": (
            "Health Insurance Claim\n"
            "Patient: Kavita Rane\n"
            "Treatment: Chemotherapy for Breast Cancer\n"
            "Claim Amount: Rs. 2,50,000\n"
            "Hospital: Ruby Hall Clinic\n"
        ),
        "gold": [
            ("PERSON_NAME", "Kavita Rane"),
            ("MEDICAL_CONDITION", "Breast Cancer"),
            ("MEDICAL_TREATMENT", "Chemotherapy"),
            ("FINANCIAL_VALUE", "Rs. 2,50,000"),
            ("ORGANIZATION", "Ruby Hall Clinic"),
        ],
    },
    {
        "id": "pincode_22",
        "genre": "structured address form",
        "text": (
            "Customer KYC\n"
            "House No: 8-2-293\n"
            "Street: Road No. 12, Banjara Hills\n"
            "City: Hyderabad\n"
            "PIN Code: 500034\n"
        ),
        "gold": [
            ("PIN_CODE", "500034"),
        ],
    },
    {
        "id": "negative_tollfree_23",
        "genre": "negative / support page",
        "text": (
            "Support page\n"
            "Toll free: 1800-123-4567\n"
            "Working hours 9:00 to 18:00.\n"
        ),
        "gold": [],
    },
    {
        "id": "uppercase_24",
        "genre": "contact details",
        "text": (
            "Contact: AJIT.BIRAJDAR@EXAMPLE.COM\n"
            "Phone: +91 90000 00001\n"
        ),
        "gold": [
            ("EMAIL", "AJIT.BIRAJDAR@EXAMPLE.COM"),
            ("PHONE_IN", "+91 90000 00001"),
        ],
    },
]


# Held-out challenge documents. These were written after the engine was
# tuned and are reported separately as a generalisation check.
HELDOUT_DOCS: list[dict] = [
    {
        "id": "h01_international_names",
        "genre": "meeting notes",
        "text": (
            "John Smith met Maria Gonzalez in the lobby.\n"
            "Zhang Wei joined them later.\n"
        ),
        "gold": [
            ("PERSON_NAME", "John Smith"),
            ("PERSON_NAME", "Maria Gonzalez"),
            ("PERSON_NAME", "Zhang Wei"),
        ],
    },
    {
        "id": "h02_unlabelled_indian_names",
        "genre": "project update",
        "text": (
            "Priya Nair will lead the project.\n"
            "Tanmay Bhosale is the reviewer.\n"
        ),
        "gold": [
            ("PERSON_NAME", "Priya Nair"),
            ("PERSON_NAME", "Tanmay Bhosale"),
        ],
    },
    {
        "id": "h03_oov_name",
        "genre": "board minutes",
        "text": "Gurpreet Sandhu addressed the board about the merger.\n",
        "gold": [
            ("PERSON_NAME", "Gurpreet Sandhu"),
        ],
    },
    {
        "id": "h04_landlines",
        "genre": "office directory",
        "text": (
            "Head office: +91 22 2456 7890\n"
            "Regional office: 022-24567890\n"
        ),
        "gold": [
            ("PHONE_GENERIC", "+91 22 2456 7890"),
            ("PHONE_GENERIC", "022-24567890"),
        ],
    },
    {
        "id": "h05_amex",
        "genre": "payment record",
        "text": "Corporate card on file: 3782 822463 10005.\n",
        "gold": [
            ("CREDIT_CARD", "3782 822463 10005"),
        ],
    },
    {
        "id": "h06_aadhaar_dashed",
        "genre": "UIDAI letter",
        "text": "UIDAI letter\nAadhaar No : 2345-6789-0124\n",
        "gold": [
            ("AADHAAR", "2345-6789-0124"),
        ],
    },
    {
        "id": "h07_dob_formats",
        "genre": "personal details",
        "text": (
            "Personal details\n"
            "Date of Birth: 12 May 2003\n"
            "Alternative DOB: 2003-05-12\n"
        ),
        "gold": [
            ("DATE_OF_BIRTH", "12 May 2003"),
            ("DATE_OF_BIRTH", "2003-05-12"),
        ],
    },
    {
        "id": "h08_medical_sentence",
        "genre": "clinical note",
        "text": "The patient was diagnosed with hypertension and takes amlodipine daily.\n",
        "gold": [
            ("MEDICAL_CONDITION", "hypertension"),
            ("MEDICATION", "amlodipine"),
        ],
    },
    {
        "id": "h09_negative_dates_ip",
        "genre": "negative / ordinary dates",
        "text": (
            "The agreement was signed on 12/05/2023.\n"
            "Server build 8.8.8.8 was tested.\n"
            "The PAN format uses ten characters.\n"
        ),
        "gold": [],
    },
    {
        "id": "h10_org_suffix",
        "genre": "corporate filing",
        "text": "Adani Enterprises and Acme Corp filed the report.\n",
        "gold": [
            ("ORGANIZATION", "Adani Enterprises"),
            ("ORGANIZATION", "Acme Corp"),
        ],
    },
    {
        "id": "h11_location_context",
        "genre": "profile",
        "text": "She is a resident of Nagpur and works remotely.\n",
        "gold": [
            ("LOCATION", "Nagpur"),
        ],
    },
    {
        "id": "h12_negative_capitalisation",
        "genre": "negative / capitalised words",
        "text": "My name is not important. The Patient Report is confidential.\n",
        "gold": [],
    },
    {
        "id": "h13_address_block",
        "genre": "permanent address",
        "text": (
            "Permanent Address:\n"
            "B-12, Rose Villa\n"
            "Sector 21, Noida\n"
            "Uttar Pradesh 201301\n"
        ),
        "gold": [
            ("ADDRESS", "B-12, Rose Villa\nSector 21, Noida\nUttar Pradesh 201301"),
        ],
    },
    {
        "id": "h14_login_upi",
        "genre": "account details",
        "text": (
            "Login ID: rahul_2024\n"
            "UPI: rahul@okaxis\n"
        ),
        "gold": [
            ("USERNAME", "rahul_2024"),
            ("UPI_ID", "rahul@okaxis"),
        ],
    },
    {
        "id": "h15_negative_invoice_numbers",
        "genre": "negative / reference numbers",
        "text": (
            "Invoice number 4500 was paid in 2023.\n"
            "Call extension 4567 for help.\n"
        ),
        "gold": [],
    },
]


# Natural-sentence split: every sensitive value appears both with and
# without an explicit label. Used to measure label independence.
NATURAL_DOCS: list[dict] = [
    {
        "id": "n01_labelled_name",
        "genre": "labelled name",
        "text": "Name: Ajit Birajdar\n",
        "gold": [("PERSON_NAME", "Ajit Birajdar")],
    },
    {
        "id": "n02_unlabelled_name",
        "genre": "unlabelled sentence",
        "text": "Ajit Birajdar is developing a project.\n",
        "gold": [("PERSON_NAME", "Ajit Birajdar")],
    },
    {
        "id": "n03_name_in_sentence",
        "genre": "unlabelled sentence",
        "text": "My friend Ajit Birajdar visited Kolhapur.\n",
        "gold": [("PERSON_NAME", "Ajit Birajdar")],
    },
    {
        "id": "n04_labelled_email",
        "genre": "labelled email",
        "text": "Email: ajit@example.com\n",
        "gold": [("EMAIL", "ajit@example.com")],
    },
    {
        "id": "n05_unlabelled_email",
        "genre": "unlabelled sentence",
        "text": "Contact me at ajit@example.com.\n",
        "gold": [("EMAIL", "ajit@example.com")],
    },
    {
        "id": "n06_labelled_phone",
        "genre": "labelled phone",
        "text": "My phone number is 9876543210.\n",
        "gold": [("PHONE_IN", "9876543210")],
    },
    {
        "id": "n07_unlabelled_phone",
        "genre": "unlabelled sentence",
        "text": "Call me on 9876543210.\n",
        "gold": [("PHONE_IN", "9876543210")],
    },
    {
        "id": "n08_address_sentence",
        "genre": "unlabelled address",
        "text": "I live at 123 MG Road, Kolhapur.\n",
        "gold": [("ADDRESS", "123 MG Road, Kolhapur")],
    },
    {
        "id": "n09_address_locality",
        "genre": "unlabelled address",
        "text": "She stays in Shivaji Nagar, Pune.\n",
        "gold": [("ADDRESS", "Shivaji Nagar, Pune")],
    },
    {
        "id": "n10_address_landmark",
        "genre": "unlabelled address",
        "text": "The office is located near Rankala Lake, Kolhapur.\n",
        "gold": [("ADDRESS", "Rankala Lake, Kolhapur")],
    },
    {
        "id": "n11_dob_sentence",
        "genre": "unlabelled DOB",
        "text": "I was born on 12 May 2003.\n",
        "gold": [("DATE_OF_BIRTH", "12 May 2003")],
    },
    {
        "id": "n12_birthday_sentence",
        "genre": "unlabelled DOB",
        "text": "Her birthday is 15/08/2001.\n",
        "gold": [("DATE_OF_BIRTH", "15/08/2001")],
    },
    {
        "id": "n13_medical_sentence",
        "genre": "unlabelled medical",
        "text": "The patient has diabetes and hypertension.\n",
        "gold": [
            ("MEDICAL_CONDITION", "diabetes"),
            ("MEDICAL_CONDITION", "hypertension"),
        ],
    },
    {
        "id": "n14_person_and_org",
        "genre": "unlabelled person/org",
        "text": "Ajit works at ABC Technologies.\n",
        "gold": [
            ("PERSON_NAME", "Ajit"),
            ("ORGANIZATION", "ABC Technologies"),
        ],
    },
    {
        "id": "n15_financial_sentence",
        "genre": "unlabelled financial",
        "text": "The employee earns 45000 per month.\n",
        "gold": [("FINANCIAL_VALUE", "45000")],
    },
    {
        "id": "n16_location_sentence",
        "genre": "unlabelled location",
        "text": "Ajit lives in Kolhapur Maharashtra.\n",
        "gold": [
            ("PERSON_NAME", "Ajit"),
            ("LOCATION", "Kolhapur"),
            ("LOCATION", "Maharashtra"),
        ],
    },
    {
        "id": "n17_aadhaar_sentence",
        "genre": "unlabelled identifier",
        "text": "My Aadhaar number is 1234 5678 9012.\n",
        "gold": [("AADHAAR_FORMAT", "1234 5678 9012")],
    },
    {
        "id": "n18_signed_name",
        "genre": "email signature",
        "text": "Signed by Barack Obama.\n",
        "gold": [("PERSON_NAME", "Barack Obama")],
    },
    {
        "id": "n19_negative_sentences",
        "genre": "negative / ordinary sentences",
        "text": (
            "There are 12 items in 2024 and 3 boxes on the shelf.\n"
            "The agreement was signed on 12/05/2023.\n"
            "Invoice number 4500 was paid in 2023.\n"
            "Toll free: 1800-123-4567.\n"
        ),
        "gold": [],
    },
    {
        "id": "n20_negative_capitalisation",
        "genre": "negative / capitalised words",
        "text": "My name is not important. The Patient Report is confidential.\n",
        "gold": [],
    },
]



def resolve_gold(doc: dict) -> list[dict]:
    """Resolve declared (type, surface) pairs into offsets for one document."""
    text = doc["text"]
    gold = []
    cursor = 0
    for entity_type, surface in doc["gold"]:
        idx = text.find(surface, cursor)
        if idx == -1:
            idx = text.find(surface)
        if idx == -1:
            raise ValueError(f"Gold surface {surface!r} not found in document {doc['id']}")
        gold.append({
            "entity_type": entity_type,
            "matched_value": surface,
            "start": idx,
            "end": idx + len(surface),
        })
        cursor = idx + len(surface)
    return gold


def load_docs() -> list[dict]:
    """Return development documents with resolved gold offsets."""
    return _resolve_all(DOCS)


def load_heldout_docs() -> list[dict]:
    """Return held-out challenge documents with resolved gold offsets."""
    return _resolve_all(HELDOUT_DOCS)


def load_natural_docs() -> list[dict]:
    """Return the labelled/unlabelled natural-sentence split."""
    return _resolve_all(NATURAL_DOCS)


def _resolve_all(docs: list[dict]) -> list[dict]:
    return [
        {
            "id": d["id"],
            "genre": d["genre"],
            "text": d["text"],
            "gold": resolve_gold(d),
        }
        for d in docs
    ]
