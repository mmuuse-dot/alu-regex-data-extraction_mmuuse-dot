import re
import json
from pathlib import Path

# -----------------------------
# Read input file
# -----------------------------

input_file = Path("input/raw-text.txt")

with open(input_file, "r", encoding="utf-8") as file:
    text = file.read()

# -----------------------------
# Security filtering
# Reject suspicious content
# -----------------------------

dangerous_patterns = [
    r"<script.*?>.*?</script>",
    r"DROP\s+TABLE",
    r"DELETE\s+FROM",
    r"javascript:"
]

clean_text = text

for pattern in dangerous_patterns:
    clean_text = re.sub(pattern, "", clean_text, flags=re.IGNORECASE)

# -----------------------------
# Regex patterns
# -----------------------------

# General emails
email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'

# ALU email validations
alu_official_pattern = r'\b[a-zA-Z0-9._%+-]+@alueducation\.com\b'
alu_alumni_pattern = r'\b[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com\b'
alu_si_pattern = r'\b[a-zA-Z0-9._%+-]+@si\.alueducation\.com\b'

# URLs
url_pattern = r'https?://[^\s]+'

# Phone numbers
phone_pattern = r'(\+\d{1,3}\s\d{3}\s\d{3}\s\d{3}|\(\d{3}\)\s\d{3}-\d{4}|\d{3}-\d{3}-\d{4})'

# Credit cards
card_pattern = r'(?:\d{4}[- ]?){3}\d{4}'

# -----------------------------
# Extract data
# -----------------------------

emails = re.findall(email_pattern, clean_text)

alu_official = re.findall(alu_official_pattern, clean_text)
alu_alumni = re.findall(alu_alumni_pattern, clean_text)
alu_si = re.findall(alu_si_pattern, clean_text)

urls = re.findall(url_pattern, clean_text)

phones = re.findall(phone_pattern, clean_text)

cards = re.findall(card_pattern, clean_text)

# -----------------------------
# Mask credit card numbers
# Security: avoid exposing full numbers
# -----------------------------

masked_cards = []

for card in cards:
    digits = re.sub(r'[- ]', '', card)

    if len(digits) == 16:
        masked = digits[:4] + " **** **** " + digits[-4:]
        masked_cards.append(masked)

# -----------------------------
# Remove duplicates
# -----------------------------

emails = list(set(emails))
urls = list(set(urls))
phones = list(set(phones))
masked_cards = list(set(masked_cards))

# -----------------------------
# Prepare output
# -----------------------------

results = {
    "valid_emails": emails,
    "alu_official_emails": alu_official,
    "alu_alumni_emails": alu_alumni,
    "alu_si_emails": alu_si,
    "urls": urls,
    "phone_numbers": phones,
    "credit_cards": masked_cards
}

# -----------------------------
# Save JSON output
# -----------------------------

output_file = Path("output/sample-output.json")

with open(output_file, "w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

# -----------------------------
# Print results
# -----------------------------

print("Data extraction complete.")
print(json.dumps(results, indent=4))
