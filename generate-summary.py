import os
import re
from datetime import datetime

BASE_FOLDER = "."
SUMMARY_FILE = os.path.join(BASE_FOLDER, "readme.md")

def extract_metadata(filepath):
    print(f"[+] Scanning: {filepath}")
    filename = os.path.basename(filepath)
    if not filename.endswith(".md"):
        return None

    # Extract title from filename: category--challenge_name--type.md
    name = filename[:-3]  # Remove .md
    parts = [p.strip() for p in name.split('--')]
    if len(parts) < 3:
        return None  # Skip if format is wrong

    category, challenge_name, challenge_type = parts[0], parts[1], parts[2]

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[-] Error reading {filepath}: {e}")
        return None

    # Extract challenge description (under # 1.0 Challenge)
    challenge_match = re.search(r'#\s*1\.0\s*Challenge\s*\n+(.*?)(\n#|$)', content, re.DOTALL)
    if challenge_match:
        desc_lines = challenge_match.group(1).strip().splitlines()
        desc_lines = [line.strip('- ').strip() for line in desc_lines if line.strip()]
        desc = '<br>'.join(desc_lines) if desc_lines else 'No description.'
    else:
        desc = 'No description.'

    # Determine solved status based on presence of FLAG
    solved_match = re.search(r'#\s*4\.0\s*FLAG\s*\n+(.*?)(\n#|$)', content, re.DOTALL)
    solved = "✅ Yes" if solved_match and solved_match.group(1).strip() else "❌ No"

    # Get file's last modified date
    timestamp = os.path.getmtime(filepath)
    date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')

    return category, challenge_name, challenge_type, desc, date, solved

def load_existing_entries():
    existing = set()
    if not os.path.exists(SUMMARY_FILE):
        return existing

    with open(SUMMARY_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines[2:]:  # Skip table headers
        parts = [p.strip() for p in line.strip().split('|')[1:-1]]
        if len(parts) >= 3:
            existing.add((parts[0], parts[1], parts[2]))  # (Category, CTF Name, Challenge Name)
    return existing

def generate_summary():
    existing_entries = load_existing_entries()
    new_rows = []

    for ctf_name in os.listdir(BASE_FOLDER):
        ctf_path = os.path.join(BASE_FOLDER, ctf_name)
        if not os.path.isdir(ctf_path) or ctf_name == "node_modules":
            continue

        for file in os.listdir(ctf_path):
            if not file.endswith(".md"):
                continue

            full_path = os.path.join(ctf_path, file)
            metadata = extract_metadata(full_path)
            if metadata:
                category, chal_name, chal_type, desc, date, solved = metadata
                key = (category, ctf_name, chal_name)
                if key not in existing_entries:
                    new_rows.append((category, ctf_name, chal_name, chal_type, desc, date, solved))
                    existing_entries.add(key)  # Prevent duplication in one run

    if not os.path.exists(SUMMARY_FILE):
        with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
            f.write("| Category | CTF Name | Challenge Name | Type | Description | Date | Solved |\n")
            f.write("|----------|----------|----------------|------|-------------|------|--------|\n")

    with open(SUMMARY_FILE, 'a', encoding='utf-8') as f:
        for row in sorted(new_rows, key=lambda r: r[5], reverse=True):
            f.write(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | {row[5]} | {row[6]} |\n")

    print(f"[+] {len(new_rows)} new entries added to {SUMMARY_FILE}")

if __name__ == "__main__":
    generate_summary()
