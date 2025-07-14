import os
import re
from datetime import datetime

BASE_FOLDER = "."
SUMMARY_FILE = os.path.join(BASE_FOLDER, "readme.md")

def extract_metadata(filepath):
    print(filepath)
    filename = os.path.basename(filepath)
    if not filename.endswith(".md"):
        return None

    # Extract title
    name = filename[:-3]  # strip .md
    parts = [p.strip() for p in name.split('--')]
    if len(parts) < 3:
        return None  # Skip badly formatted filenames
    category, challenge_name, challenge_type = parts[0], parts[1], parts[2]
    print(category, challenge_name, challenge_type)

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[-] Error reading {filepath}: {e}")
        return None
    
    # Extract description
    challenge_match = re.search(r'#\s*1\.0\s*Challenge\s*\n+(.*?)(\n#|$)', content, re.DOTALL)
    if challenge_match:
        desc_lines = challenge_match.group(1).strip().splitlines()
        desc_lines = [line.strip('- ').strip() for line in desc_lines if line.strip()]
        desc = '<br>'.join(desc_lines) if desc_lines else 'No description.'

    else:
        desc = 'No description.'

    # Determine solved status
    solved_match = re.search(r'#\s*4\.0\s*FLAG\s*\n+(.*?)(\n#|$)', content, re.DOTALL)
    solved = "✅ Yes" if solved_match and solved_match.group(1).strip() else "❌ No"

    # Get file modification date
    timestamp = os.path.getmtime(filepath)
    date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')

    return category, challenge_name, challenge_type, desc, date, solved

def generate_summary():
    rows = []
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
                rows.append((category, ctf_name, chal_name, chal_type, desc, date, solved))

    # Sort by date (latest first)
    rows.sort(key=lambda r: r[5], reverse=True)

    # Write to SUMMARY.md
    with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
        f.write("| Category | CTF Name | Challenge Name | Type | Description | Date | Solved |\n")
        f.write("|----------|----------|----------------|------|-------------|------|--------|\n")
        for row in rows:
            f.write(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | {row[5]} | {row[6]} |\n")

    print(f"[+] SUMMARY.md generated at: {SUMMARY_FILE}")

if __name__ == "__main__":
    generate_summary()
