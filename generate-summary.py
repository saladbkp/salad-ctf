import os
import re
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

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


def generate_summary():
    all_rows = []

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
                all_rows.append((category, ctf_name, chal_name, chal_type, desc, date, solved))

    all_rows.sort(key=lambda r: r[5], reverse=True)

    with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
        f.write("| Category | CTF Name | Challenge Name | Type | Description | Date | Solved |\n")
        f.write("|----------|----------|----------------|------|-------------|------|--------|\n")
        for row in all_rows:
            f.write(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | {row[5]} | {row[6]} |\n")

    # Return full rows for later plotting
    print(f"[+] Summary updated with {len(all_rows)} total entries sorted by date.")
    return all_rows


def plot_summary(df):
    # Filter only solved challenges
    df_solved = df[df["Solved"] == "Yes"]

    if df_solved.empty:
        print("[-] No solved challenges. Skipping plots.")
        return

    df_solved["Month"] = pd.to_datetime(df_solved["Date"]).dt.to_period("M")

    # Challenges by Month
    month_count = df_solved.groupby("Month").size()
    plt.figure(figsize=(10, 5))
    month_count.plot(kind="bar", color='skyblue')
    plt.title("Number of Solved Challenges by Month")
    plt.ylabel("Count")
    plt.xlabel("Month")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("challenges_by_month.jpg")
    plt.close()

    # Challenges by Category
    cat_count = df_solved["Category"].value_counts()
    plt.figure(figsize=(10, 5))
    cat_count.plot(kind="bar", color='salmon')
    plt.title("Number of Solved Challenges by Category")
    plt.ylabel("Count")
    plt.xlabel("Category")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("challenges_by_category.jpg")
    plt.close()


def plot_techniques(tech_series, solved_series):
    all_techs = []
    for techs, solved in zip(tech_series, solved_series):
        if "Yes" in solved and isinstance(techs, str):
            # Convert string like "canary ROP" to list ["CANARY", "ROP"]
            split_techs = [t.strip().upper() for t in techs.split() if t.strip()]
            all_techs.extend(split_techs)

    if not all_techs:
        print("[-] No techniques found.")
        return

    tech_counts = Counter(all_techs)
    most_common = tech_counts.most_common(20)

    labels, values = zip(*most_common)

    plt.figure(figsize=(10, 8))
    plt.barh(labels, values, color='mediumseagreen')
    plt.title("Top Techniques Used in Solved CTF Challenges")
    plt.xlabel("Frequency")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig("challenge_techniques.jpg")
    plt.close()



def update_readme_with_images():
    with open(SUMMARY_FILE, "a", encoding="utf-8") as f:
        f.write("\n\n## 📊 Challenge Stats\n")
        f.write("### Challenges by Month\n")
        f.write("![Challenges by Month](challenges_by_month.jpg)\n\n")
        f.write("### Challenges by Category\n")
        f.write("![Challenges by Category](challenges_by_category.jpg)\n\n")
        f.write("### Challenge Techniques (Top 20)\n")
        f.write("![Challenge Techniques](challenge_techniques.jpg)\n")


if __name__ == "__main__":
    all_rows = generate_summary()

    # Convert to DataFrame
    df = pd.DataFrame(all_rows, columns=["Category", "CTF", "Challenge", "Type", "Description", "Date", "Solved"])

    plot_summary(df)
    plot_techniques(df["Type"],df["Solved"])
    update_readme_with_images()
    print("[+] Graphs generated and embedded into readme.md")
