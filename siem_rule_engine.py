import re
import pandas as pd

# ==============================
# Stage 1: Parse Logs → Excel
# ==============================

def parse_log_line(line):
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\]\s+"(GET|POST)\s+(.*?)\s+HTTP.*?"\s+(\d{3})'
    match = re.search(pattern, line)

    if match:
        raw_time = match.group(2)

        # ✅ REMOVE TIMEZONE (e.g., +0530 or +0000)
        raw_time = re.sub(r"\s[+-]\d{4}", "", raw_time)

        # ✅ HANDLE BOTH FORMATS
        if " " in raw_time:
            parts = raw_time.split(" ")
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else ""
        else:
            date_part, time_part = raw_time.split(":", 1)

        return {
            "IP": match.group(1),
            "Date": date_part,
            "Time": time_part,
            "Method": match.group(3),
            "URL": match.group(4),
            "Status Code": match.group(5)
        }
    return None


def txt_to_excel(input_file, output_excel):
    logs = []

    with open(input_file, "r", encoding="utf-8") as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                logs.append(parsed)

    df = pd.DataFrame(logs)

    if df.empty:
        print("⚠️ No valid logs found!")
    else:
        df.to_excel(output_excel, index=False)
        print(f"✅ Logs converted to Excel → {output_excel}")


# ==============================
# Stage 2: Attack Detection
# ==============================

def detect_sqli(url):
    return bool(re.search(r"(?i)(\bor\b|\band\b).*(=|like)|('|--|#|;|\bunion\b)", str(url)))


def detect_xss(url):
    return bool(re.search(r"(?i)(<script>|</script>|alert\(|onerror=|onload=)", str(url)))


def detect_lfi(url):
    return bool(re.search(r"(?i)(/etc/passwd|/etc/shadow|php://filter|proc/self)", str(url)))


def detect_rfi(url):
    return bool(re.search(r"(?i)(http://|https://)", str(url)))


def detect_traversal(url):
    return bool(re.search(r"(\.\./|\.\.\\|%2e%2e%2f)", str(url)))


def detect_dos_time_based(df, window_seconds=5, threshold=20):
    dos_ips = set()

    for ip, group in df.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_start = times.iloc[i]
            window_end = window_start + pd.Timedelta(seconds=window_seconds)

            count = ((times >= window_start) & (times <= window_end)).sum()

            if count >= threshold:
                dos_ips.add(ip)
                break

    return dos_ips


def detect_bruteforce_time_based(df, window_seconds=10, threshold=5):
    bf_ips = set()

    failed = df[df["Status Code"].astype(str).isin(["401", "403"])]

    for ip, group in failed.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_start = times.iloc[i]
            window_end = window_start + pd.Timedelta(seconds=window_seconds)

            count = ((times >= window_start) & (times <= window_end)).sum()

            if count >= threshold:
                bf_ips.add(ip)
                break

    return bf_ips


def detect_attack(url):
    if detect_sqli(url):
        return "SQL Injection"
    elif detect_xss(url):
        return "XSS"
    elif detect_lfi(url):
        return "LFI"
    elif detect_rfi(url):
        return "RFI"
    elif detect_traversal(url):
        return "Directory Traversal"
    else:
        return "Normal"


def analyze_excel(input_excel, output_excel):
    try:
        df = pd.read_excel(input_excel)
    except Exception as e:
        print("❌ Error reading Excel:", e)
        return

    if df.empty:
        print("⚠️ Excel file is empty!")
        return

    # ==============================
    # CREATE CLEAN TIMESTAMP
    # ==============================
    df["Timestamp"] = pd.to_datetime(
        df["Date"].astype(str) + " " + df["Time"].astype(str),
        format="%d/%b/%Y %H:%M:%S",
        errors="coerce"
    )

    df = df.sort_values(by=["IP", "Timestamp"])

    # ==============================
    # BASE ATTACK DETECTION
    # ==============================
    df["Attack"] = df["URL"].apply(detect_attack)

    # ==============================
    # DoS + Brute Force Detection
    # ==============================
    dos_ips = detect_dos_time_based(df)
    bf_ips = detect_bruteforce_time_based(df)

    # ✅ FIX: Do NOT overwrite existing attacks
    df.loc[
        (df["IP"].isin(dos_ips)) & (df["Attack"] == "Normal"),
        "Attack"
    ] = "DoS"

    df.loc[
        (df["IP"].isin(bf_ips)) & (df["Attack"] == "Normal"),
        "Attack"
    ] = "Brute Force"

    # ==============================
    # FILTER ONLY THREATS
    # ==============================
    threats_df = df[df["Attack"] != "Normal"]

    if threats_df.empty:
        empty_df = pd.DataFrame(columns=["IP", "Attack", "Attack Count"])
        empty_df.to_excel(output_excel, index=False)
        print("✅ No attacks detected. Empty report generated.")
        return

    # ==============================
    # GROUPING
    # ==============================
    summary_df = (
        threats_df
        .groupby(["IP", "Attack"])
        .size()
        .reset_index(name="Attack Count")
    )

    summary_df.to_excel(output_excel, index=False)

    print(f"⚠️ Threat summary saved → {output_excel}")


# ==============================
# MAIN DRIVER
# ==============================

if __name__ == "__main__":

    input_txt = "rfi_logs.txt"
    raw_excel = "raw_logs.xlsx"
    threat_excel = "threat_logs.xlsx"

    txt_to_excel(input_txt, raw_excel)
    analyze_excel(raw_excel, threat_excel)

    print("🚀 Full pipeline executed successfully!")