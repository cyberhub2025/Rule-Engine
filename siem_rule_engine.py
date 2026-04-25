import re
import pandas as pd
from urllib.parse import unquote

# ==============================
# FULL DECODE
# ==============================
def fully_decode(url):
    prev = ""
    url = str(url)
    while prev != url:
        prev = url
        url = unquote(url)
    return url


# ==============================
# PARSE LOGS
# ==============================
def parse_log_line(line):
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\]\s+"?(GET|POST)\s+(.*?)\s+HTTP.*?"?\s+(\d{3})'
    match = re.search(pattern, line)

    if match:
        raw_time = match.group(2)
        raw_time = re.sub(r"\s[+-]\d{4}", "", raw_time)

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
    encodings = ['cp1252', 'utf-16', 'utf-8']
    file_opened = False
    for enc in encodings:
        try:
            with open(input_file, "r", encoding=enc) as file:
                for line in file:
                    parsed = parse_log_line(line)
                    if parsed:
                        logs.append(parsed)
            file_opened = True
            break
        except UnicodeDecodeError:
            continue
    if not file_opened:
        # Last resort with errors='replace'
        with open(input_file, "r", encoding='utf-8', errors='replace') as file:
            for line in file:
                parsed = parse_log_line(line)
                if parsed:
                    logs.append(parsed)

    df = pd.DataFrame(logs)

    if df.empty:
        print("⚠️ No valid logs found!")
    else:
        df.to_excel(output_excel, index=False)
        print(f"✅ Logs converted → {output_excel}")


# ==============================
# ATTACK DETECTION
# ==============================

def detect_sqli(url):
    url = fully_decode(url).lower()

    patterns = [
        r"(\bor\b|\band\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
        r"['\"]\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"union\s+select",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"information_schema",
        r"--",
        r"or\s*1\s*=\s*1",
    ]

    return any(re.search(p, url) for p in patterns)


def detect_xss_advanced(url):
    raw = fully_decode(url).lower()
    attacks = []
    flag = True

    if flag:

        # Session hijacking (storage-based)
        if re.search(r"(localstorage|sessionstorage|json\s*\.\s*stringify)", raw):
            attacks.append("Session Hijacking")
            flag = False
        
        # 🍪 Cookie stealing (separate detection)
        elif re.search(r"document\s*\.\s*cookie", raw):
            attacks.append("Cookie Stealing")
            flag = False

        # Keylogging
        elif re.search(r"(onkey(down|press|up)|addEventListener\s*\(\s*['\"]key)", raw):
            attacks.append("Keylogging")
            flag = False

        # Data exfiltration
        elif re.search(r"(fetch\s*\()", raw):
            attacks.append("Data Exfiltration")
            flag = False

        # Credential harvesting
        elif re.search(r"type\s*=\s*['\"]?\s*password", raw):
            attacks.append("Credential Harvesting")
            flag = False

    if flag:
        if re.search(r"(window\s*\.\s*location|location\s*\.\s*href)", raw):
            attacks.append("XSS")

        elif re.search(r"<script[^>]*>\s*alert\s*\(", raw):
            attacks.append("XSS")

        elif "<script" in raw:
            attacks.append("XSS")

    return attacks if attacks else None


def detect_lfi(url):
    url = fully_decode(url).lower()
    return bool(re.search(r"(/etc/passwd|/etc/shadow|php://filter|proc/self)", url))


def detect_rfi(url):
    url = fully_decode(url).lower()

    # RFI only when external URL is used as parameter value
    return bool(re.search(
        r"(file|page|include|path|template)\s*=\s*https?://",
        url
    ))


def detect_traversal(url):
    url = fully_decode(url).lower()
    return bool(re.search(r"(\.\./|\.\.\\|%2e%2e%2f)", url))


def detect_attack(url):
    attacks = []

    if detect_sqli(url):
        attacks.append("SQL Injection")

    xss = detect_xss_advanced(url)
    if xss:
        attacks.extend(xss)

    if detect_lfi(url):
        attacks.append("LFI")

    if detect_rfi(url):
        attacks.append("RFI")

    if detect_traversal(url):
        attacks.append("Directory Traversal")

    return attacks if attacks else None


# ==============================
# BEHAVIOR DETECTION
# ==============================

def detect_dos_time_based(df, window_seconds=5, threshold=20):
    dos_ips = set()

    for ip, group in df.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=window_seconds)
            count = ((times >= times.iloc[i]) & (times <= window_end)).sum()

            if count >= threshold:
                dos_ips.add(ip)
                break

    return dos_ips


def detect_bruteforce_time_based(df, window_seconds=10, threshold=5):
    bf_ips = set()

    login_attempts = df[
        (df["URL"].str.contains("login", case=False, na=False)) &
        (df["Status Code"].astype(str) == "401")
    ]

    for ip, group in login_attempts.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=window_seconds)
            count = ((times >= times.iloc[i]) & (times <= window_end)).sum()

            if count >= threshold:
                bf_ips.add(ip)
                break

    return bf_ips


# ==============================
# MAIN ANALYSIS
# ==============================

def analyze_excel(input_excel, output_excel):

    df = pd.read_excel(input_excel)

    df["Timestamp"] = pd.to_datetime(
        df["Date"].astype(str) + " " + df["Time"].astype(str),
        format="%d/%b/%Y %H:%M:%S",
        errors="coerce"
    )

    df = df.sort_values(by=["IP", "Timestamp"])

    # 🔥 MULTI ATTACK DETECTION
    df["Attack"] = df["URL"].apply(detect_attack)

    # Flatten multiple attacks
    df = df.explode("Attack")

    # ------------------------------
    # DoS ROW-LEVEL DETECTION
    # ------------------------------
    df["DoS_Flag"] = False

    for (ip, url), group in df.groupby(["IP", "URL"]):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=2)
            mask = (times >= times.iloc[i]) & (times <= window_end)

            if mask.sum() >= 30:
                df.loc[group.index[mask], "DoS_Flag"] = True

    # ------------------------------
    # BRUTE FORCE ROW-LEVEL DETECTION
    # ------------------------------
    df["BF_Flag"] = False

    login_df = df[
        (df["URL"].str.contains("login", case=False, na=False)) &
        (df["Status Code"].astype(str) == "401")
    ]

    for ip, group in login_df.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=10)
            mask = (times >= times.iloc[i]) & (times <= window_end)

            if mask.sum() >= 5:
                df.loc[group.index[mask], "BF_Flag"] = True

    # APPLY LABELS
    df.loc[df["DoS_Flag"], "Attack"] = "DoS"
    df.loc[df["BF_Flag"], "Attack"] = "Brute Force"

    # ------------------------------
    # ALERT GENERATION (FINAL FIX)
    # ------------------------------
    alerts = []

    # -------- DoS WINDOW --------
    dos_df = df[df["DoS_Flag"]]

    for (ip, url), group in dos_df.groupby(["IP", "URL"]):
        times = group["Timestamp"].sort_values().tolist()

        i = 0
        while i < len(times):
            start = times[i]
            window_end = start + pd.Timedelta(seconds=2)

            count = 0
            j = i

            while j < len(times) and times[j] <= window_end:
                count += 1
                j += 1

            if count >= 30:
                alerts.append({
                    "IP": ip,
                    "Attack": "DoS",
                    "Start Time": start,
                    "End Time": times[j-1],
                    "Attack Count": count
                })

            i = j

    # -------- BRUTE FORCE WINDOW --------
    bf_df = df[df["BF_Flag"]]

    for ip, group in bf_df.groupby("IP"):
        times = group["Timestamp"].sort_values().tolist()

        i = 0
        while i < len(times):
            start = times[i]
            window_end = start + pd.Timedelta(seconds=10)

            count = 0
            j = i

            while j < len(times) and times[j] <= window_end:
                count += 1
                j += 1

            if count >= 5:
                alerts.append({
                    "IP": ip,
                    "Attack": "Brute Force",
                    "Start Time": start,
                    "End Time": times[j-1],
                    "Attack Count": count
                })

            i = j

    # -------- OTHER ATTACKS --------
    other_df = df[
        (~df["DoS_Flag"]) &
        (~df["BF_Flag"]) &
        (df["Attack"].notna())
    ]

    for (ip, attack), group in other_df.groupby(["IP", "Attack"]):
        times = group["Timestamp"].sort_values()

        alerts.append({
            "IP": ip,
            "Attack": attack,
            "Start Time": times.iloc[0],
            "End Time": times.iloc[-1],
            "Attack Count": len(times)
        })

    # FINAL OUTPUT
    summary_df = pd.DataFrame(alerts)

    summary_df.to_excel(output_excel, index=False)

    print(f"⚠️ Threat summary saved → {output_excel}")


# ==============================
# MAIN DRIVER
# ==============================

if __name__ == "__main__":

    input_txt = "directorynew.txt"
    raw_excel = "raw_logs.xlsx"
    threat_excel = "threat_logs.xlsx"

    txt_to_excel(input_txt, raw_excel)
    analyze_excel(raw_excel, threat_excel)

    print("🚀 Done!")