from __future__ import annotations
import argparse, concurrent.futures, re, sys, threading
from urllib.parse import urlparse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


try:
    import requests
except Exception:
    sys.exit("Install requests: pip install requests")

try:
    import colorama
    colorama.init(autoreset=True)
    RED = colorama.Fore.RED + colorama.Style.BRIGHT
    GREEN = colorama.Fore.GREEN + colorama.Style.BRIGHT
    YELLOW = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    CYAN = colorama.Fore.CYAN + colorama.Style.BRIGHT
    MAGENTA = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
except Exception:
    sys.exit("Install colorama: pip install colorama")

VARS = ["apiKey","authDomain","projectId","storageBucket","messagingSenderId","appId","measurementId","databaseURL"]
# Запасной регэксп, если структура менее стандартна
VAR_REGEXES = {v: re.compile(rf'(?:["\']{re.escape(v)}["\']\s*:\s*|{re.escape(v)}\s*[:=]\s*)(["\'`])([^"\']+?)\1', re.IGNORECASE) for v in VARS}
FALLBACK_REGEX = re.compile(r'(?:"|\'|`)(apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId|measurementId|databaseURL)(?:"|\'|`)\s*[:=]?\s*(["\'`])([^"\']+?)\2', re.IGNORECASE)
FIREBASE_DOMAIN_INDICATORS = [r'.firebasedatabase.app', r'firebaseapp.com', r'firebaseio.com']
# По надобности добавляем свои заголовки
HEADERS = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}
PRINT_LOCK = threading.Lock()

def normalize_url(u: str):
    u = (u or "").strip()
    if not u: return None
    p = urlparse(u)
    return u if p.scheme in ("http","https") or p.scheme == "" else u

def fetch_url(url: str, timeout: int):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True, verify=True)
        return r.status_code, r.text
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True, verify=False)
            return r.status_code, r.text
        except Exception as e:
            return None, f"ERROR: {e}"
    except Exception as e:
        return None, f"ERROR: {e}"

def try_both_schemes(original_url: str, timeout: int):
    p = urlparse(original_url)
    if p.scheme in ("http","https"):
        candidates = [original_url] + (["https://" + p.netloc + p.path + (("?" + p.query) if p.query else "")] if p.scheme == "http" else [])
    else:
        candidates = ["https://" + original_url, "http://" + original_url]
    last_err = None
    for c in candidates:
        status, text = fetch_url(c, timeout)
        if status is None:
            last_err = text
            continue
        return c, status, text
    return None, None, last_err or f"All attempts failed for {original_url}"

def extract_vars(text: str):
# Выделяем переменные конфигурации из текста страницы
    found = {}
    lowered = text.lower()
    domain_found = any(ind.lower() in lowered for ind in FIREBASE_DOMAIN_INDICATORS)
    for var, rx in VAR_REGEXES.items():
        m = rx.search(text)
        if m: found[var] = m.group(2).strip()
    if len(found) < 2:
        for m in FALLBACK_REGEX.finditer(text):
            name, val = m.group(1), m.group(3)
            if name not in found: found[name] = val.strip()
    return found, domain_found

def inspect_url(original_url: str, timeout:int=10):
# извлечение переменных и принятие решения о детекте
    url_norm = normalize_url(original_url)
    if not url_norm:
        return {"url": original_url, "error": "invalid url", "detected": False, **{v: "-" for v in VARS}}
    tried_url, status, text = try_both_schemes(url_norm, timeout)
    if status is None:
        return {"url": original_url, "error": str(text), "detected": False, **{v: "-" for v in VARS}}
    found_vars, domain_flag = extract_vars(text)
    detected = domain_flag or (len(found_vars) >= 2)
    out = {v: found_vars.get(v, "-") for v in VARS}
    return {"url": tried_url or url_norm, "http_status": status, "detected": detected, **out}

def print_detected_pretty(e: dict):
    with PRINT_LOCK:
        print(f"{GREEN}== DETECTED =={RESET} {CYAN}{e.get('url')}{RESET}")
        print(f"{MAGENTA}Config:{RESET}")
        for v in VARS:
            val = e.get(v, "-") or "-"
            label = f"{v}:".ljust(20)
            print(f"  {label} {val if val != '-' else f'{YELLOW}-{RESET}'}")
        print("")

def print_not_detected(e: dict):
    with PRINT_LOCK:
        print(f"{YELLOW}- NOT detected: {e.get('url', '-')}{RESET}")

def save_output_file(path: str, results: list[dict]):
# Экспортируем только одно поле (удобно для дальнейшей автоматизации)
    lines = []
    for r in results:
        if not r.get("detected"): continue
        lines.append(r.get("url","-")); lines.append(""); lines.append("Config:")
        for v in VARS:
            lines.append(f"{v}: {r.get(v,'-') or '-'}")
        lines.append("")
    try:
        with open(path, "w", encoding="utf-8") as f: f.write("\n".join(lines))
        print(f"{GREEN}Saved detected entries to:{RESET} {path}")
    except Exception as e:
        print(f"{RED}Failed to write output file:{RESET} {e}")

def save_single_field(path: str, results: list[dict], field: str):
    values = [ (r.get(field) or "") for r in results if r.get("detected") and (r.get(field) or "-") != "-" ]
    try:
        with open(path, "w", encoding="utf-8") as f: f.write("\n".join(values))
        print(f"{GREEN}Saved {len(values)} values of '{field}' to:{RESET} {path}")
    except Exception as e:
        print(f"{RED}Failed to write {field} file:{RESET} {e}")

def process_list(file_path: str, workers:int=10, timeout:int=10, verbose:bool=False):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception as e:
        sys.exit(f"Failed to read file {file_path}: {e}")
    results = []; total = found = not_found = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(inspect_url, line, timeout): line for line in lines}
        for fut in concurrent.futures.as_completed(futures):
            line = futures[fut]; total += 1
            try:
                res = fut.result()
            except Exception as e:
                res = {"url": line, "error": f"exception: {e}", "detected": False, **{v: "-" for v in VARS}}
            results.append(res)
            if res.get("detected"):
                found += 1
                print_detected_pretty(res) if verbose else print(f"{GREEN}[FOUND]{RESET} {res.get('url')}")
            else:
                not_found += 1
                print_not_detected(res) if verbose else None
    return results, {"total": total, "found": found, "not_found": not_found}

print(f"""{CYAN}
***************     
*****************         Firebase Config Extractor
****       *******        Made by YmbMember
****  **************      For duty-free.cc forum
****  **************
****  ****      ****
****  ********* ****
****  ******** *****
****  ******* ***** 
****  ************* 
*****************   
***************     
{RESET}""")

def main():
    p = argparse.ArgumentParser(description="Firebase config detector (compact)")
    p.add_argument("file"); p.add_argument("-v","--verbose", action="store_true")
    p.add_argument("-o","--output"); p.add_argument("-oad"); p.add_argument("-osb"); p.add_argument("-odu")
    p.add_argument("--workers", type=int, default=10); p.add_argument("--timeout", type=int, default=10)
    args = p.parse_args()
    results, stats = process_list(args.file, workers=args.workers, timeout=args.timeout, verbose=args.verbose)
    if args.output: save_output_file(args.output, results)
    if args.oad: save_single_field(args.oad, results, "authDomain")
    if args.osb: save_single_field(args.osb, results, "storageBucket")
    if args.odu: save_single_field(args.odu, results, "databaseURL")
    print(""); print(f"{CYAN}=== STATISTICS ==={RESET}")
    print(f"Total processed: {stats['total']}")
    print(f"{GREEN}Configs found: {stats['found']}{RESET}")
    print(f"{YELLOW}Configs NOT found: {stats['not_found']}{RESET}")
    print("")

if __name__ == "__main__":
    main()
