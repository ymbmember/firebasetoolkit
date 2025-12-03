from __future__ import annotations
import argparse, random, string, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Dict
import requests
import colorama

colorama.init(autoreset=True)
RED = colorama.Fore.RED + colorama.Style.BRIGHT
GREEN = colorama.Fore.GREEN + colorama.Style.BRIGHT
YELLOW = colorama.Fore.YELLOW + colorama.Style.BRIGHT
CYAN = colorama.Fore.CYAN + colorama.Style.BRIGHT
MAGENTA = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
RESET = colorama.Style.RESET_ALL

DEF_TIMEOUT = 10
DEF_WORKERS = 10

print(f"""{CYAN}
***************
*****************         Firebase Realtime checker
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

# Если нету протокола передачи - добавим
def norm(u: str) -> str:
    u = u.strip()
    if not u:
        return ""
    p = urlparse(u)
    if not p.scheme:
        u = "https://" + u
    return u.rstrip("/")

# Генератор случайных строк (надо для чека прав на чтение)
def rnd(n=7) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def chk_read(base: str, timeout: int) -> Dict:
    r = {"available": False, "reason": None, "details": {}, "content_length": None}
    try:
        resp = requests.get(base + "/.json", timeout=timeout, allow_redirects=True)
        r["details"]["initial_code"] = resp.status_code
        r["details"]["initial_text"] = resp.text
        r["content_length"] = len(resp.content) if resp.content else None
    except requests.Timeout:
        r["reason"] = f"timeout waiting for /.json ({timeout}s)"
        return r
    except requests.RequestException as e:
        r["reason"] = f"request error to /.json: {e}"
        return r

    sc = resp.status_code // 100
    txt = (resp.text or "").strip()

# Плохой статус код - рандомим для точной проверки
    if sc in (3, 4):
        token = rnd(7)
        try:
            r2 = requests.get(f"{base}/{token}.json", timeout=timeout, allow_redirects=True)
            r["details"]["random_code"] = r2.status_code
            r["details"]["random_text"] = r2.text
        except requests.Timeout:
            r["reason"] = f"timeout waiting for random endpoint ({timeout}s)"
            return r
        except requests.RequestException as e:
            r["reason"] = f"request error to random endpoint {token}: {e}"
            return r

        sc2 = r2.status_code // 100
        if sc2 in (3, 4):
            r["reason"] = f"initial {resp.status_code} and random {r2.status_code} => unreadable"
            return r
        if txt == "null" or r2.text.strip() == "null":
            r["available"] = True
            r["reason"] = 'responded "null"'
            return r

        r["available"] = True
        r["reason"] = f"random returned {r2.status_code}"
        return r

    if txt == "null":
        r["available"] = True
        r["reason"] = '/.json = "null"'
        return r

    r["available"] = True
    r["reason"] = f"/.json returned {resp.status_code}"
    return r

# Проверка можно ли записывать
def chk_write(base: str, timeout: int) -> Dict:
    r = {"available": False, "reason": None, "details": {}}
    key = "pchk_" + rnd(8)

    try:
        resp = requests.put(f"{base}/{key}.json", json={"_pentest_check": key}, timeout=timeout)
        r["details"]["put_code"] = resp.status_code
    except requests.Timeout:
        r["reason"] = f"timeout during PUT ({timeout}s)"
        return r
    except requests.RequestException as e:
        r["reason"] = f"PUT error: {e}"
        return r

    if 200 <= resp.status_code < 300:
        r["available"] = True
        r["reason"] = f"PUT returned {resp.status_code}"
        try:
            d = requests.delete(f"{base}/{key}.json", timeout=timeout)
            r["details"]["delete_code"] = d.status_code
        except requests.RequestException as e:
            r["details"]["delete_error"] = str(e)
        return r

    r["reason"] = f"PUT returned {resp.status_code}"
    return r

def is_err(d: Dict) -> bool:
    if not isinstance(d, dict):
        return False
    r = (d.get("reason") or "").lower()
    if any(k in r for k in ("timeout", "request error", "put error", "exception")):
        return True
    codes = [v for k, v in (d.get("details") or {}).items() if k.endswith("_code")]
    return codes and all(c is None for c in codes)

def colored_bool(v: bool) -> str:
    return GREEN + "true" + RESET if v else RED + "false" + RESET

def colored_skip() -> str:
    return YELLOW + "skipped" + RESET

def output(o: Dict, verbose: bool) -> None:
    url = o["target"]
    r = o["read"]
    w = o["write"]

    print(f"[URL] {url}")

    if is_err(r):
        print(f"Read  - {RED}false{RESET}    {YELLOW}Error. Use -v for more info{RESET}")
        if verbose:
            print("   Reason:", r.get("reason"))
    else:
        a = r.get("available", False)
        print(f"Read  - {colored_bool(a)}")
        if a and r.get("content_length") is not None:
            print(f"  {MAGENTA}[+] Content Length: {r['content_length']}{RESET}")
        if verbose and r.get("reason"):
            print("   Reason:", r["reason"])

    if w.get("skipped"):
        print(f"Write - {colored_skip()}    (use --write to enable)")
        return

    if is_err(w):
        print(f"Write - {RED}false{RESET}    {YELLOW}Error. Use -v for more info{RESET}")
        if verbose:
            print("   Reason:", w.get("reason"))
    else:
        print(f"Write - {colored_bool(w.get('available', False))}")
        if verbose and w.get("reason"):
            print("   Reason:", w["reason"])

def process(url: str, do_write: bool, timeout: int) -> Dict:
    url = norm(url)
    if not url:
        return {"target": url, "error": "empty"}

    try:
        r = chk_read(url, timeout)
    except Exception as e:
        r = {"available": False, "reason": f"exception during read: {e}", "details": {}}

    if do_write:
        try:
            w = chk_write(url, timeout)
        except Exception as e:
            w = {"available": False, "reason": f"exception during write: {e}", "details": {}}
    else:
        w = {"skipped": True, "reason": "write disabled"}

    return {"target": url, "read": r, "write": w}

def main():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url")
    g.add_argument("-l", "--list")
    p.add_argument("--write", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-w", "--workers", type=int, default=DEF_WORKERS)
    p.add_argument("--timeout", type=int, default=DEF_TIMEOUT)
    p.add_argument("-or", "--out-read")
    p.add_argument("-ow", "--out-write")
    args = p.parse_args()

    if args.url:
        targets = [args.url.strip()]
    else:
        targets = [l.strip() for l in open(args.list, encoding="utf-8") if l.strip()]

    read_ok = []
    write_ok = []
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(process, t, args.write, args.timeout): t for t in targets}

        for fut in as_completed(futs):
            t = futs[fut]
            print("=" * 60)
            try:
                out = fut.result()
            except Exception as e:
                print(f"[URL] {t}\n  ERROR: {e}")
                continue

            if out.get("error"):
                print(f"[URL] {t}\n  ERROR: {out['error']}")
                continue

            output(out, args.verbose)

            if out["read"].get("available"):
                read_ok.append(t)
            if out["write"].get("available"):
                write_ok.append(t)

            results.append(out)

    if args.out_read:
        with open(args.out_read, "w", encoding="utf-8") as f:
            f.write("\n".join(read_ok))
        print(f"Wrote {len(read_ok)} readable URLs to {args.out_read}")

    if args.out_write:
        with open(args.out_write, "w", encoding="utf-8") as f:
            f.write("\n".join(write_ok))
        print(f"Wrote {len(write_ok)} writable URLs to {args.out_write}")

    print("\n=== Statistics ===")
    print("Total tested:", len(results))
    print("Readable:", len(read_ok))
    print("Writable:", len(write_ok))

if __name__ == "__main__":
    main()
