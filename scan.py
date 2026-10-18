#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اسکنر سرور v2ray برای GitHub Actions.
  1) لینک‌ها را از sources.txt می‌گیرد
  2) فیلتر سریع TCP
  3) هر سرور را با Xray واقعی تست می‌کند (تاخیر + یوتیوب/اینستاگرام/تلگرام + جمینی)
  4) خروجی اشتراک (base64) در پوشه‌ی output می‌نویسد
"""
import base64, html, json, os, random, socket, subprocess, sys, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote

import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
XRAY = os.environ.get("XRAY_BIN", os.path.join(ROOT, "xray", "xray"))
OUT = os.path.join(ROOT, "output")

WORKERS = 40            # تست هم‌زمان با Xray
MAX_CONFIGS = 6000      # سقف کانفیگ در هر اجرا
TIME_BUDGET = 40 * 60   # ثانیه؛ بعد از این تست‌های جدید شروع نمی‌شه
TOP_MOBILE = 150        # تعداد لینک در لیست موبایل
TOP_GEMINI = 60         # تعداد لینک در لیست جمینی
PER_HOST = 3            # حداکثر لینک از هر آدرس:پورت (برای تنوع)
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
SITES = {"youtube": "https://www.youtube.com/generate_204",
         "instagram": "https://www.instagram.com/",
         "telegram": "https://web.telegram.org/"}
BAD_COUNTRIES = {"IR", "RU", "CN", "KP", "CU", "SY"}
BAD_MARKERS = ("currently supported in your country", "not available in your country",
               "isn't available in your", "not supported in your country", "stay tuned")


def log(*a):
    print(*a, flush=True)


# ------------------------------------------------------------ parsing
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def build_stream(net, security, p):
    net = (net or "tcp").lower()
    net = {"h2": "http", "splithttp": "xhttp"}.get(net, net)
    if net not in ("tcp", "ws", "grpc", "http", "httpupgrade", "xhttp"):
        raise ValueError("unsupported network " + net)
    host, path = p.get("host", ""), p.get("path", "") or "/"
    ss = {"network": net, "security": security or "none"}
    sni = p.get("sni") or host or p.get("_addr", "")
    if security == "tls":
        t = {"serverName": sni, "allowInsecure": True, "fingerprint": p.get("fp") or "chrome"}
        if p.get("alpn"):
            t["alpn"] = p["alpn"].split(",")
        ss["tlsSettings"] = t
    elif security == "reality":
        ss["realitySettings"] = {"serverName": sni, "fingerprint": p.get("fp") or "chrome",
                                 "publicKey": p.get("pbk", ""), "shortId": p.get("sid", ""),
                                 "spiderX": p.get("spx", "")}
    if net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("serviceName") or p.get("path", ""),
                              "multiMode": p.get("mode") == "multi"}
    elif net == "http":
        ss["httpSettings"] = {"path": path, "host": [h for h in host.split(",") if h]}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": host}
    elif net == "xhttp":
        ss["xhttpSettings"] = {"path": path, "host": host, "mode": p.get("mode", "auto")}
    elif net == "tcp" and p.get("headerType") == "http":
        ss["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path], "headers": {"Host": [h for h in host.split(",") if h]}}}}
    return ss


def parse_link(link):
    link = link.strip()
    try:
        if link.startswith("vmess://"):
            j = json.loads(b64d(link[8:]))
            host, port = j["add"], int(j["port"])
            sec = "tls" if j.get("tls") == "tls" else "none"
            p = {"host": j.get("host", ""), "path": j.get("path", ""), "sni": j.get("sni", ""),
                 "fp": j.get("fp", ""), "alpn": j.get("alpn", ""), "headerType": j.get("type", ""),
                 "_addr": host, "serviceName": j.get("path", "")}
            ob = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port,
                  "users": [{"id": j["id"], "alterId": int(j.get("aid", 0) or 0),
                             "security": j.get("scy") or "auto"}]}]},
                  "streamSettings": build_stream(j.get("net", "tcp"), sec, p)}
            return dict(host=host, port=port, key=f"vmess|{host}|{port}|{j['id']}",
                        outbound=ob, link=link)
        if link.startswith(("vless://", "trojan://")):
            u = urlparse(link)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            host, port = u.hostname, u.port
            if not host or not port:
                return None
            q["_addr"] = host
            sec = q.get("security") or ("tls" if u.scheme == "trojan" else "none")
            stream = build_stream(q.get("type", "tcp"), sec, q)
            ident = unquote(u.username or "")
            if u.scheme == "vless":
                ob = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port,
                      "users": [{"id": ident, "encryption": q.get("encryption", "none"),
                                 "flow": q.get("flow", "")}]}]}, "streamSettings": stream}
            else:
                ob = {"protocol": "trojan", "settings": {"servers": [{"address": host,
                      "port": port, "password": ident}]}, "streamSettings": stream}
            return dict(host=host, port=port, key=f"{u.scheme}|{host}|{port}|{ident}",
                        outbound=ob, link=link)
        if link.startswith("ss://"):
            body = link[5:].split("#")[0]
            if "plugin" in body:
                return None
            body = body.split("?")[0]
            if "@" in body:
                ui, hp = body.rsplit("@", 1)
                if ":" not in ui:
                    ui = b64d(ui)
            else:
                ui, hp = b64d(body).rsplit("@", 1)
            method, pw = ui.split(":", 1)
            host, port = hp.rsplit(":", 1)
            host, port = host.strip("[]"), int(port)
            ob = {"protocol": "shadowsocks", "settings": {"servers": [{
                "address": host, "port": port, "method": method, "password": pw}]}}
            return dict(host=host, port=port, key=f"ss|{host}|{port}|{pw}", outbound=ob, link=link)
    except Exception:
        return None
    return None


def parse_blob(text):
    text = text.strip()
    if text and "://" not in text[:200]:
        try:
            text = b64d(text)
        except Exception:
            pass
    out = []
    for line in text.replace("\r", "").split("\n"):
        if "://" in line:
            s = parse_link(line)
            if s:
                out.append(s)
    return out


def rename_link(link, name):
    """اسم سرور را در لینک عوض می‌کند تا توی برنامه‌ی گوشی خوانا باشه"""
    if link.startswith("vmess://"):
        j = json.loads(b64d(link[8:]))
        j["ps"] = name
        return "vmess://" + base64.b64encode(json.dumps(j).encode()).decode()
    from urllib.parse import quote
    return link.split("#")[0] + "#" + quote(name)


# --------------------------------------------------------------- xray
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_xray(outbound, port):
    ob = dict(outbound)
    ob["tag"] = "proxy"
    cfg = {"log": {"loglevel": "none"},
           "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
           "outbounds": [ob]}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    try:
        proc = subprocess.Popen([XRAY, "run", "-c", path], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        t0 = time.time()
        while time.time() - t0 < 5:
            if proc.poll() is not None:
                return None
            try:
                socket.create_connection(("127.0.0.1", port), 0.3).close()
                return proc
            except OSError:
                time.sleep(0.1)
        proc.kill()
        return None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def kill(proc):
    try:
        proc.kill()
        proc.wait(3)
    except Exception:
        pass


# -------------------------------------------------------------- tests
def session(port):
    s = requests.Session()
    s.trust_env = False
    s.proxies = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
    s.headers.update(UA)
    return s


def reach(s, url):
    try:
        return s.get(url, timeout=8, allow_redirects=False).status_code < 500
    except Exception:
        return False


def norm(t):
    t = html.unescape(t)
    for a, b in (("\\u2019", "'"), ("\\u0027", "'"), ("\\x27", "'"), ("\u2019", "'")):
        t = t.replace(a, b)
    return t.lower()


def exit_country(s):
    for url in ("http://ip-api.com/line/?fields=countryCode", "https://ipinfo.io/country",
                "https://api.country.is"):
        try:
            r = s.get(url, timeout=7)
            t = r.json().get("country", "") if url.endswith("country.is") else r.text.strip()
            if len(t) == 2 and t.isalpha():
                return t.upper()
        except Exception:
            pass
    return None


def gemini_ok(s, cc):
    if not cc or cc in BAD_COUNTRIES:
        return False
    try:
        r = s.get("https://generativelanguage.googleapis.com/v1beta/models?key=INVALID_TEST",
                  timeout=10)
        t = r.text.lower()
        if "location is not supported" in t or ("api_key_invalid" not in t and "api key not valid" not in t):
            return False
        for url in ("https://gemini.google.com/", "https://gemini.google.com/app"):
            r = s.get(url, timeout=12)
            if r.status_code != 200 or any(m in norm(r.text) for m in BAD_MARKERS):
                return False
            if "google.com" not in urlparse(r.url).netloc:
                return False
        return True
    except Exception:
        return False


def test(srv):
    port = free_port()
    proc = start_xray(srv["outbound"], port)
    if not proc:
        return None
    try:
        s = session(port)
        t0 = time.time()
        r = s.get("https://www.gstatic.com/generate_204", timeout=8)
        if r.status_code not in (200, 204):
            return None
        ping = int((time.time() - t0) * 1000)
        sites = {k: reach(s, u) for k, u in SITES.items()}
        if sum(sites.values()) < 2:                 # حالت نرم: حداقل ۲ از ۳ سایت
            return None
        cc = exit_country(s)
        gem = sites["youtube"] and gemini_ok(s, cc)
        return {"ping": ping, "sites": sites, "cc": cc or "??", "gemini": gem}
    except Exception:
        return None
    finally:
        kill(proc)


# --------------------------------------------------------------- main
def fetch(url):
    for _ in range(3):
        try:
            r = requests.get(url, timeout=40, headers=UA)
            r.raise_for_status()
            return r.text
        except Exception:
            time.sleep(2)
    return ""


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_sub(name, links):
    text = "\n".join(links)
    with open(os.path.join(OUT, name + "_plain.txt"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(OUT, name + ".txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode(text.encode()).decode())


def pick(results, n):
    out, per = [], {}
    for r in sorted(results, key=lambda x: x["ping"]):
        k = f'{r["host"]}:{r["port"]}'
        if per.get(k, 0) >= PER_HOST:
            continue
        per[k] = per.get(k, 0) + 1
        out.append(r)
        if len(out) >= n:
            break
    return out


def main():
    t_start = time.time()
    os.makedirs(OUT, exist_ok=True)
    known_file = os.path.join(OUT, "known_good.json")

    cands, seen = [], set()
    for l in load_json(known_file, []):               # اول سرورهای سالم دفعه‌ی قبل
        s = parse_link(l)
        if s and s["key"] not in seen:
            seen.add(s["key"]); cands.append(s)
    log(f"سرورهای قبلی: {len(cands)}")

    fresh = []
    with open(os.path.join(ROOT, "sources.txt"), encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip().startswith("http")]
    for u in urls:
        items = parse_blob(fetch(u))
        log(f"{len(items):5d} کانفیگ از {u}")
        for s in items:
            if s["key"] not in seen:
                seen.add(s["key"]); fresh.append(s)
    random.shuffle(fresh)
    cands += fresh[:max(0, MAX_CONFIGS - len(cands))]
    log(f"مجموع کاندید: {len(cands)}")

    def tcp_ok(s):
        try:
            socket.create_connection((s["host"], s["port"]), 3).close()
            return True
        except OSError:
            return False

    with ThreadPoolExecutor(300) as ex:
        flags = list(ex.map(tcp_ok, cands))
    alive = [s for s, ok in zip(cands, flags) if ok]
    log(f"بعد از فیلتر TCP: {len(alive)}")

    results, lock, done = [], threading.Lock(), [0]

    def work(s):
        if time.time() - t_start > TIME_BUDGET:
            return
        r = test(s)
        with lock:
            done[0] += 1
            if r:
                results.append({**r, "host": s["host"], "port": s["port"], "link": s["link"]})
            if done[0] % 100 == 0:
                log(f"تست‌شده {done[0]}/{len(alive)} | موفق: {len(results)}")

    with ThreadPoolExecutor(WORKERS) as ex:
        list(ex.map(work, alive))

    if not results:
        log("هیچ سروری پاس نشد؛ خروجی قبلی دست‌نخورده ماند.")
        return

    def named(rs):
        out = []
        for i, r in enumerate(rs, 1):
            tag = "G" if r["gemini"] else ""
            out.append(rename_link(r["link"], f'{r["cc"]} {r["ping"]}ms {tag} #{i}'.strip()))
        return out

    mobile = pick(results, TOP_MOBILE)
    gemini = pick([r for r in results if r["gemini"]], TOP_GEMINI)
    write_sub("mobile", named(mobile))
    write_sub("gemini", named(gemini))
    with open(known_file, "w", encoding="utf-8") as f:
        json.dump([r["link"] for r in pick(results, 300)], f)
    stats = {"updated_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
             "candidates": len(cands), "tcp_alive": len(alive), "passed": len(results),
             "mobile_list": len(mobile), "gemini_list": len(gemini),
             "seconds": int(time.time() - t_start)}
    with open(os.path.join(OUT, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    log("پایان:", stats)


if __name__ == "__main__":
    main()
