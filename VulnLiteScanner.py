
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnLite Scanner — Fancy Final (SPACED + Extended Tools)
- Big margins & padding, generous spacing (readable PDF)
- Deep Scan option: whois, whatweb, subfinder, wafw00f, a2sv, dnsenum,
  sqlmap, wpscan, goofile, ffuf, photon, hakrawler, plus nmap/nikto.
- Auto-detects tools; simulates if missing.
- Single-file, no external Python deps.
"""
import os, re, sys, ssl, json, time, socket, queue, shutil, threading, subprocess, argparse, tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen

HAS_TK, TK_ERROR = True, ""
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception as e:
    HAS_TK, TK_ERROR = False, str(e)

APP_NAME = "VulnLite Scanner"
APP_VER  = "v2.6-spaced-ext"
HTTP_UA  = "VulnLiteScanner/2.6 (+https://example.local)"
TIMEOUT  = 5.0
DEFAULT_PORTS = [21,22,25,53,80,110,139,143,443,445,587,8080,8443,3306,5432,6379,27017]
SUBDOMAIN_WORDS = ["www","mail","dev","test","api","stage","staging","admin","cdn","shop","blog","portal"]

EXTERNAL_TOOLS = ["whois","whatweb","subfinder","wafw00f","a2sv","dnsenum","sqlmap","wpscan","goofile","ffuf","photon","hakrawler","nmap","nikto"]

VULN_DB = [
    {"pattern": r"Apache/2\.4\.49", "cve": "CVE-2021-41773", "desc": "Path traversal & RCE (specific configs)"},
    {"pattern": r"Apache/2\.4\.50", "cve": "CVE-2021-42013", "desc": "Path traversal & RCE (specific configs)"},
    {"pattern": r"nginx/1\.18\.0", "cve": "CVE-2021-23017", "desc": "Resolver off-by-one (rare default impact)"},
    {"pattern": r"OpenSSH[_/ ]7\.2", "cve": "CVE-2016-0777", "desc": "Roaming info leak (client-side)"},
    {"pattern": r"PHP/5\.", "cve": "Multiple", "desc": "PHP 5 is EoL with numerous vulns"},
    {"pattern": r"X-Powered-By: PHP/5\.", "cve": "Multiple", "desc": "EoL PHP 5 exposed via header"},
    {"pattern": r"Microsoft-IIS/6\.0", "cve": "CVE-2017-7269", "desc": "WebDAV exploit (legacy IIS 6)"},
    {"pattern": r"OpenSSL/1\.0\.1", "cve": "CVE-2014-0160", "desc": "Heartbleed (if vulnerable build)"},
]

# ===== Utilities =====
def safe_parse_host(target: str) -> str:
    if "://" in target:
        try: return urlparse(target).netloc.split(":")[0]
        except Exception: return target.strip().split("/")[0]
    return target.strip().split("/")[0]

def resolve_host(host: str):
    try: return socket.gethostbyname(host)
    except Exception: return None

def http_fetch(host: str, use_https=True):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}/"
    try:
        req = Request(url, headers={"User-Agent": HTTP_UA})
        with urlopen(req, timeout=TIMEOUT, context=ctx if use_https else None) as resp:
            headers = dict(resp.getheaders())
            body = resp.read(120000).decode("utf-8", errors="replace")
            return {"url": url, "code": resp.getcode(), "headers": headers, "body": body}
    except Exception as e:
        return {"url": url, "error": str(e)}

def small_port_scan(ip: str, ports):
    results = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5); start = time.time()
        try:
            res = s.connect_ex((ip, p)); latency = int((time.time()-start)*1000)
            if res == 0:
                banner = ""
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n"); sneak = s.recv(256)
                    banner = sneak.decode("latin-1", errors="replace").strip()
                except Exception: pass
                results.append({"port":p,"state":"open","latency_ms":latency,"banner":banner})
            else:
                results.append({"port":p,"state":"closed","latency_ms":latency,"banner":""})
        except Exception as e:
            results.append({"port":p,"state":"error","latency_ms":0,"banner":str(e)})
        finally:
            try: s.close()
            except: pass
    return results

def brute_subdomains(domain: str, limit=20):
    found = []
    for sub in SUBDOMAIN_WORDS[:limit]:
        fqdn = f"{sub}.{domain}"
        try: found.append({"host": fqdn, "ip": socket.gethostbyname(fqdn)})
        except Exception: pass
    return found

def detect_tools():
    return {t: shutil.which(t) is not None for t in EXTERNAL_TOOLS}

def run_cmd(cmd, timeout_sec=30, shell=False):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout_sec, shell=shell)
        return out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[error running {cmd!r}: {e}]"

# ===== Fancy PDF writer (SPACED, readable) =====
class FancyPDF:
    def __init__(self, title=APP_NAME):
        self.title = title
        self.objects=[]; self.page_objs=[]; self.streams=[]
        self.page_w, self.page_h = 595, 842  # A4
        self.margin = 72          # 1 inch margins
        self.pad_x = 20           # padding
        self.pad_y = 16
        self.line_gap = 8
        self.section_gap = 18
        self.block_gap = 18
        self.body_size = 11
        self.header_size = 12
        self.cursor_y = self.page_h - 140
        self.font_obj_num = self._add_obj(b"<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Helvetica >>")
        self._new_page()

    def _add_obj(self, data: bytes) -> int:
        self.objects.append(data); return len(self.objects)

    def _new_page(self):
        self.cursor_y = self.page_h - 140
        self.streams.append(bytearray())
        content_num = self._add_obj(b"<< /Length 0 >>")
        page_obj = f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 {self.page_w} {self.page_h}] /Contents {content_num} 0 R /Resources << /Font << /F1 {self.font_obj_num} 0 R >> >> >>"
        self.page_objs.append(self._add_obj(page_obj.encode("latin-1")))

    def _s(self, txt: str): self.streams[-1].extend((txt+"\n").encode("latin-1"))
    def set_fill_rgb(self, r,g,b): self._s(f"{r} {g} {b} rg")
    def rect(self, x,y,w,h, fill=True): self._s(f"{x} {y} {w} {h} re {'f' if fill else 'S'}")

    @staticmethod
    def _ascii(s: str) -> str:
        repl = {"•":"*", "→":"->", "—":"-", "–":"-", "…":"...", "’":"'", "✓":"v", "✔":"v", "✗":"x"}
        for k,v in repl.items(): s = s.replace(k,v)
        return s

    def text(self, x,y, txt, size=None, r=None,g=None,b=None):
        if r is not None: self.set_fill_rgb(r,g,b)
        txt = self._ascii(txt)
        safe = txt.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        size = size or self.body_size
        self._s("BT /F1 %d Tf %d %d Td (%s) Tj ET" % (size, x, y, safe))

    def page_header(self):
        self.set_fill_rgb(0.12,0.16,0.22); self.rect(0, self.page_h-120, self.page_w, 120, True)
        self.text(self.margin, self.page_h-70, f"{APP_NAME}", size=26, r=1,g=1,b=1)
        self.text(self.margin, self.page_h-95, f"Fancy Report  {APP_VER}", size=13, r=0.85,g=0.92,b=1)
        self.cursor_y = self.page_h - 150

    def h1(self, label):
        self.text(self.margin, self.cursor_y, label, size=20, r=0.06,g=0.23,b=0.36)
        self.cursor_y -= (20 + self.section_gap)

    def section_header(self, title):
        x = self.margin; w = self.page_w - 2*self.margin
        bar_y = self.cursor_y - (self.pad_y + 8)
        bar_h = (2*self.pad_y) + 18
        self.set_fill_rgb(0.93,0.96,1.0); self.rect(x, bar_y, w, bar_h, True)
        self.text(x + self.pad_x, self.cursor_y, title, size=self.header_size, r=0.1,g=0.2,b=0.35)
        self.cursor_y = bar_y - self.section_gap

    def _wrap_lines(self, text, size=None, max_width=None):
        size = size or self.body_size
        if max_width is None:
            usable = self.page_w - 2*self.margin - self.pad_x*1.5
            max_chars = int(usable / (0.55*size))
        else:
            max_chars = max_width
        max_chars = max(60, min(max_chars, 120))
        lines = []
        for raw_line in text.split("\n"):
            s = self._ascii(raw_line)
            while len(s) > max_chars:
                cut = s.rfind(" ", 0, max_chars)
                if cut == -1: cut = max_chars
                lines.append(s[:cut])
                s = s[cut:].lstrip()
            lines.append(s)
        return lines

    def paragraph(self, text, size=None, indent=0):
        size = size or self.body_size
        x = self.margin + indent
        for line in self._wrap_lines(text, size=size):
            self.text(x, self.cursor_y, line, size=size)
            self.cursor_y -= (size + self.line_gap)

    def bullet(self, s, size=None): self.paragraph(f"* {s}", size=size)

    def ensure(self, need=160):
        if self.cursor_y - need < 60:
            self._new_page(); self.page_header()

    def save(self, path):
        xref=[]; out=bytearray(); out.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        for idx, page_obj_num in enumerate(self.page_objs):
            stream_bytes = bytes(self.streams[idx])
            content_obj_num = int(re.search(rb"/Contents (\d+) 0 R", self.objects[page_obj_num-1]).group(1))
            stream_obj = b"<< /Length %d >>\nstream\n" % len(stream_bytes) + stream_bytes + b"\nendstream"
            self.objects[content_obj_num-1] = stream_obj
        kids_refs = " ".join(f"{n} 0 R" for n in self.page_objs)
        pages_obj = f"<< /Type /Pages /Kids [{kids_refs}] /Count {len(self.page_objs)} >>".encode("latin-1")
        pages_obj_num = self._add_obj(pages_obj)
        for page_obj_num in self.page_objs:
            self.objects[page_obj_num-1] = self.objects[page_obj_num-1].replace(b"/Parent 0 0 R", f"/Parent {pages_obj_num} 0 R".encode("latin-1"))
        catalog_obj = f"<< /Type /Catalog /Pages {pages_obj_num} 0 R >>".encode("latin-1")
        catalog_num = self._add_obj(catalog_obj)
        creation = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%SZ')
        info_obj = f"<< /Producer (VulnLite FancyPDF) /Title ({self.title}) /CreationDate (D:{creation}) >>".encode("latin-1")
        info_num = self._add_obj(info_obj)
        for i, obj in enumerate(self.objects, start=1):
            xref.append(len(out)); out.extend(f"{i} 0 obj\n".encode("ascii")); out.extend(obj); out.extend(b"\nendobj\n")
        startxref = len(out)
        out.extend(b"xref\n"); out.extend(f"0 {len(self.objects)+1}\n".encode("ascii")); out.extend(b"0000000000 65535 f \n")
        for pos in xref: out.extend(f"{pos:010} 00000 n \n".encode("ascii"))
        out.extend(b"trailer\n"); out.extend(f"<< /Size {len(self.objects)+1} /Root {catalog_num} 0 R /Info {info_num} 0 R >>\n".encode("ascii"))
        out.extend(b"startxref\n"); out.extend(f"{startxref}\n".encode("ascii")); out.extend(b"%%EOF")
        with open(path, "wb") as f: f.write(out)

# ===== Report using SPACED layout =====
def export_stylish_pdf(path, res):
    meta=res.get("meta",{}); dns=res.get("dns",{}); http=res.get("http",{})
    subs=res.get("subdomains",[]); ports=res.get("ports",[]); ex=res.get("exploits",[]); tools=res.get("tools",{})
    open_ports=sum(1 for p in ports if p.get("state")=="open")
    sev_count={"high":0,"medium":0,"info":0}
    for e in ex: sev_count[e.get("severity","info")] = sev_count.get(e.get("severity","info"),0)+1

    pdf=FancyPDF(title=f"{APP_NAME} Report")
    pdf.page_header()
    pdf.h1("Scan Summary")
    pdf.section_header("Overview")
    pdf.paragraph(f"Target: {meta.get('target','')}")
    pdf.paragraph(f"Mode: {'SIMULATE' if meta.get('simulate') else 'LIVE'}")
    pdf.paragraph(f"Timestamp (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}")
    pdf.cursor_y -= pdf.block_gap
    pdf.section_header("Key Stats")
    pdf.paragraph(f"Open Ports: {open_ports}")
    pdf.paragraph(f"Findings — High: {sev_count['high']}  |  Medium: {sev_count['medium']}  |  Info: {sev_count['info']}")
    pdf.cursor_y -= pdf.block_gap

    pdf.ensure()
    pdf.section_header("DNS")
    pdf.paragraph(f"Host: {dns.get('host','')}")
    pdf.paragraph(f"IP: {dns.get('ip','')}")
    pdf.cursor_y -= pdf.block_gap

    pdf.ensure()
    pdf.section_header("HTTP Fingerprints")
    for proto in ["https","http"]:
        info=http.get(proto,{})
        pdf.paragraph(f"[{proto.upper()}]", size=12)
        if "error" in info:
            pdf.paragraph(f"Error: {info['error']}")
        else:
            pdf.paragraph(f"URL: {info.get('url','')}")
            if "code" in info: pdf.paragraph(f"Status: {info['code']}")
            if "headers" in info:
                for k,v in list(info["headers"].items())[:10]:
                    pdf.paragraph(f"{k}: {v}", indent=pdf.pad_x)
            if "body" in info:
                title = re.search(r"<title>(.*?)</title>", info['body'], re.I | re.S)
                if title: pdf.paragraph(f"Title: {title.group(1)}")
        pdf.cursor_y -= (pdf.block_gap//2)

    pdf.ensure()
    pdf.section_header("Subdomains")
    if subs:
        for s in subs[:25]:
            pdf.paragraph(f"* {s['host']}  ->  {s['ip']}")
    else:
        pdf.paragraph("(none)")
    pdf.cursor_y -= pdf.block_gap

    pdf.ensure()
    pdf.section_header("Ports")
    if ports:
        for p in ports[:40]:
            banner = f"  |  {p['banner']}" if p.get("banner") else ""
            pdf.paragraph(f"* {p['port']}/tcp  {p['state']}  ({p['latency_ms']}ms){banner}")
    else:
        pdf.paragraph("(no IP or no ports scanned)")
    pdf.cursor_y -= pdf.block_gap

    pdf.ensure()
    pdf.section_header("Exploit Hints")
    if ex:
        for e in ex:
            color = (0.78,0.20,0.18) if e.get("severity")=="high" else ((0.91,0.55,0.17) if e.get("severity")=="medium" else (0.22,0.48,0.75))
            x = pdf.margin; w = pdf.page_w - 2*pdf.margin
            pdf.set_fill_rgb(*color); pdf.rect(x, pdf.cursor_y-24, w, 26, True)
            pdf.text(x+pdf.pad_x, pdf.cursor_y-8, f"{e.get('ref','')} - {e['note']} (evidence: {e['evidence']})", size=10, r=1,g=1,b=1)
            pdf.cursor_y -= (26 + pdf.line_gap)
    else:
        pdf.paragraph("(no heuristic matches)")
    pdf.cursor_y -= pdf.block_gap

    pdf.ensure()
    pdf.section_header("External Tools (Snippets)")
    if tools:
        for k,v in tools.items():
            snippet=v.replace("\r","")
            pdf.paragraph(f"[{k}]", size=12)
            for line in pdf._wrap_lines(snippet, size=10):
                pdf.text(pdf.margin+pdf.pad_x, pdf.cursor_y, line[:120], size=9)
                pdf.cursor_y -= (9 + 4)
            pdf.cursor_y -= (pdf.block_gap//2)
            pdf.ensure(180)
    else:
        pdf.paragraph("(none / simulate mode)")
    pdf.cursor_y -= pdf.block_gap

    pdf.ensure()
    pdf.section_header("Notes & Recommendations")
    for s in ["Validate all findings using dedicated tools before remediation.",
              "Only scan systems you own or are authorized to test.",
              "Prioritize HIGH findings, then MEDIUM, then INFO."]:
        pdf.paragraph(f"* {s}")
    pdf.cursor_y -= (pdf.block_gap//2)

    pdf.save(path)

# ===== Scanner with Extended Tools =====
def build_simulated_tool_output(host):
    return {
        "whois": f"Domain Name: {host}\nRegistrar: Example Registrar\nUpdated Date: 2025-01-01",
        "whatweb": "nginx/1.18.0, PHP/5.6, Title: Index of /",
        "subfinder": f"dev.{host}\nadmin.{host}\ncdn.{host}",
        "wafw00f": f"The site {host} is behind Cloudflare (Cloudflare)",
        "a2sv": "Scanning SSL/TLS...\nVULNERABLE: SSLv3 enabled (POODLE)",
        "dnsenum": "DNS enumeration report\nTrying Zone Transfer... FAILED\nName Servers: ns1.example, ns2.example",
        "sqlmap": "Hint: provide a URL with parameters (?id=1).",
        "wpscan": "WordPress 5.5 found. Some plugins may be outdated.",
        "goofile": f"Found: 12 PDF, 3 DOCX, 1 XLSX (sample)",
        "ffuf": "/admin (Status: 301)\n/login (Status: 200)\n/backup (Status: 403)",
        "photon": "Crawled 124 URLs; 8 JS; 5 endpoints with params.",
        "hakrawler": "http://{}/login\nhttp://{}/api/users?id=1\nhttp://{}/admin".format(host,host,host),
        "nmap": f"PORT   STATE SERVICE VERSION\n80/tcp open  http  Apache httpd 2.4.50\n22/tcp open  ssh   OpenSSH 7.2",
        "nikto": "OSVDB-3092: /admin/: This might be a directory.\n+ Server leaks inodes via ETags",
    }

class ScannerEngine:
    def __init__(self, target, simulate=False, deep=False, log_cb=None, progress_cb=None):
        self.target = target.strip(); self.simulate = simulate; self.deep = deep
        self.log = log_cb or (lambda s: None); self.progress = progress_cb or (lambda p: None)
        self.results = {"meta":{"target":self.target,"timestamp":datetime.now(timezone.utc).isoformat(),"simulate":simulate,"deep":deep,"tools":detect_tools()},
                        "dns":{}, "http":{}, "subdomains":[], "ports":[], "tools":{}, "exploits":[]}

    def _step(self, m,p): self.log(m); self.progress(p)

    def run(self):
        try:
            host = safe_parse_host(self.target)
            if not host: self.log("[!] Invalid target"); return self.results
            self._step(f"[+] Target resolved host: {host}", 4)

            ip = resolve_host(host); self.results["dns"] = {"host": host, "ip": ip}
            self._step(f"[+] DNS: {host} -> {ip}" if ip else f"[!] DNS: failed to resolve {host}", 10)

            # HTTP fingerprints
            if not self.simulate:
                https = http_fetch(host, True); http  = http_fetch(host, False)
            else:
                https = {"url": f"https://{host}/", "code": 200, "headers": {"Server":"nginx/1.18.0","X-Powered-By":"PHP/5.6"}, "body":"<html><title>Index of /</title><body>Welcome</body></html>"}
                http  = {"url": f"http://{host}/", "code": 301, "headers": {"Server":"Apache/2.4.49"}, "body":""}
            self.results["http"]={"https":https,"http":http}; self._step("[+] HTTP fingerprinting done", 22)

            # Subdomains
            subs = brute_subdomains(host) if not self.simulate else [{"host": f"dev.{host}", "ip":"203.0.113.10"},{"host": f"admin.{host}", "ip":"203.0.113.11"}]
            self.results["subdomains"]=subs; self._step(f"[+] Subdomain sweep found {len(subs)} hosts", 30)

            # Ports
            ports = small_port_scan(ip, DEFAULT_PORTS) if (ip and not self.simulate) else ([{"port":80,"state":"open","latency_ms":8,"banner":"HTTP/1.0 200 OK\nServer: Apache/2.4.50"},{"port":22,"state":"open","latency_ms":12,"banner":"SSH-2.0-OpenSSH_7.2"}] if ip or self.simulate else [])
            self.results["ports"]=ports; self._step(f"[+] Port scan completed ({len(ports)} ports)", 44)

            # External tools
            tool_outputs = {}
            tools = self.results["meta"]["tools"]
            if self.simulate:
                tool_outputs.update(build_simulated_tool_output(host))
                self._step("[+] Simulated external tool output generated", 70)
            else:
                # Always-on lighter tools (if present)
                if tools.get("whois"):   tool_outputs["whois"]   = run_cmd(["whois", host], 20); self._step("[+] whois completed", 48)
                if tools.get("whatweb"): tool_outputs["whatweb"] = run_cmd(["whatweb","-v", host], 30); self._step("[+] whatweb completed", 52)
                if tools.get("subfinder"): tool_outputs["subfinder"] = run_cmd(["subfinder","-silent","-d",host], 35); self._step("[+] subfinder completed", 56)

                # Deep scan (optional, heavier)
                if self.deep:
                    if tools.get("wafw00f"): tool_outputs["wafw00f"] = run_cmd(["wafw00f", host], 35); self._step("[+] wafw00f completed", 58)
                    if tools.get("a2sv"):    tool_outputs["a2sv"]    = run_cmd(["a2sv","-t",host], 45); self._step("[+] a2sv completed", 60)
                    if tools.get("dnsenum"): tool_outputs["dnsenum"] = run_cmd(["dnsenum",host], 45); self._step("[+] dnsenum completed", 62)

                    # sqlmap: only if URL with params
                    if tools.get("sqlmap"):
                        if ("?" in self.target) or ("=" in self.target):
                            try_url = self.target if "://" in self.target else ("http://"+self.target)
                            tool_outputs["sqlmap"] = run_cmd(["sqlmap","-u",try_url,"--batch","--level=1","--risk=1","--random-agent","--smart","--time-sec=5"], 90)
                        else:
                            tool_outputs["sqlmap"] = "Hint: provide a URL with parameters (?id=1) to test for SQLi."
                        self._step("[+] sqlmap processed", 66)

                    if tools.get("wpscan"):
                        url = "http://"+host
                        tool_outputs["wpscan"] = run_cmd(["wpscan","--url",url,"--no-update","--random-user-agent","--plugins-detection","passive"], 120)
                        self._step("[+] wpscan completed", 70)

                    if tools.get("goofile"):
                        tool_outputs["goofile"] = run_cmd(["goofile","-d",host,"-f","pdf"], 45)
                        self._step("[+] goofile completed", 72)

                    if tools.get("ffuf"):
                        # keep it short and safe
                        wordlist = "/usr/share/wordlists/dirb/common.txt"
                        if not os.path.exists(wordlist):
                            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
                        if os.path.exists(wordlist):
                            cmd = ["ffuf","-u",f"http://{host}/FUZZ","-w",wordlist,"-t","20","-mc","200,204,301,302,307,403","-fs","0","-of","md","-o","-"]
                            tool_outputs["ffuf"] = run_cmd(cmd, 60)
                        else:
                            tool_outputs["ffuf"] = "[wordlist not found]"
                        self._step("[+] ffuf completed", 76)

                    if tools.get("hakrawler"):
                        cmd = f"printf 'http://{host}\\n' | hakrawler -plain -depth 2 -scope subs"
                        tool_outputs["hakrawler"] = run_cmd(cmd, 45, shell=True)
                        self._step("[+] hakrawler completed", 80)

                    if tools.get("photon"):
                        # photon prefers output dirs; run minimal to stdout (simulate via help if needed)
                        tool_outputs["photon"] = run_cmd(["photon","-u",f"http://{host}","-l","2","-n"], 60)
                        self._step("[+] photon completed", 84)

                    if tools.get("nmap") and self.results["dns"].get("ip"):
                        tool_outputs["nmap"] = run_cmd(["nmap","-sV","-F",self.results["dns"]["ip"]], 60)
                        self._step("[+] nmap completed", 88)

                    if tools.get("nikto"):
                        tool_outputs["nikto"] = run_cmd(["nikto","-host",host], 90)
                        self._step("[+] nikto completed", 92)

            self.results["tools"]=tool_outputs

            # Exploit heuristics from fingerprints and tool outputs
            fingerprints = []
            for k in ["https","http"]:
                info=self.results["http"].get(k,{})
                if info.get("headers"):
                    for hk,hv in info["headers"].items(): fingerprints.append(f"{hk}: {hv}")
                if info.get("body"):
                    title=re.search(r"<title>(.*?)</title>", info["body"], re.I|re.S)
                    if title: fingerprints.append(f"Title: {title.group(1)}")
                    if "Index of /" in info["body"]:
                        self.results["exploits"].append({"evidence":"Index page listing detected","note":"Possible directory listing exposure","ref":"CWE-548","severity":"medium"})
            for pr in self.results["ports"]:
                if pr.get("banner"): fingerprints.append(pr["banner"])
            joined="\n".join(fingerprints) + "\n" + "\n".join(self.results["tools"].values())

            # Known patterns from VULN_DB
            for rule in VULN_DB:
                if re.search(rule["pattern"], joined, re.I):
                    self.results["exploits"].append({"evidence":rule["pattern"], "note":rule["desc"], "ref":rule["cve"], "severity":"high"})

            # Tool-specific hints
            if "dnsenum" in tool_outputs and re.search(r"zone transfer.*(successful|succeeded)|AXFR.*(successful|succeeded)", tool_outputs["dnsenum"], re.I):
                self.results["exploits"].append({"evidence":"dnsenum AXFR success","note":"Zone transfer allowed","ref":"CWE-200","severity":"high"})
            if "wafw00f" in tool_outputs and re.search(r"is behind|WAF", tool_outputs["wafw00f"], re.I):
                self.results["exploits"].append({"evidence":"WAF detected","note":"Web Application Firewall present; adjust testing strategy","ref":"Info","severity":"info"})
            if "a2sv" in tool_outputs and re.search(r"VULNERABLE|POODLE|BEAST|CRIME|BREACH|SSLv3 enabled", tool_outputs["a2sv"], re.I):
                self.results["exploits"].append({"evidence":"TLS finding (a2sv)","note":"SSL/TLS weakness reported","ref":"SSL/TLS","severity":"medium"})
            if "wpscan" in tool_outputs and re.search(r"vulnerable|out of date|vulnerability", tool_outputs["wpscan"], re.I):
                self.results["exploits"].append({"evidence":"wpscan report","note":"WordPress components may be vulnerable/outdated","ref":"WP","severity":"medium"})
            if "ffuf" in tool_outputs and re.search(r"\(Status:\s*(200|301|302|403)\)", tool_outputs["ffuf"]):
                self.results["exploits"].append({"evidence":"ffuf discovered paths","note":"Interesting directories/files found","ref":"Recon","severity":"info"})
            if "sqlmap" in tool_outputs and re.search(r"is vulnerable|parameter|payload", tool_outputs["sqlmap"], re.I):
                self.results["exploits"].append({"evidence":"sqlmap output","note":"Possible SQL injection identified","ref":"CWE-89","severity":"high"})
            if "hakrawler" in tool_outputs and re.search(r"\?", tool_outputs["hakrawler"]):
                self.results["exploits"].append({"evidence":"hakrawler endpoints with params","note":"Parameters discovered — test for injection/XSS","ref":"Recon","severity":"info"})

            self._step(f"[+] Exploit heuristics generated ({len(self.results['exploits'])} findings)", 96)
            self._step("[✔] Scan complete", 100)
        except Exception as e:
            self.log(f"[!] Scanner error: {e}")
        return self.results

# ===== CLI/GUI glue =====
def format_report_text(res, colored=False):
    ANSI = {"reset":"\033[0m","bold":"\033[1m","green":"\033[32m","yellow":"\033[33m","red":"\033[31m","blue":"\033[34m","cyan":"\033[36m"}
    def colorize(s, col): return f"{ANSI[col]}{s}{ANSI['reset']}" if colored else s
    meta=res.get("meta",{}); dns=res.get("dns",{}); http=res.get("http",{})
    subs=res.get("subdomains",[]); ports=res.get("ports",[]); ex=res.get("exploits",[]); tools=res.get("tools",{})
    lines=[]; title=f"{APP_NAME} {APP_VER} Report"
    lines.append(colorize(title,"cyan")); lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')} UTC")
    lines.append(f"Target: {meta.get('target','')}   Mode: {'SIMULATE' if meta.get('simulate') else 'LIVE'}   Deep: {meta.get('deep')}"); lines.append("")
    open_ports=sum(1 for p in ports if p.get("state")=="open")
    sev_count={"high":0,"medium":0,"info":0}; 
    for e in ex: sev_count[e.get("severity","info")] = sev_count.get(e.get("severity","info"),0)+1
    lines.append(colorize(f"Open Ports: {open_ports} | Exploits: High {sev_count['high']}  Medium {sev_count['medium']}  Info {sev_count['info']}", "green")); lines.append("")
    lines.append(colorize("== DNS ==", "blue")); lines.append(json.dumps(dns, indent=2)); lines.append("")
    lines.append(colorize("== HTTP Fingerprints ==", "blue"))
    for proto in ["https","http"]:
        info=http.get(proto,{}); lines.append(f"[{proto.upper()}]")
        if "error" in info: lines.append(f"  Error: {info['error']}")
        else:
            lines.append(f"  URL: {info.get('url','')}")
            if "code" in info: lines.append(f"  Status: {info['code']}")
            if "headers" in info:
                lines.append("  Headers:")
                for k,v in info["headers"].items(): lines.append(f"    {k}: {v}")
            if "body" in info:
                title = re.search(r"<title>(.*?)</title>", info['body'], re.I | re.S)
                if title: lines.append(f"  Title: {title.group(1)}")
        lines.append("")
    lines.append(colorize("== Subdomains ==", "blue")); lines += [f"- {s['host']} -> {s['ip']}" for s in subs] or ["(none)"]; lines.append("")
    lines.append(colorize("== Ports ==", "blue"))
    lines += [f"- {p['port']}/tcp: {p['state']} ({p['latency_ms']}ms){(' | '+p['banner']) if p.get('banner') else ''}" for p in ports] or ["(no IP or no ports scanned)"]; lines.append("")
    lines.append(colorize("== Exploit Hints ==", "blue"))
    if ex:
        for e in ex:
            tag={"high":"[HIGH]","medium":"[MED]","info":"[INFO]"}.get(e.get("severity","info"),"[INFO]")
            lines.append(f"{tag} {e.get('ref','')} - {e['note']}  (evidence: {e['evidence']})")
    else: lines.append("(no heuristic matches)")
    lines.append(""); lines.append(colorize("== External Tools ==", "blue"))
    if tools:
        for k,v in tools.items():
            snippet=v[:1600]; tail="... (truncated)" if len(v)>1600 else ""
            lines.append(f"[{k}]\n{snippet}{tail}\n")
    else: lines.append("(none / simulate mode)")
    lines.append(""); lines.append("== Notes ==")
    lines.append("* This is a lightweight scanner. Verify findings with dedicated tools before remediation.")
    lines.append("* Only scan systems you are authorized to test.")
    return "\n".join(lines)

class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title(f"{APP_NAME} {APP_VER}")
        self.geometry("1020x700"); self.minsize(900,600)
        self.dark_mode=True; self._queue=queue.Queue(); self._worker=None; self._results=None
        self._build_ui(); self._apply_theme(); self.after(100, self._drain_log_queue)
    def _build_ui(self):
        top=ttk.Frame(self); top.pack(fill="x", padx=10, pady=10)
        ttk.Label(top, text="🛡️ VulnLite", font=("Segoe UI", 14, "bold")).pack(side="left", padx=(0,10))
        ttk.Label(top, text="Target (domain/IP or URL):").pack(side="left")
        self.target_var=tk.StringVar(value="example.com")
        ttk.Entry(top, textvariable=self.target_var, width=40).pack(side="left", padx=6)
        self.sim_var=tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Simulate", variable=self.sim_var).pack(side="left", padx=10)
        self.deep_var=tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Deep Scan (more tools)", variable=self.deep_var).pack(side="left", padx=10)
        ttk.Button(top, text="Start Scan", command=self.start_scan).pack(side="left", padx=6)
        ttk.Button(top, text="Clear", command=self.clear_log).pack(side="left", padx=6)
        ttk.Button(top, text="Toggle Dark/Light", command=self.toggle_theme).pack(side="right")

        prog_fr=ttk.Frame(self); prog_fr.pack(fill="x", padx=10)
        self.prog=ttk.Progressbar(prog_fr, orient="horizontal", mode="determinate", maximum=100); self.prog.pack(fill="x")

        cap=ttk.Frame(self); cap.pack(fill="x", padx=10, pady=(2,0))
        self.cap_label=ttk.Label(cap, text="Installed tools: ..."); self.cap_label.pack(side="left")

        body=ttk.Frame(self); body.pack(fill="both", expand=True, padx=10, pady=10)
        self.text=tk.Text(body, wrap="word", height=26, undo=False)
        self.scroll=ttk.Scrollbar(body, command=self.text.yview); self.text.configure(yscrollcommand=self.scroll.set)
        self.text.pack(side="left", fill="both", expand=True); self.scroll.pack(side="right", fill="y")

        bottom=ttk.Frame(self); bottom.pack(fill="x", padx=10, pady=(0,10))
        ttk.Button(bottom, text="Export .txt", command=self.export_txt).pack(side="left")
        ttk.Button(bottom, text="Export .pdf (Fancy)", command=self.export_pdf).pack(side="left", padx=8)
        self.status=ttk.Label(bottom, text="Ready"); self.status.pack(side="right")

        self._refresh_tools_banner()
        self._log("[i] Enter a domain/URL and click Start Scan.")
        self._log("[i] 'Deep Scan' runs more tools and may take longer. Use only on targets you are authorized to test.\n")

    def _refresh_tools_banner(self):
        tools = detect_tools()
        present = [k for k,v in tools.items() if v]
        self.cap_label.configure(text="Installed tools: " + (", ".join(present) if present else "(none) — using simulate mode or built-ins"))

    def _apply_theme(self):
        bg_dark, fg_dark, widget_dark = "#0f1115", "#e7e9ee", "#171a21"
        bg_light, fg_light, widget_light = "#f8f8fb", "#1b1f2a", "#ffffff"
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except: pass
        if self.dark_mode:
            self.configure(bg=bg_dark); self.text.configure(bg=widget_dark, fg=fg_dark, insertbackground=fg_dark, highlightthickness=0, bd=0)
            style.configure(".", background=bg_dark, foreground=fg_dark)
            style.configure("TFrame", background=bg_dark); style.configure("TLabel", background=bg_dark, foreground=fg_dark)
            style.configure("TButton", background=widget_dark, foreground=fg_dark); style.configure("Horizontal.TProgressbar", background="#3b82f6")
        else:
            self.configure(bg=bg_light); self.text.configure(bg=widget_light, fg=fg_light, insertbackground=fg_light, highlightthickness=0, bd=0)
            style.configure(".", background=bg_light, foreground=fg_light)
            style.configure("TFrame", background=bg_light); style.configure("TLabel", background=bg_light, foreground=fg_light)
            style.configure("TButton", background=widget_light, foreground=fg_light); style.configure("Horizontal.TProgressbar", background="#3b82f6")

    def toggle_theme(self): self.dark_mode=not self.dark_mode; self._apply_theme()
    def _log(self, msg): self._queue.put(msg)
    def _drain_log_queue(self):
        try:
            while True:
                msg=self._queue.get_nowait()
                self.text.insert("end", msg+"\n"); self.text.see("end")
        except queue.Empty: pass
        self.after(80, self._drain_log_queue)
    def _set_progress(self, val): self.prog["value"]=max(0,min(100,val)); self.status.configure(text=f"{int(self.prog['value'])}%")

    def start_scan(self):
        if self._worker and self._worker.is_alive(): messagebox.showinfo(APP_NAME, "A scan is already running."); return
        target=self.target_var.get().strip()
        if not target: messagebox.showwarning(APP_NAME, "Please enter a target domain or IP."); return
        self.text.delete("1.0","end"); self._set_progress(0)
        self._log(f"=== {APP_NAME} {APP_VER} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')} UTC ===")
        self._log(f"Target: {target}"); self._log(f"Mode: {'SIMULATE' if self.sim_var.get() else 'LIVE'}  Deep: {self.deep_var.get()}"); self._log("Starting...")
        self._results=None
        def work():
            engine=ScannerEngine(target, simulate=self.sim_var.get(), deep=self.deep_var.get(), log_cb=self._log, progress_cb=self._set_progress)
            res=engine.run(); self._results=res; self._log("\n== SUMMARY ==")
            self._log(json.dumps(res["dns"], indent=2)); self._log(f"Subdomains found: {len(res['subdomains'])}")
            open_ports=sum(1 for p in res["ports"] if p.get("state")=="open")
            self._log(f"Open ports: {open_ports} of {len(res['ports'])} checked"); self._log(f"Exploit hints: {len(res['exploits'])}")
            for ex in res["exploits"]: self._log(f"- [{ex.get('ref','')}] {ex['note']} (sev: {ex.get('severity','info')}, evidence: {ex['evidence']})")
            self._log("\n== DONE ==")
        self._worker=threading.Thread(target=work, daemon=True); self._worker.start()

    def clear_log(self): self.text.delete("1.0","end"); self._set_progress(0); self.status.configure(text="Ready")
    def export_txt(self):
        if not self._results: messagebox.showwarning(APP_NAME, "Run a scan first."); return
        path=filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f: f.write(format_report_text(self._results, colored=False))
            messagebox.showinfo(APP_NAME, f"Saved: {path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to save TXT: {e}")
    def export_pdf(self):
        if not self._results: messagebox.showwarning(APP_NAME, "Run a scan first."); return
        path=filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files","*.pdf")])
        if not path: return
        try:
            export_stylish_pdf(path, self._results); messagebox.showinfo(APP_NAME, f"Saved: {path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to save PDF: {e}")

# CLI
def run_cli(args):
    engine=ScannerEngine(args.target, simulate=args.simulate, deep=args.deep, log_cb=lambda s: print(s), progress_cb=lambda p: None)
    res=engine.run()
    txt=format_report_text(res, colored=sys.stdout.isatty()); print("\n== REPORT =="); print(txt)
    if args.export_txt:
        with open(args.export_txt,"w",encoding="utf-8") as f: f.write(format_report_text(res, colored=False))
        print(f"\n[+] Saved TXT: {args.export_txt}")
    if args.export_pdf:
        export_stylish_pdf(args.export_pdf, res); print(f"[+] Saved PDF: {args.export_pdf}")

def main():
    parser=argparse.ArgumentParser(description=f"{APP_NAME} {APP_VER}")
    parser.add_argument("--target","-t", help="Domain/IP or URL (e.g., example.com or http://example.com/?id=1)")
    parser.add_argument("--simulate", action="store_true", help="Enable simulate mode")
    parser.add_argument("--deep", action="store_true", help="Run deep scan (more tools, slower)")
    parser.add_argument("--export-txt", help="Export report to TXT (CLI)")
    parser.add_argument("--export-pdf", help="Export report to PDF (CLI)")
    parser.add_argument("--nogui", action="store_true", help="Force CLI mode")
    args=parser.parse_args()
    want_gui = not args.nogui and HAS_TK and (os.environ.get("DISPLAY") or sys.platform.startswith("win") or sys.platform=="darwin")
    if want_gui and not args.target:
        app=App(); app.mainloop()
    else:
        if not args.target:
            print(f"[!] No --target provided and GUI unavailable.")
            print(f"    Example: python3 {os.path.basename(__file__)} --target example.com --simulate --deep --export-pdf report.pdf")
            if not HAS_TK: print(f"[i] Tkinter unavailable: {TK_ERROR}")
            sys.exit(1)
        run_cli(args)

if __name__ == "__main__":
    main()
