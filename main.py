import requests
import re
import base64
import json
import asyncio
import time
from urllib.parse import urlparse, unquote, parse_qs, quote
from bs4 import BeautifulSoup
import yaml

# --- НАСТРОЙКИ ДЛЯ КИТАЯ ---
CHANNELS = [
    "VlessConfig", "PrivateVPNs", "oneclickvpnkeys", 
    "v2ray_outlineir", "v2ray_free_conf", "shadowsockskeys"
]

EXTERNAL_SUBS = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_v2ray_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/etc/all",
    "https://raw.githubusercontent.com/officialputuid/V2Ray-Config/main/Splitted-v2ray-config/all"
]

MAX_TOTAL_ALIVE = 1000
TIMEOUT = 2.0 # Увеличим время, в аэропорту инет может быть тугим
CONCURRENCY_LIMIT = 40 # Меньше нагрузки, чтобы не палиться

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def b64_decode(s):
    try:
        s = re.sub(r'[^a-zA-Z0-9+/=]', '', s)
        padding = len(s) % 4
        if padding: s += '=' * (4 - padding)
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except: return ""

def get_flag(code):
    if not code or code == '??': return "🏳️"
    return "".join(chr(ord(c) + 127397) for c in code.upper())

async def check_port(ip, port, sem):
    async with sem:
        try:
            # В Китае даже соединение может висеть, поэтому проверяем быстро
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return True
        except: return False

def parse_link(link):
    try:
        if link.startswith("vmess://"):
            data = json.loads(b64_decode(link[8:]))
            return data.get('add'), int(data.get('port'))
        p = urlparse(link)
        if link.startswith("ss://"):
            if "@" in link:
                part = link.split("@")[-1].split("#")[0].split("/")[0]
                if ":" in part: return part.split(":")[0].replace("[","").replace("]",""), int(part.split(":")[1])
        if p.hostname and p.port: return p.hostname, p.port
    except: pass
    return None, None

# --- ЛОГИКА ---

def get_links():
    seen = set(); links = []
    # Добавили socks5 и hy2 в регулярку
    reg = re.compile(r'(?:vless|vmess|ss|ssr|trojan|hy2|hysteria|hysteria2|tuic|socks5)://[^\s<"\'\)]+')
    head = {'User-Agent': 'Mozilla/5.0'}
    
    for c in CHANNELS:
        try:
            r = requests.get(f"https://t.me/s/{c}", headers=head, timeout=10)
            for l in reg.findall(r.text):
                cl = l.strip().split('<')[0].split('"')[0]
                if cl not in seen: seen.add(cl); links.append(cl)
        except: pass
    
    for url in EXTERNAL_SUBS:
        try:
            r = requests.get(url, headers=head, timeout=15)
            content = r.text
            found = reg.findall(content)
            if len(found) < 10:
                decoded = b64_decode(content)
                if decoded: found = reg.findall(decoded)
            for l in found:
                cl = l.strip()
                if cl not in seen: seen.add(cl); links.append(cl)
        except: pass
    return links

def add_labels(link, ip):
    # ЛОГИКА ДЛЯ КИТАЯ: Ищем Reality и стойкие протоколы
    label = ""
    priority = 100 # Чем меньше, тем выше в списке
    
    # Reality - самый топ для Китая
    if "reality" in link.lower() or "pbk=" in link.lower():
        label = "🛡️ Reality"
        priority = 1
    elif link.startswith("hy2://") or "hysteria2" in link.lower():
        label = "⚡ Hy2"
        priority = 10
    elif "type=ws" in link.lower():
        label = "☁️ CDN"
        priority = 20
    elif link.startswith("socks5://"):
        label = "🧦 SOCKS5"
        priority = 5
    elif link.startswith("vless://"):
        label = "⚓ Vless"
        priority = 30
    else:
        label = "🌐 Proxy"
        priority = 50

    name = f"{label} | {ip.split('.')[-1]}"
    return name, priority

def link_to_clash(link, name):
    try:
        if link.startswith("vmess://"):
            d = json.loads(b64_decode(link[8:]))
            return {'name': name, 'type': 'vmess', 'server': d.get('add'), 'port': int(d.get('port')), 'uuid': d.get('id'), 'alterId': 0, 'cipher': 'auto', 'udp': True, 'tls': d.get('tls')=='tls', 'skip-cert-verify': True, 'network': d.get('net', 'tcp')}
        
        if link.startswith(("vless://", "trojan://")):
            p = urlparse(link); q = parse_qs(p.query); tp = 'vless' if link.startswith('vless') else 'trojan'
            obj = {'name': name, 'type': tp, 'server': p.hostname, 'port': p.port, 'uuid': p.username or p.password, 'password': p.username or p.password, 'udp': True, 'skip-cert-verify': True, 'tls': q.get('security',[''])[0] in ['tls','reality'], 'network': q.get('type',['tcp'])[0]}
            if tp == 'trojan' and 'uuid' in obj: del obj['uuid']
            if q.get('security',[''])[0] == 'reality':
                obj['servername'] = q.get('sni',[''])[0]; obj['reality-opts'] = {'public-key': q.get('pbk',[''])[0], 'short-id': q.get('sid', [''])[0]}; obj['client-fingerprint'] = 'chrome'
            if obj['network'] == 'ws':
                obj['ws-opts'] = {'path': q.get('path', ['/'])[0], 'headers': {'Host': q.get('host', [''])[0]}}
            return obj
            
        if link.startswith("ss://"):
            main = link.split("#")[0].replace("ss://", "")
            if "@" in main:
                userinfo, serverinfo = main.split("@", 1)
                dec_u = b64_decode(userinfo)
                if ":" in dec_u: method, password = dec_u.split(":", 1)
                else: method, password = userinfo.split(":", 1)
                host = serverinfo.split(":")[0]; port = int(serverinfo.split(":")[1].split("/")[0])
                return {'name': name, 'type': 'ss', 'server': host, 'port': port, 'cipher': method, 'password': password, 'udp': True}
        
        if link.startswith("socks5://"):
            # socks5://user:pass@host:port
            p = urlparse(link)
            return {'name': name, 'type': 'socks5', 'server': p.hostname, 'port': p.port, 'username': p.username, 'password': p.password, 'udp': True}
            
    except: pass
    return None

async def main_logic():
    raw = get_links()
    print(f"🧐 Найдено {len(raw)} ссылок. Ищем выход из Китая...")
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    tasks = []
    for l in raw:
        ip, port = parse_link(l)
        if ip and port: tasks.append((l, ip, port))
    
    async def verify(item):
        link, ip, port = item
        if await check_port(ip, port, sem):
            name, prio = add_labels(link, ip)
            return (link, name, prio)
        return None

    results = await asyncio.gather(*(verify(x) for x in tasks))
    alive = [r for r in results if r is not None]
    
    # СОРТИРОВКА ПО ПРИОРИТЕТУ (Reality и SOCKS5 в самый верх)
    alive.sort(key=lambda x: x[2])
    
    clash_list = []; final_links = []
    for l, name, prio in alive[:MAX_TOTAL_ALIVE]:
        obj = link_to_clash(l, name)
        if obj:
            # Уникальность имен
            while any(p['name'] == obj['name'] for p in clash_list): obj['name'] += " "
            clash_list.append(obj); final_links.append(l)

    with open("list.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_links).encode()).decode())
    with open("proxies.yaml", "w", encoding="utf-8") as f: yaml.dump({'proxies': clash_list}, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Готово! Выгружено {len(clash_list)} серверов. Reality и SOCKS5 в топе.")

if __name__ == "__main__":
    asyncio.run(main_logic())
