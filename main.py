import requests
import re
import base64
import json
import asyncio
import time
from urllib.parse import urlparse, unquote, parse_qs, quote
from bs4 import BeautifulSoup
import yaml

# --- НАСТРОЙКИ СПАСЕНИЯ ---
CHANNELS = [
    "shadowsockskeys", "oneclickvpnkeys", "v2ray_outlineir",
    "v2ray_free_conf", "VlessConfig", "PrivateVPNs", "nV_v2ray"
]

EXTERNAL_SUBS = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_v2ray_configs.txt",
    "https://raw.githubusercontent.com/WilliamStar007/ClashX-V2Ray-TopFreeProxy/main/main.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/etc/all",
    "https://raw.githubusercontent.com/vless-reality/vless-reality/main/sub"
]

# Ключевые страны для обхода GFW (Азия)
ASIA_WINS = ['VN', 'HK', 'SG', 'JP', 'KR', 'MY', 'TW']

MAX_TOTAL_ALIVE = 1200
TIMEOUT = 1.8 # Средний баланс для китайского мобильного инета
CONCURRENCY_LIMIT = 40

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

def batch_get_ip_info(ips):
    if not ips: return {}
    ip_map = {}
    print(f"🌍 GeoIP Анализ для Азии...")
    for i in range(0, len(ips), 100):
        batch = ips[i:i+100]
        try:
            r = requests.post("http://ip-api.com/batch", json=[{"query": x, "fields": "countryCode"} for x in batch], timeout=15)
            for idx, res in enumerate(r.json()):
                ip_map[batch[idx]] = res.get('countryCode', '')
            time.sleep(1.2)
        except: pass
    return ip_map

async def check_port(ip, port, sem):
    async with sem:
        try:
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
            r = requests.get(url, headers=head, timeout=15); content = r.text
            found = reg.findall(content)
            if len(found) < 10:
                decoded = b64_decode(content)
                if decoded: found = reg.findall(decoded)
            for l in found:
                cl = l.strip()
                if cl not in seen: seen.add(cl); links.append(cl)
        except: pass
    return links

def add_labels_asia(link, ip, country_code):
    """Приоритеты для Китая"""
    flag = get_flag(country_code)
    label = ""
    priority = 100 
    
    # 1. Reality - БЕТОН
    if "reality" in link.lower() or "pbk=" in link.lower():
        label = "🛡️ Reality"
        priority = 1
    # 2. Азия (Вьетнам и ко) - ШАНС ВЫШЕ
    elif country_code in ASIA_WINS:
        label = f"🌏 {country_code}"
        priority = 5
    # 3. Скоростные UDP
    elif link.startswith("hy2://") or "hysteria2" in link.lower():
        label = "⚡ Hy2"
        priority = 10
    else:
        label = "🌐 Proxy"
        priority = 50

    name = f"{flag} {label} | {ip.split('.')[-1]}"
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
                elif ":" in userinfo: method, password = userinfo.split(":", 1)
                else: return None
                host = serverinfo.split(":")[0]; port = int(serverinfo.split(":")[1].split("/")[0])
                return {'name': name, 'type': 'ss', 'server': host, 'port': port, 'cipher': method, 'password': password, 'udp': True}
    except: pass
    return None

async def main_logic():
    raw = get_links()
    print(f"🧐 Найдено {len(raw)} ссылок. Пробиваем Азию...")
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    tasks = []
    for l in raw:
        ip, port = parse_link(l)
        if ip and port: tasks.append((l, ip, port))
    
    async def verify(item):
        link, ip, port = item
        if await check_port(ip, port, sem): return (link, ip)
        return None

    results = await asyncio.gather(*(verify(x) for x in tasks))
    alive = [r for r in results if r is not None]
    
    # Получаем страны для всех живых
    info_map = batch_get_ip_info([x[1] for x in alive])
    
    # Готовим итоговый список с приоритетами
    priority_list = []
    for l, ip in alive:
        country = info_map.get(ip, '')
        name, prio = add_labels_asia(l, ip, country)
        priority_list.append((l, name, prio))
    
    # Сортируем: Reality и Азия в начало
    priority_list.sort(key=lambda x: x[2])
    
    clash_list = []; final_links = []
    for l, name, prio in priority_list[:MAX_TOTAL_ALIVE]:
        obj = link_to_clash(l, name)
        if obj:
            while any(p['name'] == obj['name'] for p in clash_list): obj['name'] += " "
            clash_list.append(obj); final_links.append(l)

    with open("list.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_links).encode()).decode())
    with open("proxies.yaml", "w", encoding="utf-8") as f: yaml.dump({'proxies': clash_list}, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Готово! Азия и Reality выведены в топ.")

if __name__ == "__main__":
    asyncio.run(main_logic())
