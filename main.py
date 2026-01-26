import requests
import re
import base64
import json
import asyncio
import time
from urllib.parse import urlparse, unquote, parse_qs, quote
from bs4 import BeautifulSoup
import yaml

# --- НАСТРОЙКИ ---
CHANNELS = [
    "shadowsockskeys", "oneclickvpnkeys", "v2ray_outlineir",
    "v2ray_free_conf", "v2rayngvpn", "v2ray_free_vpn",
    "gurvpn_keys", "vmessh", "VMESS7", "VlessConfig",
    "PrivateVPNs", "nV_v2ray", "NotorVPN", "FairVpn_V2ray",
    "outline_marzban", "outline_k"
]

EXTERNAL_SUBS = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_v2ray_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/LonUp/NodeList/main/NodeList.txt",
    "https://raw.githubusercontent.com/officialputuid/V2Ray-Config/main/Splitted-v2ray-config/all"
]

MAX_TOTAL_ALIVE = 1200 
TIMEOUT = 2.0 # Даем шанс серверам прогрузиться сквозь GFW
CONCURRENCY_LIMIT = 50

# --- ФУНКЦИИ ---

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

def get_ip_info(ips):
    if not ips: return {}
    ip_map = {}
    print(f"🌍 GeoIP Анализ {len(ips)} узлов...")
    for i in range(0, len(ips), 100):
        batch = ips[i:i+100]
        try:
            r = requests.post("http://ip-api.com/batch", json=[{"query": x, "fields": "countryCode"} for x in batch], timeout=15)
            for idx, res in enumerate(r.json()):
                ip_map[batch[idx]] = res.get('countryCode', '')
            time.sleep(1.1)
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
        if link.startswith("ss://") and "@" in link:
            part = link.split("@")[-1].split("#")[0].split("/")[0]
            if ":" in part: return part.split(":")[0].replace("[","").replace("]",""), int(part.split(":")[1])
        if p.hostname and p.port: return p.hostname, p.port
    except: pass
    return None, None

def get_all_links():
    seen = set(); links = []
    reg = re.compile(r'(?:vless|vmess|ss|ssr|trojan|hy2|hysteria|hysteria2|tuic|socks5)://[^\s<"\'\)]+')
    head = {'User-Agent': 'Mozilla/5.0'}

    print("🚀 Собираю всё мясо из ТГ и Гитхаба...")
    
    # 1. ТЕЛЕГРАМ
    for c in CHANNELS:
        try:
            r = requests.get(f"https://t.me/s/{c}", headers=head, timeout=10)
            matches = reg.findall(r.text)
            for l in matches:
                cl = l.strip().split('<')[0].split('"')[0].split("'")[0]
                if cl not in seen: seen.add(cl); links.append(cl)
        except: pass

    # 2. ГИТХАБ (Агрессивный поиск)
    for url in EXTERNAL_SUBS:
        try:
            r = requests.get(url, headers=head, timeout=15)
            content = r.text
            # Сначала ищем как есть
            found = reg.findall(content)
            # Если мало - значит всё в base64
            if len(found) < 10:
                decoded = b64_decode(content)
                if decoded: found = reg.findall(decoded)
            
            for l in found:
                cl = l.strip()
                if cl not in seen: seen.add(cl); links.append(cl)
        except: pass
    return links

def get_china_priority(link):
    """Определяет, насколько протокол живуч в Китае"""
    l = link.lower()
    if "reality" in l or "pbk=" in l: return 1  # Самый топ
    if "hy2" in l or "hysteria2" in l: return 2
    if "trojan" in l: return 3
    if "socks5" in l: return 4
    if "vless" in l: return 5
    return 10 # Всё остальное

def link_to_clash(link, ip, country_code):
    flag = get_flag(country_code)
    # Пометка для Клэша
    prio = get_china_priority(link)
    tag = "🛡️" if prio == 1 else "⚡" if prio == 2 else "🌐"
    name = f"{flag} {tag} | {ip.split('.')[-1]}"

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
            return obj

        if link.startswith("ss://"):
            main = link.split("#")[0].replace("ss://", "")
            if "@" in main:
                userinfo, serverinfo = main.split("@", 1)
                dec_u = b64_decode(userinfo)
                if ":" in dec_u: method, password = dec_u.split(":", 1)
                else: method, password = userinfo.split(":", 1)
                return {'name': name, 'type': 'ss', 'server': serverinfo.split(":")[0], 'port': int(serverinfo.split(":")[1].split("/")[0]), 'cipher': method, 'password': password, 'udp': True}
    except: pass
    return None

async def main_logic():
    raw = get_all_links()
    print(f"🧐 Найдено {len(raw)} кандидатов. Фильтруем...")
    
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = []
    for l in raw:
        ip, port = parse_link(l)
        if ip and port: tasks.append((l, ip, port))
    
    async def verify(item):
        if await check_port(item[1], item[2], sem): return item
        return None

    # Перемешиваем для честности
    import random; random.shuffle(tasks)
    
    results = await asyncio.gather(*(verify(x) for x in tasks))
    alive = [r for r in results if r is not None]
    
    # Сортируем по живучести протокола для Китая
    alive.sort(key=lambda x: get_china_priority(x[0]))
    
    top_alive = alive[:MAX_TOTAL_ALIVE]
    info_map = get_ip_info([x[1] for x in top_alive])
    
    clash_list = []; final_links = []
    for l, ip, port in top_alive:
        obj = link_to_clash(l, ip, info_map.get(ip, ''))
        if obj:
            while any(p['name'] == obj['name'] for p in clash_list): obj['name'] += " "
            clash_list.append(obj); final_links.append(l)

    with open("list.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_links).encode()).decode())
    with open("proxies.yaml", "w", encoding="utf-8") as f: yaml.dump({'proxies': clash_list}, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Готово! Выгружено {len(clash_list)} серверов.")

if __name__ == "__main__":
    asyncio.run(main_logic())
