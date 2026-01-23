import requests
import re
import base64
import json
import asyncio
import time
from urllib.parse import urlparse, unquote, parse_qs, quote
import yaml

# --- НАСТРОЙКИ ---
CHANNELS = [
    "shadowsockskeys", "oneclickvpnkeys", "v2ray_outlineir",
    "v2ray_free_conf", "v2rayngvpn", "v2ray_free_vpn"
]

# Только те, что РЕАЛЬНО отдают тысячи
EXTERNAL_SUBS = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_v2ray_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/LonUp/NodeList/main/NodeList.txt"
]

MAX_TOTAL_ALIVE = 1000
TIMEOUT = 1.0 # Баланс скорости и стабильности
CONCURRENCY_LIMIT = 100

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def b64_decode(s):
    """Декодирует Base64 любой сложности"""
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
    print(f"🌍 GeoIP для {len(ips)} шт...")
    for i in range(0, len(ips), 100):
        batch = ips[i:i+100]
        try:
            r = requests.post("http://ip-api.com/batch", json=[{"query": x, "fields": "countryCode,isp"} for x in batch], timeout=15)
            for idx, res in enumerate(r.json()):
                ip_map[batch[idx]] = {'c': res.get('countryCode', ''), 'i': res.get('isp', '').lower()}
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
    """Достает IP и Port для проверки"""
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

# --- ПАРСЕР ---

def get_links():
    seen = set()
    links = []
    reg = re.compile(r'(?:vless|vmess|ss|ssr|trojan|hy2|hysteria|tuic)://[^\s<"\'\)]+')
    head = {'User-Agent': 'Mozilla/5.0'}

    # ТГ
    for c in CHANNELS:
        try:
            r = requests.get(f"https://t.me/s/{c}", headers=head, timeout=10)
            for l in reg.findall(r.text):
                cl = l.strip().split('<')[0].split('"')[0].split("'")[0]
                if cl not in seen: seen.add(cl); links.append(cl)
        except: pass

    # ВНЕШНИЕ
    for url in EXTERNAL_SUBS:
        try:
            r = requests.get(url, headers=head, timeout=15)
            text = r.text
            # Пробуем и так и сяк
            found = reg.findall(text)
            if len(found) < 10:
                decoded = b64_decode(text)
                if decoded: found = reg.findall(decoded)
            
            for l in found:
                cl = l.strip()
                if cl not in seen: seen.add(cl); links.append(cl)
        except: pass
    return links

def link_to_clash(link, ip, info):
    """Превращает в ПРАВИЛЬНЫЙ объект Clash"""
    country = info.get('c', ''); isp = info.get('i', ''); flag = get_flag(country)
    bad = ['amazon','aws','google','oracle','azure','digitalocean','hetzner','m247','cloudflare','vultr']
    is_ai = country not in ['RU','BY','CN','IR','KP'] and not any(w in isp for w in bad) and not link.startswith("ss://")
    name = f"{flag}{' ✨ AI' if is_ai else ''} {ip}"

    try:
        if link.startswith("vmess://"):
            d = json.loads(b64_decode(link[8:]))
            return {'name': name, 'type': 'vmess', 'server': d.get('add'), 'port': int(d.get('port')), 'uuid': d.get('id'), 'alterId': 0, 'cipher': 'auto', 'udp': True, 'tls': d.get('tls')=='tls', 'skip-cert-verify': True, 'network': d.get('net', 'tcp')}
        
        if link.startswith(("vless://", "trojan://")):
            p = urlparse(link); q = parse_qs(p.query); tp = 'vless' if link.startswith('vless') else 'trojan'
            obj = {'name': name, 'type': tp, 'server': p.hostname, 'port': p.port, 'uuid': p.username or p.password, 'password': p.username or p.password, 'udp': True, 'skip-cert-verify': True, 'tls': q.get('security',[''])[0] in ['tls','reality'], 'network': q.get('type',['tcp'])[0]}
            if tp == 'trojan' and 'uuid' in obj: del obj['uuid']
            if q.get('security',[''])[0] == 'reality':
                obj['servername'] = q.get('sni',[''])[0]; obj['reality-opts'] = {'public-key': q.get('pbk',[''])[0], 'short-id': q.get('sid',[''])[0]}; obj['client-fingerprint'] = 'chrome'
            return obj

        if link.startswith("ss://"):
            # ЧИНИМ SHADOWSOCKS
            main = link.split("#")[0].replace("ss://", "")
            if "@" in main:
                userinfo, serverinfo = main.split("@", 1)
                # Если userinfo закодирован в base64
                decoded_user = b64_decode(userinfo)
                if ":" in decoded_user:
                    method, password = decoded_user.split(":", 1)
                else:
                    # Если формат ss://method:pass@ip:port
                    if ":" in userinfo: method, password = userinfo.split(":", 1)
                    else: return None
                
                host = serverinfo.split(":")[0]
                port = int(serverinfo.split(":")[1].split("/")[0])
                return {'name': name, 'type': 'ss', 'server': host, 'port': port, 'cipher': method, 'password': password, 'udp': True}
    except: pass
    return None

async def main_logic():
    raw = get_links()
    print(f"🧐 Найдено {len(raw)} ссылок. Проверяем...")
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = []
    for l in raw:
        ip, port = parse_link(l)
        if ip and port: tasks.append((l, ip, port))
    
    async def verify(item):
        if await check_port(item[1], item[2], sem): return item
        return None

    results = await asyncio.gather(*(verify(x) for x in tasks))
    alive = [r for r in results if r is not None][:MAX_TOTAL_ALIVE]
    
    info_map = get_ip_info([x[1] for x in alive])
    
    clash_list = []; final_links = []
    for l, ip, port in alive:
        obj = link_to_clash(l, ip, info_map.get(ip, {}))
        if obj:
            while any(p['name'] == obj['name'] for p in clash_list): obj['name'] += " "
            clash_list.append(obj); final_links.append(l)

    with open("list.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_links).encode()).decode())
    with open("proxies.yaml", "w", encoding="utf-8") as f: yaml.dump({'proxies': clash_list}, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Готово! Всего: {len(clash_list)}")

if __name__ == "__main__":
    asyncio.run(main_logic())
