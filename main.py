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
    "https://raw.githubusercontent.com/LonUp/NodeList/main/NodeList.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
]

MAX_LINKS_PER_TG = 800   # Лимит ссылок с одного канала ТГ
MAX_PAGES_TG = 30        # Глубина листания истории ТГ
MAX_TOTAL_ALIVE = 1000   # Итого в файле
TIMEOUT = 1.2            # Чуть добавил времени для стабильности мобильного инета
CONCURRENCY_LIMIT = 50

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

def get_ip_info(ips):
    if not ips: return {}
    ip_map = {}
    print(f"🌍 GeoIP для {len(ips)} IP...")
    for i in range(0, len(ips), 100):
        batch = ips[i:i+100]
        try:
            r = requests.post("http://ip-api.com/batch", json=[{"query": x, "fields": "countryCode,isp"} for x in batch], timeout=15)
            for idx, res in enumerate(r.json()):
                ip_map[batch[idx]] = {'c': res.get('countryCode', ''), 'i': res.get('isp', '').lower()}
            time.sleep(1.2)
        except: pass
    return ip_map

async def check_latency(ip, port, sem):
    async with sem:
        try:
            start = time.time()
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
            lat = int((time.time() - start) * 1000)
            await asyncio.sleep(0.05) # Проверка на моментальный разрыв
            writer.close()
            await writer.wait_closed()
            if lat < 10: return None # Смерть фейкам
            return lat
        except: return None

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

# --- ГЛОБАЛЬНЫЙ ПАРСЕР ---

def get_all_links():
    seen = set()
    all_links = []
    stats = {}
    reg = re.compile(r'(?:vless|vmess|ss|ssr|trojan|hy2|hysteria|hysteria2|tuic)://[^\s<"\'\)]+')
    head = {'User-Agent': 'Mozilla/5.0'}

    print("🚀 Начинаю сбор данных...")

    # 1. ТЕЛЕГРАМ С ПАГИНАЦИЕЙ
    for c in CHANNELS:
        url = f"https://t.me/s/{c}"
        found_here = 0
        for _ in range(MAX_PAGES_TG):
            try:
                r = requests.get(url, headers=head, timeout=10)
                soup = BeautifulSoup(r.text, 'html.parser')
                msgs = soup.find_all('div', class_='tgme_widget_message_text')
                if not msgs: break
                
                new_on_page = 0
                for m in reversed(msgs):
                    matches = reg.findall(m.get_text())
                    for l in matches:
                        cl = l.strip().split('<')[0].split('"')[0].split("'")[0]
                        if cl not in seen:
                            seen.add(cl); all_links.append(cl); found_here += 1; new_on_page += 1
                
                if found_here >= MAX_LINKS_PER_TG or new_on_page == 0: break
                
                more = soup.find('a', class_='tme_messages_more')
                if more: url = "https://t.me" + more['href']
                else: break
            except: break
        stats[c] = found_here

    # 2. ГИТХАБ / ВНЕШНИЕ
    for url in EXTERNAL_SUBS:
        name = url.split('/')[-2] if 'github' in url else 'external'
        found_here = 0
        try:
            r = requests.get(url, headers=head, timeout=15)
            content = r.text
            found = reg.findall(content)
            if len(found) < 10:
                decoded = b64_decode(content)
                if decoded: found = reg.findall(decoded)
            
            for l in found:
                cl = l.strip()
                if cl not in seen:
                    seen.add(cl); all_links.append(cl); found_here += 1
                if found_here >= 1500: break
        except: pass
        stats[name] = found_here

    # ПЕЧАТАЕМ КРАСИВЫЙ ОТЧЕТ В ЛОГИ
    print("\n📊 ОТЧЕТ ПО ИСТОЧНИКАМ (уникальные):")
    for src, count in stats.items():
        print(f"   - {src.ljust(20)}: +{count}")
    print(f"🔥 Итого кандидатов: {len(all_links)}\n")
    
    return all_links

def link_to_clash(link, ip, latency, info):
    country = info.get('c', ''); isp = info.get('i', ''); flag = get_flag(country)
    bad = ['amazon','aws','google','oracle','azure','digitalocean','hetzner','cloudflare','vultr','linode','m247']
    is_ai = country not in ['RU','BY','CN','IR','KP','SY'] and not any(w in isp for w in bad) and not link.startswith("ss://")
    name = f"{flag}{'✨' if is_ai else ''} {latency}ms | {ip.split('.')[-1]}"

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
                elif ":" in userinfo: method, password = userinfo.split(":", 1)
                else: return None
                host = serverinfo.split(":")[0]; port = int(serverinfo.split(":")[1].split("/")[0])
                return {'name': name, 'type': 'ss', 'server': host, 'port': port, 'cipher': method, 'password': password, 'udp': True}
    except: pass
    return None

async def main_logic():
    raw = get_all_links()
    if not raw: return
    
    print(f"🧐 Замеряю задержку для {len(raw)} ссылок...")
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    tasks = []
    for l in raw:
        ip, port = parse_link(l)
        if ip and port: tasks.append((l, ip, port))
    
    async def verify(item):
        link, ip, port = item
        lat = await check_latency(ip, port, sem)
        return (link, ip, lat) if lat is not None else None

    # Перемешиваем перед проверкой
    import random; random.shuffle(tasks)
    
    results = await asyncio.gather(*(verify(x) for x in tasks))
    alive = [r for r in results if r is not None]
    alive.sort(key=lambda x: x[2]) # Сортировка по пингу
    
    top_alive = alive[:MAX_TOTAL_ALIVE]
    info_map = get_ip_info([x[1] for x in top_alive])
    
    clash_list = []; final_links = []
    for l, ip, lat in top_alive:
        obj = link_to_clash(l, ip, lat, info_map.get(ip, {}))
        if obj:
            while any(p['name'] == obj['name'] for p in clash_list): obj['name'] += " "
            clash_list.append(obj); final_links.append(l)

    with open("list.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_links).encode()).decode())
    with open("proxies.yaml", "w", encoding="utf-8") as f: yaml.dump({'proxies': clash_list}, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Готово! Всего элитных серверов: {len(clash_list)}")

if __name__ == "__main__":
    asyncio.run(main_logic())
