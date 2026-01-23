import requests
from bs4 import BeautifulSoup
import re
import base64
import json
import asyncio
import time
from urllib.parse import urlparse, unquote, parse_qs, quote
import yaml

# --- НАСТРОЙКИ ---
CHANNELS = [
    "shadowsockskeys",
    "oneclickvpnkeys",
    "v2ray_outlineir",
    "v2ray_free_conf",
    "iSeqaro",
    "v2ray_free_vpn",
    "v2rayngvpn",
    "free4vpn",
    "PR_VPN"
]

# Лимиты (проверь эти цифры после вставки!)
MAX_LINKS_PER_CHANNEL = 1000 
MAX_PAGES_PER_CHANNEL = 50   



# ЖИРНЫЕ ИСТОЧНИКИ (Тут лежат тысячи ссылок)
EXTERNAL_SUBS = [
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_v2ray_configs.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/etc/all",
    "https://raw.githubusercontent.com/yebekhe/TVProxy/main/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/LonUp/NodeList/main/NodeList.txt"
]

# Лимиты для стабильности (чтобы Гитхаб не прибил скрипт за 10 минут)
MAX_LINKS_PER_SOURCE = 1000
MAX_TOTAL_ALIVE = 800 # Золотая середина для FlClash

TIMEOUT = 1.0 # ЖЕСТКО. Только самые быстрые выживут.
CONCURRENCY_LIMIT = 100 # Проверяем пачками по 100

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def safe_base64_decode(s):
    s = s.strip().replace('\r', '').replace('\n', '')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try: return base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
    except: return None

def get_flag_emoji(country_code):
    if not country_code: return "🏳️"
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())

def batch_get_ip_info(ips):
    if not ips: return {}
    unique_ips = list(set(ips))[:MAX_TOTAL_ALIVE]
    ip_map = {}
    print(f"🌍 GeoIP для {len(unique_ips)} IP...")
    for i in range(0, len(unique_ips), 100):
        batch = unique_ips[i:i + 100]
        try:
            resp = requests.post("http://ip-api.com/batch", 
                               json=[{"query": ip, "fields": "countryCode,isp"} for ip in batch], timeout=15)
            for idx, result in enumerate(resp.json()):
                ip_map[batch[idx]] = {'country': result.get('countryCode', ''), 'isp': result.get('isp', '').lower()}
            time.sleep(1.1) # Чтобы API не забанило
        except: pass
    return ip_map

async def check_port(ip, port, semaphore):
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return True
        except: return False

def extract_ip_port(link):
    try:
        if link.startswith("vmess://"):
            data = json.loads(safe_base64_decode(link[8:]))
            return data.get('add'), int(data.get('port'))
        parsed = urlparse(link)
        if link.startswith("ss://") and "@" in link:
            part = link.split("@")[-1].split("/")[0].split("?")[0].split("#")[0]
            if ":" in part: return part.split(":")[0].replace("[", "").replace("]", ""), int(part.split(":")[1])
        if parsed.hostname and parsed.port: return parsed.hostname, parsed.port
    except: pass
    return None, None

# --- ПАРСИНГ ---
def get_all_links():
    seen = set()
    links = []
    pattern = re.compile(r'(?:vless|vmess|ss|ssr|trojan|hy2|hysteria|hysteria2|tuic)://[^\s<"\'\)]+')

    # 1. ТЕЛЕГРАМ
    for channel in CHANNELS:
        print(f"🔍 Парсинг ТГ: {channel}")
        try:
            resp = requests.get(f"https://t.me/s/{channel}", timeout=10)
            matches = pattern.findall(resp.text)
            found = 0
            for link in reversed(matches):
                clean = link.strip().split('<')[0].split('"')[0]
                if clean not in seen:
                    seen.add(clean); links.append(clean); found += 1
                if found >= 100: break
            print(f"   ✅ +{found}")
        except: pass

    # 2. ГИТХАБ ИСТОЧНИКИ
    print(f"📡 Пылесосим внешние подписки...")
    for url in EXTERNAL_SUBS:
        try:
            resp = requests.get(url, timeout=15)
            content = resp.text
            # Проверка на Base64
            if not any(x in content[:50] for x in ['vless://', 'vmess://', 'ss://']):
                decoded = safe_base64_decode(content)
                if decoded: content = decoded
            
            matches = pattern.findall(content)
            found = 0
            for link in matches:
                clean = link.strip()
                if clean not in seen:
                    seen.add(clean); links.append(clean); found += 1
                if found >= MAX_LINKS_PER_SOURCE: break
            print(f"   ✅ +{found} с {url.split('/')[-2]}")
        except: pass
    
    return links

def add_labels(link, ip, info):
    country = info.get('country', ''); isp = info.get('isp', ''); flag = get_flag_emoji(country)
    bad_isps = ['amazon','aws','google','oracle','microsoft','azure','digitalocean','hetzner','m247','ovh','cloudflare']
    is_ai = country not in ['RU','BY','CN','IR','KP'] and not any(w in isp for w in bad_isps) and not link.startswith("ss://")
    ai_tag = " ✨ AI" if is_ai else ""
    try:
        if link.startswith("vmess://"):
            data = json.loads(safe_base64_decode(link[8:]))
            curr = re.sub(r'[^\w\s\d\-]', '', data.get('ps', 'v')).strip()
            data['ps'] = f"{flag}{ai_tag} {curr[:15]}"
            return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8'), data['ps']
        else:
            main, tag = link.split("#", 1) if "#" in link else (link, "Srv")
            tag = re.sub(r'[^\w\s\d\-]', '', unquote(tag)).strip()
            name = f"{flag}{ai_tag} {tag[:15]}"
            return f"{main}#{quote(name)}", name
    except: return link, "Proxy"

def link_to_clash(link, name):
    try:
        if link.startswith("vmess://"):
            data = json.loads(safe_base64_decode(link[8:]))
            return {'name': name, 'type': 'vmess', 'server': data.get('add'), 'port': int(data.get('port')), 'uuid': data.get('id'), 'alterId': 0, 'cipher': 'auto', 'udp': True, 'tls': data.get('tls')=='tls', 'skip-cert-verify': True, 'network': data.get('net', 'tcp')}
        if link.startswith("vless://") or link.startswith("trojan://"):
            parsed = urlparse(link); qs = parse_qs(parsed.query)
            proxy = {'name': name, 'type': 'vless' if link.startswith('vless') else 'trojan', 'server': parsed.hostname, 'port': int(parsed.port), 'uuid': parsed.username or parsed.password, 'password': parsed.username or parsed.password, 'udp': True, 'skip-cert-verify': True, 'tls': qs.get('security', [''])[0] in ['tls', 'reality'], 'network': qs.get('type', ['tcp'])[0]}
            if 'uuid' in proxy and link.startswith('trojan'): del proxy['uuid']
            if qs.get('security', [''])[0] == 'reality':
                proxy['servername'] = qs.get('sni', [''])[0]; proxy['reality-opts'] = {'public-key': qs.get('pbk', [''])[0], 'short-id': qs.get('sid', [''])[0]}; proxy['client-fingerprint'] = 'chrome'
            return proxy
        if link.startswith("ss://"):
            if "@" in link:
                main = link.split("#")[0]; p1 = main.split("@")[0].replace("ss://", ""); p2 = main.split("@")[1]
                try: dec = safe_base64_decode(p1); ciph, pw = dec.split(":", 1) if ":" in dec else (p1, "")
                except: ciph, pw = "aes-256-gcm", p1
                return {'name': name, 'type': 'ss', 'server': p2.split(":")[0], 'port': int(p2.split(":")[1].split("/")[0]), 'cipher': ciph, 'password': pw, 'udp': True}
    except: pass
    return None

async def process_all(links):
    print(f"🧐 Всего кандидатов: {len(links)}. Начинаем проверку (Timeout: {TIMEOUT}s)...")
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    items = []
    for link in links:
        ip, port = extract_ip_port(link)
        if ip and port: items.append((link, ip, port))
    
    async def verify(item):
        link, ip, port = item
        if await check_port(ip, port, semaphore): return (link, ip)
        return None

    # Перемешиваем, чтобы не брать всё из одного источника в начале
    import random; random.shuffle(items)
    
    results = await asyncio.gather(*(verify(i) for i in items))
    alive = [r for r in results if r is not None][:MAX_TOTAL_ALIVE]
    
    print(f"✅ Живых: {len(alive)}. Получаем GeoIP...")
    ip_info = batch_get_ip_info([x[1] for x in alive])
    
    final_links = []; clash_proxies = []
    for link, ip in alive:
        new_link, pretty_name = add_labels(link, ip, ip_info.get(ip, {}))
        final_links.append(new_link)
        clash_obj = link_to_clash(new_link, pretty_name)
        if clash_obj:
            while any(p['name'] == clash_obj['name'] for p in clash_proxies): clash_obj['name'] += "."
            clash_proxies.append(clash_obj)
    return final_links, clash_proxies

def main():
    raw_total = get_all_links()
    if not raw_total: return
    final_links, clash_data = asyncio.run(process_all(raw_total))
    
    with open("list.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_links).encode()).decode())
    with open("proxies.yaml", "w", encoding="utf-8") as f: yaml.dump({'proxies': clash_data}, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Готово! Всего серверов: {len(final_links)}")

if __name__ == "__main__":
    main()
