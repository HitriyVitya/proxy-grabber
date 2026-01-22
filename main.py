
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
    "v2ray_outlineir",  # Из твоего скрина
    "v2ray_free_conf",  # Из твоего скрина         # Добавил от себя (жирный)
    "iSeqaro",          # Тоже жирный
]


# Лимиты, чтобы скрипт не сдох по таймауту
MAX_LINKS_PER_CHANNEL = 150 # Сколько ссылок сосать с одного канала
MAX_PAGES_PER_CHANNEL = 10  # Сколько раз нажимать "Load more"
MAX_TOTAL_ALIVE = 200       # Сколько живых оставить в итоге (самых свежих)

TIMEOUT = 2
GEOIP_BATCH_SIZE = 100
CONCURRENCY_LIMIT = 50      # Проверять не более 50 серверов одновременно

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def safe_base64_decode(s):
    s = s.strip()
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try: return base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
    except: return None

def get_flag_emoji(country_code):
    if not country_code: return ""
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())

def batch_get_countries(ips):
    if not ips: return {}
    unique_ips = list(set(ips))
    ip_map = {}
    print(f"🌍 GeoIP для {len(unique_ips)} IP...")
    for i in range(0, len(unique_ips), GEOIP_BATCH_SIZE):
        batch = unique_ips[i:i + GEOIP_BATCH_SIZE]
        try:
            resp = requests.post("http://ip-api.com/batch", 
                               json=[{"query": ip, "fields": "countryCode"} for ip in batch], timeout=10)
            data = resp.json()
            for idx, result in enumerate(data):
                if 'countryCode' in result:
                    ip_map[batch[idx]] = get_flag_emoji(result['countryCode'])
        except Exception as e: print(f"⚠️ GeoIP Error: {e}")
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
            b64 = link[8:]
            decoded = safe_base64_decode(b64)
            if decoded:
                data = json.loads(decoded)
                return data.get('add'), int(data.get('port'))
        parsed = urlparse(link)
        if link.startswith("ss://") and "@" in link:
            part = link.split("@")[-1].split("/")[0].split("?")[0].split("#")[0]
            if ":" in part: return part.split(":")[0].replace("[", "").replace("]", ""), int(part.split(":")[1])
        if parsed.hostname and parsed.port: return parsed.hostname, parsed.port
    except: pass
    return None, None

# --- ПАРСИНГ ---
def get_raw_links():
    links = []
    pattern = re.compile(r'(?:vless|vmess|ss|trojan|hysteria|hysteria2|hy2|tuic)://[^ \n<]+')
    
    for channel in CHANNELS:
        print(f"🔍 Канал: {channel}")
        url = f"https://t.me/s/{channel}"
        found_in_channel = 0
        pages = 0
        
        while pages < MAX_PAGES_PER_CHANNEL:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200: break
                soup = BeautifulSoup(resp.text, 'html.parser')
                messages = soup.find_all('div', class_='tgme_widget_message_text')
                if not messages: break
                
                # Собираем ссылки с текущей страницы (с конца, т.к. они свежее)
                for msg in reversed(messages):
                    text = msg.get_text()
                    matches = pattern.findall(text)
                    for link in matches:
                        clean = link.strip().rstrip('.,<>"\')]}')
                        if clean not in links:
                            links.append(clean)
                            found_in_channel += 1
                    if found_in_channel >= MAX_LINKS_PER_CHANNEL: break
                
                if found_in_channel >= MAX_LINKS_PER_CHANNEL: break
                
                more_tag = soup.find('a', class_='tme_messages_more')
                if more_tag and 'href' in more_tag.attrs:
                    url = "https://t.me" + more_tag['href']
                    pages += 1
                else: break
            except: break
        print(f"   ✅ Взято {found_in_channel} ссылок.")
    return links

def add_flag_to_link_and_get_name(link, ip, flag):
    name = "Proxy"
    new_link = link
    try:
        if link.startswith("vmess://"):
            data = json.loads(safe_base64_decode(link[8:]))
            curr = re.sub(r'[^\w\s\d\-]', '', data.get('ps', 'vmess')).strip()
            name = f"{flag} {curr}" if flag else curr
            data['ps'] = name
            new_link = "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        else:
            main, tag = link.split("#", 1) if "#" in link else (link, "Server")
            tag = re.sub(r'[^\w\s\d\-]', '', unquote(tag)).strip()
            name = f"{flag} {tag}" if flag else tag
            new_link = f"{main}#{quote(name)}"
    except: pass
    return new_link, name

def link_to_clash_proxy(link):
    try:
        if link.startswith("vmess://"):
            data = json.loads(safe_base64_decode(link[8:]))
            return {'name': data.get('ps', 'v'), 'type': 'vmess', 'server': data.get('add'), 'port': int(data.get('port')), 'uuid': data.get('id'), 'alterId': 0, 'cipher': 'auto', 'udp': True, 'tls': data.get('tls')=='tls', 'skip-cert-verify': True, 'network': data.get('net', 'tcp')}
        if link.startswith("vless://") or link.startswith("trojan://"):
            parsed = urlparse(link); qs = parse_qs(parsed.query)
            proxy = {'name': unquote(parsed.fragment) or 'v', 'type': 'vless' if link.startswith('vless') else 'trojan', 'server': parsed.hostname, 'port': parsed.port, 'uuid': parsed.username, 'password': parsed.username, 'udp': True, 'skip-cert-verify': True, 'tls': qs.get('security', [''])[0] in ['tls', 'reality'], 'network': qs.get('type', ['tcp'])[0]}
            if 'uuid' in proxy and link.startswith('trojan'): del proxy['uuid']
            if qs.get('security', [''])[0] == 'reality':
                proxy['servername'] = qs.get('sni', [''])[0]; proxy['reality-opts'] = {'public-key': qs.get('pbk', [''])[0], 'short-id': qs.get('sid', [''])[0]}; proxy['client-fingerprint'] = 'chrome'
            return proxy
        if link.startswith("ss://"):
            if "@" in link:
                main = link.split("#")[0]; name = unquote(link.split("#")[1]) if "#" in link else "SS"
                p1 = main.split("@")[0].replace("ss://", ""); p2 = main.split("@")[1]
                try: dec = safe_base64_decode(p1); ciph, pw = dec.split(":", 1) if ":" in dec else (p1, "")
                except: ciph, pw = "aes-256-gcm", p1
                return {'name': name, 'type': 'ss', 'server': p2.split(":")[0], 'port': int(p2.split(":")[1].split("/")[0]), 'cipher': ciph, 'password': pw, 'udp': True}
    except: pass
    return None

async def process_all(links):
    print(f"🧐 Проверка {len(links)} ссылок...")
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    items = []
    for link in links:
        ip, port = extract_ip_port(link)
        if ip and port: items.append((link, ip, port))
    
    async def verify(item):
        link, ip, port = item
        if await check_port(ip, port, semaphore): return (link, ip)
        return None

    results = await asyncio.gather(*(verify(i) for i in items))
    alive = [r for r in results if r is not None]
    
    # Оставляем только самые свежие
    alive = alive[:MAX_TOTAL_ALIVE]
    print(f"✅ Живых: {len(alive)}. Получаем флаги...")
    
    ip_flags = batch_get_countries([x[1] for x in alive])
    final_links = []; clash_proxies = []
    
    for link, ip in alive:
        flag = ip_flags.get(ip, "")
        new_link, pretty_name = add_flag_to_link_and_get_name(link, ip, flag)
        final_links.append(new_link)
        clash_obj = link_to_clash_proxy(new_link)
        if clash_obj:
            clash_obj['name'] = pretty_name
            while any(p['name'] == clash_obj['name'] for p in clash_proxies):
                clash_obj['name'] += " "
            clash_proxies.append(clash_obj)
    return final_links, clash_proxies

def main():
    raw = get_raw_links()
    if not raw: return
    final_links, clash_data = asyncio.run(process_all(raw))
    with open("list.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_links).encode()).decode())
    with open("proxies.yaml", "w", encoding="utf-8") as f: yaml.dump({'proxies': clash_data}, f, allow_unicode=True, sort_keys=False)
    print(f"🎉 Готово!")

if __name__ == "__main__":
    main()
