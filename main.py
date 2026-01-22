

import requests
from bs4 import BeautifulSoup
import re
import base64
import json
import asyncio
from urllib.parse import urlparse, unquote, parse_qs, quote
import yaml # pip install pyyaml

# --- НАСТРОЙКИ ---


# --- НАСТРОЙКИ ---
CHANNELS = [
    "shadowsockskeys",
    "oneclickvpnkeys",
    "v2ray_outlineir",
    "v2ray_free_conf"
]
MSG_LIMIT = 600
TIMEOUT = 2
GEOIP_BATCH_SIZE = 100

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def safe_base64_decode(s):
    s = s.strip()
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    try:
        return base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
    except:
        return None

def get_flag_emoji(country_code):
    if not country_code: return ""
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())

def batch_get_countries(ips):
    if not ips: return {}
    unique_ips = list(set(ips))
    ip_map = {}
    for i in range(0, len(unique_ips), GEOIP_BATCH_SIZE):
        batch = unique_ips[i:i + GEOIP_BATCH_SIZE]
        try:
            resp = requests.post(
                "http://ip-api.com/batch", 
                json=[{"query": ip, "fields": "countryCode"} for ip in batch],
                timeout=10
            )
            data = resp.json()
            for idx, result in enumerate(data):
                if 'countryCode' in result:
                    flag = get_flag_emoji(result['countryCode'])
                    original_ip = batch[idx]
                    ip_map[original_ip] = flag
        except Exception as e:
            print(f"⚠️ Ошибка GeoIP API: {e}")
    return ip_map

async def check_port(ip, port):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def extract_ip_port(link):
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            decoded = safe_base64_decode(b64)
            if decoded:
                data = json.loads(decoded)
                return data.get('add'), int(data.get('port'))
            return None, None
        
        parsed = urlparse(link)
        if link.startswith("ss://") and "@" in link:
            part = link.split("@")[-1]
            ip_port = part.split("/")[0].split("?")[0].split("#")[0]
            if ":" in ip_port:
                ip = ip_port.split(":")[0].replace("[", "").replace("]", "")
                port = int(ip_port.split(":")[1])
                return ip, port
            return None, None

        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port
        return None, None
    except:
        return None, None

# --- ПАРСЕР ДЛЯ CLASH (Самое сложное) ---
def link_to_clash_proxy(link):
    """Превращает ссылку в словарь для Clash"""
    try:
        # 1. VMESS
        if link.startswith("vmess://"):
            data = json.loads(safe_base64_decode(link[8:]))
            proxy = {
                'name': data.get('ps', 'vmess'),
                'type': 'vmess',
                'server': data.get('add'),
                'port': int(data.get('port')),
                'uuid': data.get('id'),
                'alterId': int(data.get('aid', 0)),
                'cipher': 'auto',
                'udp': True
            }
            if data.get('net'):
                proxy['network'] = data.get('net')
                if data.get('net') == 'ws':
                    proxy['ws-opts'] = {'path': data.get('path', '/'), 'headers': {'Host': data.get('host', '')}}
            if data.get('tls') == 'tls':
                proxy['tls'] = True
                proxy['skip-cert-verify'] = True
            return proxy

        # 2. VLESS & TROJAN
        if link.startswith("vless://") or link.startswith("trojan://"):
            parsed = urlparse(link)
            qs = parse_qs(parsed.query)
            
            proxy = {
                'name': unquote(parsed.fragment) if parsed.fragment else 'vless',
                'type': 'vless' if link.startswith('vless') else 'trojan',
                'server': parsed.hostname,
                'port': parsed.port,
                'uuid': parsed.username, # для trojan это password
                'udp': True,
                'skip-cert-verify': True
            }
            
            if link.startswith('trojan'):
                proxy['password'] = parsed.username
                del proxy['uuid']

            # Flow (Reality / Vision)
            if 'flow' in qs and qs['flow'][0]:
                proxy['flow'] = qs['flow'][0]
            
            # TLS / Reality
            if qs.get('security', [''])[0] == 'reality':
                proxy['tls'] = True
                proxy['servername'] = qs.get('sni', [''])[0]
                proxy['reality-opts'] = {
                    'public-key': qs.get('pbk', [''])[0],
                    'short-id': qs.get('sid', [''])[0]
                }
                if 'fp' in qs: proxy['client-fingerprint'] = qs['fp'][0]
            elif qs.get('security', [''])[0] == 'tls':
                proxy['tls'] = True
                if 'sni' in qs: proxy['servername'] = qs['sni'][0]
            
            # Transport
            net = qs.get('type', ['tcp'])[0]
            proxy['network'] = net
            if net == 'ws':
                proxy['ws-opts'] = {'path': qs.get('path', ['/'])[0]}
                if 'host' in qs: proxy['ws-opts'].setdefault('headers', {})['Host'] = qs['host'][0]
            if net == 'grpc':
                proxy['grpc-opts'] = {'grpc-service-name': qs.get('serviceName', [''])[0]}
                
            return proxy

        # 3. SHADOWSOCKS
        if link.startswith("ss://"):
            # Формат user:pass@ip:port
            if "@" in link:
                main = link.split("#")[0]
                name = unquote(link.split("#")[1]) if "#" in link else "SS"
                
                # Попытка декодировать base64 часть (cipher:pass)
                part1 = main.split("@")[0].replace("ss://", "")
                part2 = main.split("@")[1]
                
                # Если part1 это base64
                try:
                    decoded = safe_base64_decode(part1)
                    if ":" in decoded:
                        cipher, password = decoded.split(":", 1)
                    else:
                        return None # Нестандартный формат
                except:
                    # Бывает новый формат без base64
                    if ":" in part1:
                        cipher, password = part1.split(":", 1)
                    else: return None

                ip = part2.split(":")[0]
                port = int(part2.split(":")[1].split("/")[0])
                
                proxy = {
                    'name': name,
                    'type': 'ss',
                    'server': ip,
                    'port': port,
                    'cipher': cipher,
                    'password': password,
                    'udp': True
                }
                return proxy
            
        return None # Остальное пока скипаем (Hysteria и т.д. сложнее)
    except Exception as e:
        # print(f"Error parsing link for Clash: {e}")
        return None

# --- ОСНОВНАЯ ЛОГИКА ---

def get_raw_links():
    links = set()
    pattern = re.compile(r'(?:vless|vmess|ss|trojan)://[^ \n<]+')
    for channel in CHANNELS:
        print(f"🔍 Парсинг {channel}...")
        try:
            url = f"https://t.me/s/{channel}"
            resp = requests.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            messages = soup.find_all('div', class_='tgme_widget_message_text')
            for msg in messages[-MSG_LIMIT:]:
                found = pattern.findall(msg.get_text())
                for link in found:
                    clean = link.strip().rstrip('.,<>"\')]}')
                    links.add(clean)
        except Exception as e:
            print(f"⚠️ Ошибка {channel}: {e}")
    return list(links)

def add_flag_to_link_and_get_name(link, ip, flag):
    """
    Добавляет флаг в ссылку И возвращает красивое имя для Clash
    """
    name = "Proxy"
    new_link = link
    
    try:
        # VMESS
        if link.startswith("vmess://"):
            b64 = link[8:]
            decoded = safe_base64_decode(b64)
            if decoded:
                data = json.loads(decoded)
                curr = data.get('ps', 'vmess')
                if flag and flag not in curr:
                    curr = f"{flag} {curr}"
                    data['ps'] = curr
                name = curr
                new_link = "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        
        # Остальные
        else:
            if "#" in link:
                main, tag = link.split("#", 1)
                tag = unquote(tag)
                if flag and flag not in tag:
                    tag = f"{flag} {tag}"
                name = tag
                new_link = f"{main}#{quote(tag)}"
            else:
                name = f"{flag} Server" if flag else "Server"
                new_link = f"{link}#{quote(name)}"
                
    except:
        pass
        
    return new_link, name

async def process_all(links):
    print(f"🧐 Найдено {len(links)} ссылок. Проверяем...")
    
    tasks = []
    items = [] # (link, ip, port)

    for link in links:
        ip, port = extract_ip_port(link)
        if ip and port:
            items.append((link, ip, port))
    
    async def verify(item):
        link, ip, port = item
        if await check_port(ip, port):
            return (link, ip)
        return None

    results = await asyncio.gather(*(verify(i) for i in items))
    alive = [r for r in results if r is not None]
    
    print(f"✅ Живых: {len(alive)}. Получаем флаги...")
    
    ips = [x[1] for x in alive]
    ip_flags = batch_get_countries(ips)
    
    final_links_list = []
    clash_proxies = []
    
    for link, ip in alive:
        flag = ip_flags.get(ip, "")
        
        # 1. Обновляем ссылку (добавляем флаг)
        new_link, pretty_name = add_flag_to_link_and_get_name(link, ip, flag)
        final_links_list.append(new_link)
        
        # 2. Создаем объект для Clash
        clash_obj = link_to_clash_proxy(new_link)
        if clash_obj:
            # Обновляем имя в объекте клэша, чтобы оно совпадало
            clash_obj['name'] = pretty_name
            # Важно: имена в Clash должны быть уникальными!
            # Если имя дублируется, добавим цифру
            while any(p['name'] == clash_obj['name'] for p in clash_proxies):
                clash_obj['name'] += f"_{len(clash_proxies)}"
                
            clash_proxies.append(clash_obj)
            
    return final_links_list, clash_proxies

def main():
    raw = get_raw_links()
    if not raw: return

    final_links, clash_data = asyncio.run(process_all(raw))
    
    if not final_links:
        print("❌ Все мертвые")
        return

    # 1. Сохраняем sub.txt (Base64)
    with open("list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_links))
    b64 = base64.b64encode("\n".join(final_links).encode()).decode()
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(b64)
        
    # 2. Сохраняем clash.yaml
    # Структура конфига
    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': clash_data,
        'proxy-groups': [
            {
                'name': '🚀 Auto Select',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': [p['name'] for p in clash_data]
            },
            {
                'name': '🌍 Proxy',
                'type': 'select',
                'proxies': ['🚀 Auto Select'] + [p['name'] for p in clash_data]
            }
        ],
        'rules': [
            'MATCH,🌍 Proxy'
        ]
    }
    
    # Записываем YAML (нужен pyyaml)
    with open("clash.yaml", "w", encoding="utf-8") as f:
        # allow_unicode=True чтобы флаги и русские буквы не ломались
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        
    print(f"🎉 Готово! Сохранено {len(final_links)} ссылок и {len(clash_data)} прокси для Clash.")

if __name__ == "__main__":
    main()
