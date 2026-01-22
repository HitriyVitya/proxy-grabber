
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

# Теперь это РЕАЛЬНО сработает (будет листать назад)
MSG_LIMIT = 300 

# Таймаут проверки порта
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
    # Лимит для ip-api бесплатного
    print(f"🌍 Определяем страны для {len(unique_ips)} IP...")
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
            # Небольшая пауза, чтобы не забанили API
            time.sleep(0.5)
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

# --- ГЛУБОКИЙ ПАРСИНГ (С Листалкой) ---
def get_raw_links():
    links = set()
    pattern = re.compile(r'(?:vless|vmess|ss|trojan|hysteria|hysteria2|hy2|tuic)://[^ \n<]+')
    
    for channel in CHANNELS:
        print(f"🔍 Канал: {channel}")
        channel_links = 0
        
        # Начинаем с главной страницы
        url = f"https://t.me/s/{channel}"
        
        while True:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200: break
                
                soup = BeautifulSoup(resp.text, 'html.parser')
                messages = soup.find_all('div', class_='tgme_widget_message_text')
                
                if not messages: break
                
                # Ищем ссылки в сообщениях
                for msg in messages:
                    # Некоторые ссылки могут быть внутри тега <a> с href, а некоторые текстом
                    text = msg.get_text()
                    found = pattern.findall(text)
                    for link in found:
                        clean = link.strip().rstrip('.,<>"\')]}')
                        links.add(clean)
                        channel_links += 1
                        
                    # Также проверим href аттрибуты (иногда ссылка спрятана под словом)
                    for a in msg.find_all('a', href=True):
                        href = a['href']
                        if pattern.match(href):
                            links.add(href)
                            channel_links += 1

                # Проверка лимита на канал
                if channel_links >= MSG_LIMIT:
                    print(f"   -> Достигнут лимит ({channel_links} ссылок). Стоп.")
                    break
                
                # ПАГИНАЦИЯ: Ищем ссылку на "Предыдущие посты"
                # Обычно это <a class="tme_messages_more" href="/s/channel?before=123">
                more_tag = soup.find('a', class_='tme_messages_more')
                
                if more_tag and 'href' in more_tag.attrs:
                    next_url = "https://t.me" + more_tag['href']
                    # Если ссылка та же самая (зациклились), выходим
                    if next_url == url: break
                    url = next_url
                    # print(f"   -> Листаем историю назад... Найдено пока: {channel_links}")
                else:
                    print(f"   -> Конец истории канала.")
                    break
                    
            except Exception as e:
                print(f"⚠️ Ошибка парсинга {channel}: {e}")
                break
        
        print(f"   ✅ Итого с канала {channel}: {channel_links}")

    return list(links)

def add_flag_to_link_and_get_name(link, ip, flag):
    name = "Proxy"
    new_link = link
    try:
        if link.startswith("vmess://"):
            b64 = link[8:]
            decoded = safe_base64_decode(b64)
            if decoded:
                data = json.loads(decoded)
                curr = data.get('ps', 'vmess')
                # Удаляем старые флаги если есть, чтобы не было 🇩🇪 🇩🇪 Server
                curr = re.sub(r'[^\w\s\d\-\(\)\[\]]', '', curr).strip()
                name = f"{flag} {curr}" if flag else curr
                data['ps'] = name
                new_link = "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        else:
            if "#" in link:
                main, tag = link.split("#", 1)
                tag = unquote(tag)
                tag = re.sub(r'[^\w\s\d\-\(\)\[\]]', '', tag).strip()
                name = f"{flag} {tag}" if flag else tag
                new_link = f"{main}#{quote(name)}"
            else:
                name = f"{flag} Server" if flag else "Server"
                new_link = f"{link}#{quote(name)}"
    except: pass
    return new_link, name

def link_to_clash_proxy(link):
    """Упрощенный конвертер, чтобы не падал"""
    try:
        if link.startswith("vmess://"):
            data = json.loads(safe_base64_decode(link[8:]))
            return {
                'name': data.get('ps', 'vmess'),
                'type': 'vmess',
                'server': data.get('add'),
                'port': int(data.get('port')),
                'uuid': data.get('id'),
                'alterId': int(data.get('aid', 0)),
                'cipher': 'auto',
                'udp': True,
                'tls': True if data.get('tls') == 'tls' else False,
                'skip-cert-verify': True,
                'network': data.get('net', 'tcp'),
                'ws-opts': {'path': data.get('path', '/'), 'headers': {'Host': data.get('host', '')}} if data.get('net') == 'ws' else None
            }
        
        if link.startswith("vless://") or link.startswith("trojan://"):
            parsed = urlparse(link)
            qs = parse_qs(parsed.query)
            proxy = {
                'name': unquote(parsed.fragment) if parsed.fragment else 'vless',
                'type': 'vless' if link.startswith('vless') else 'trojan',
                'server': parsed.hostname,
                'port': parsed.port,
                'uuid': parsed.username,
                'udp': True,
                'skip-cert-verify': True,
                'tls': True if qs.get('security', [''])[0] in ['tls', 'reality'] else False,
                'network': qs.get('type', ['tcp'])[0]
            }
            if link.startswith('trojan'):
                proxy['password'] = parsed.username
                del proxy['uuid']
            
            if qs.get('security', [''])[0] == 'reality':
                proxy['servername'] = qs.get('sni', [''])[0]
                proxy['reality-opts'] = {'public-key': qs.get('pbk', [''])[0], 'short-id': qs.get('sid', [''])[0]}
                proxy['client-fingerprint'] = qs.get('fp', ['chrome'])[0]
            elif proxy['tls'] and 'sni' in qs:
                proxy['servername'] = qs['sni'][0]
                
            if proxy['network'] == 'ws':
                proxy['ws-opts'] = {'path': qs.get('path', ['/'])[0]}
                if 'host' in qs: proxy['ws-opts'].setdefault('headers', {})['Host'] = qs['host'][0]
            if proxy['network'] == 'grpc':
                proxy['grpc-opts'] = {'grpc-service-name': qs.get('serviceName', [''])[0]}
            return proxy

        if link.startswith("ss://"):
            if "@" in link:
                main = link.split("#")[0]
                name = unquote(link.split("#")[1]) if "#" in link else "SS"
                part1 = main.split("@")[0].replace("ss://", "")
                part2 = main.split("@")[1]
                try:
                    decoded = safe_base64_decode(part1)
                    cipher, password = decoded.split(":", 1) if ":" in decoded else part1.split(":", 1)
                except:
                    cipher, password = part1.split(":", 1) if ":" in part1 else ("aes-256-gcm", part1)
                
                ip = part2.split(":")[0]
                port = int(part2.split(":")[1].split("/")[0])
                return {
                    'name': name, 'type': 'ss', 'server': ip, 'port': port,
                    'cipher': cipher, 'password': password, 'udp': True
                }
        return None
    except: return None

async def process_all(links):
    print(f"🧐 Всего найдено {len(links)} уникальных ссылок. Начинаем прозвон...")
    tasks = []
    items = [] 
    for link in links:
        ip, port = extract_ip_port(link)
        if ip and port: items.append((link, ip, port))
    
    async def verify(item):
        link, ip, port = item
        if await check_port(ip, port): return (link, ip)
        return None

    # Пингуем
    results = await asyncio.gather(*(verify(i) for i in items))
    alive = [r for r in results if r is not None]
    
    print(f"✅ Живых серверов: {len(alive)}. Получаем флаги...")
    
    ips = [x[1] for x in alive]
    ip_flags = batch_get_countries(ips)
    
    final_links_list = []
    clash_proxies = []
    
    for link, ip in alive:
        flag = ip_flags.get(ip, "")
        new_link, pretty_name = add_flag_to_link_and_get_name(link, ip, flag)
        final_links_list.append(new_link)
        
        clash_obj = link_to_clash_proxy(new_link)
        if clash_obj:
            clash_obj['name'] = pretty_name
            # Уникальность имен
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
        # Очищаем файлы
        for f_name in ["list.txt", "sub.txt", "proxies.yaml"]:
            with open(f_name, "w", encoding="utf-8") as f: f.write("")
        return

    # 1. list.txt
    with open("list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_links))
        
    # 2. sub.txt
    b64 = base64.b64encode("\n".join(final_links).encode()).decode()
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(b64)
        
    # 3. proxies.yaml
    clash_provider = {'proxies': clash_data}
    with open("proxies.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_provider, f, allow_unicode=True, sort_keys=False)
        
    print(f"🎉 Готово! Живых: {len(final_links)}. Файлы обновлены.")

if __name__ == "__main__":
    main()
