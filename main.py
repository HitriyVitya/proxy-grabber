import requests
from bs4 import BeautifulSoup
import re
import base64
import json
import asyncio
from urllib.parse import urlparse, unquote, quote

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

def add_flag_to_link(link, ip, flag):
    if not flag: return link
    try:
        if link.startswith("vmess://"):
            b64_part = link[8:]
            decoded = safe_base64_decode(b64_part)
            if decoded:
                data = json.loads(decoded)
                current_name = data.get('ps', 'vmess')
                if flag not in current_name:
                    data['ps'] = f"{flag} {current_name}"
                new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
                return f"vmess://{new_b64}"
        else:
            if "#" in link:
                main_part, name = link.split("#", 1)
                name = unquote(name)
                if flag not in name:
                    new_name = f"{flag} {name}"
                    return f"{main_part}#{quote(new_name)}"
            else:
                return f"{link}#{quote(flag + ' Server')}"
        return link
    except:
        return link

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
            b64_part = link[8:]
            decoded = safe_base64_decode(b64_part)
            if decoded:
                data = json.loads(decoded)
                return data.get('add'), int(data.get('port'))
            return None, None

        parsed = urlparse(link)
        if link.startswith("ss://") and "@" in link:
            part_after_at = link.split("@")[-1]
            ip_port = part_after_at.split("/")[0].split("?")[0].split("#")[0]
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

def get_raw_links():
    links = set()
    # ВОТ ТУТ БЫЛА ОШИБКА. Добавил ?: в начале скобок.
    # Это значит "Не захватывай группу отдельно, бери всё вместе".
    pattern = re.compile(r'(?:vless|vmess|ss|ssr|trojan|hy2|hysteria|hysteria2|tuic)://[^ \n<]+')

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

async def filter_and_rename(links):
    print(f"🧐 Найдено {len(links)} ссылок (сырых). Проверяем...")
    if len(links) > 0:
        print(f"👀 Пример ссылки: {links[0][:50]}...")
    
    tasks = []
    candidates = []
    unchecked = []

    for link in links:
        ip, port = extract_ip_port(link)
        if ip and port:
            candidates.append((link, ip, port))
        else:
            unchecked.append(link)

    async def verify(item):
        link, ip, port = item
        is_alive = await check_port(ip, port)
        return (link, ip) if is_alive else None

    results = await asyncio.gather(*(verify(c) for c in candidates))
    
    alive_entries = [res for res in results if res is not None]
    alive_ips = [entry[1] for entry in alive_entries]
    
    print(f"✅ Живых по пингу: {len(alive_entries)}. Определяем страны...")
    
    ip_to_flag = batch_get_countries(alive_ips)
    final_links = []
    
    for link, ip in alive_entries:
        flag = ip_to_flag.get(ip, "")
        new_link = add_flag_to_link(link, ip, flag)
        final_links.append(new_link)
        
    final_links.extend(unchecked)
    return final_links

def main():
    raw = get_raw_links()
    if not raw:
        print("❌ Пусто. Возможно, регулярка не сработала или каналы пустые.")
        return

    final_list = asyncio.run(filter_and_rename(raw))
    
    if not final_list:
        print("❌ Все найденные ссылки мертвые.")
        # Очищаем файл, чтобы не висело старье
        with open("sub.txt", "w", encoding="utf-8") as f: f.write("")
        with open("list.txt", "w", encoding="utf-8") as f: f.write("")
        return

    # Сохраняем
    with open("list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_list))
        
    b64 = base64.b64encode("\n".join(final_list).encode()).decode()
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(b64)
        
    print(f"🎉 Готово! Сохранено {len(final_list)} конфигов.")

if __name__ == "__main__":
    main()
