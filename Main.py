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

MSG_LIMIT = 500 
TIMEOUT = 2

# Ограничение для API (ip-api.com разрешает 15 запросов в минуту, мы делаем пачками по 100)
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
    """Превращает 'RU' в '🇷🇺'"""
    if not country_code: return ""
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())

def batch_get_countries(ips):
    """
    Получает страны для списка IP через ip-api.com (Batch mode).
    Возвращает словарь {ip: flag_emoji}
    """
    if not ips: return {}
    
    unique_ips = list(set(ips))
    ip_map = {}
    
    # Разбиваем на пачки по 100 (лимит API)
    for i in range(0, len(unique_ips), GEOIP_BATCH_SIZE):
        batch = unique_ips[i:i + GEOIP_BATCH_SIZE]
        try:
            # Формируем запрос
            resp = requests.post(
                "http://ip-api.com/batch", 
                json=[{"query": ip, "fields": "countryCode"} for ip in batch],
                timeout=10
            )
            data = resp.json()
            # Сопоставляем
            for idx, result in enumerate(data):
                if 'countryCode' in result:
                    flag = get_flag_emoji(result['countryCode'])
                    original_ip = batch[idx]
                    ip_map[original_ip] = flag
        except Exception as e:
            print(f"⚠️ Ошибка GeoIP API: {e}")
            
    return ip_map

def add_flag_to_link(link, ip, flag):
    """Добавляет флаг в название конфига"""
    if not flag: return link
    
    try:
        # 1. VMESS (JSON внутри Base64)
        if link.startswith("vmess://"):
            b64_part = link[8:]
            decoded = safe_base64_decode(b64_part)
            if decoded:
                data = json.loads(decoded)
                # Добавляем флаг к имени (поле ps)
                current_name = data.get('ps', 'vmess')
                # Проверяем, нет ли уже флага, чтобы не дублировать
                if flag not in current_name:
                    data['ps'] = f"{flag} {current_name}"
                    
                # Кодируем обратно
                new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
                return f"vmess://{new_b64}"

        # 2. SS / VLESS / TROJAN и прочие (где имя после #)
        else:
            if "#" in link:
                main_part, name = link.split("#", 1)
                name = unquote(name) # Декодируем %20 и прочее
                if flag not in name:
                    new_name = f"{flag} {name}"
                    return f"{main_part}#{quote(new_name)}"
            else:
                # Если имени нет, создаем
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
    pattern = re.compile(r'(vless|vmess|ss|ssr|trojan|hy2|hysteria|hysteria2|tuic)://[^ \n<]+')

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
                    links.add(link.strip().rstrip('.,<>"\')]}'))
        except Exception as e:
            print(f"⚠️ Ошибка {channel}: {e}")
            
    return list(links)

async def filter_and_rename(links):
    print(f"🧐 Найдено {len(links)} ссылок. Проверяем пинг...")
    
    tasks = []
    # Храним кортеж: (ссылка, ip, port)
    candidates = []
    
    # Список, который мы не можем проверить и переименовать (сложные ссылки)
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

    # Пингуем
    results = await asyncio.gather(*(verify(c) for c in candidates))
    
    # Собираем живые IP для GeoIP запроса
    alive_entries = [res for res in results if res is not None] # Список (link, ip)
    alive_ips = [entry[1] for entry in alive_entries]
    
    print(f"✅ Живых: {len(alive_entries)}. Определяем страны...")
    
    # Определяем страны ОПТОМ
    ip_to_flag = batch_get_countries(alive_ips)
    
    final_links = []
    
    # Переименовываем
    for link, ip in alive_entries:
        flag = ip_to_flag.get(ip, "")
        # Добавляем флаг в ссылку
        new_link = add_flag_to_link(link, ip, flag)
        final_links.append(new_link)
        
    # Добавляем непроверенные (их не переименовываем, т.к. не знаем IP)
    final_links.extend(unchecked)
    
    return final_links

def main():
    raw = get_raw_links()
    if not raw:
        print("❌ Пусто.")
        return

    final_list = asyncio.run(filter_and_rename(raw))
    
    # Сохраняем
    with open("list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_list))
        
    b64 = base64.b64encode("\n".join(final_list).encode()).decode()
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(b64)
        
    print(f"🎉 Готово! Сохранено {len(final_list)} конфигов с флагами.")

if __name__ == "__main__":
    main()