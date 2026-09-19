import json
import yaml

# 1. Чтение исходного JSON
with open('raw_config.json', 'r', encoding='utf-8') as f:
    raw_configs = json.load(f)

ru_proxies = []
foreign_proxies = []

# Словарь для исключения дубликатов
seen_keys = set()

# Ключевые слова для определения RU нод
ru_keywords = ["россия", "белые списки", "для заграницы", "🇷🇺", "wl-"]

# 2. Парсинг массива конфигураций
for cfg in raw_configs:
    remark = cfg.get("remarks", "").lower()
    outbounds = cfg.get("outbounds", [])
    
    for outbound in outbounds:
        protocol = outbound.get("protocol")
        
        # Парсим VLESS
        if protocol == "vless":
            try:
                vnext = outbound["settings"]["vnext"][0]
                user = vnext["users"][0]
                stream = outbound.get("streamSettings", {})
                reality = stream.get("realitySettings", {})
                tag = outbound.get("tag", "VLESS")
                
                # Игнорируем технические служебные тэги
                if tag in ["direct", "block", "dns-out"] or "to-" in tag:
                    continue

                server_addr = vnext["address"]
                server_port = int(vnext["port"])
                
                # Проверка на дубликаты
                node_key = f"{server_addr}:{server_port}:{user['id']}"
                if node_key in seen_keys:
                    continue
                seen_keys.add(node_key)

                # Название ноды (комбинация remarks и tag)
                node_name = cfg.get("remarks", tag)
                if cfg.get("remarks") and tag not in ["proxy", "candidate"]:
                    node_name = f"{cfg.get('remarks')} ({tag})"

                node = {
                    "name": node_name,
                    "type": "vless",
                    "server": server_addr,
                    "port": server_port,
                    "uuid": user["id"],
                    "udp": True,
                    "tls": stream.get("security") in ["tls", "reality"],
                    "skip-cert-verify": True,
                    "network": stream.get("network", "tcp")
                }
                
                if user.get("flow"):
                    node["flow"] = user["flow"]
                    
                if stream.get("security") == "reality":
                    node["servername"] = reality.get("serverName", "")
                    node["reality-opts"] = {
                        "public-key": reality.get("publicKey", "")
                    }
                    if reality.get("shortId"):
                        node["reality-opts"]["short-id"] = reality["shortId"]
                    if reality.get("fingerprint"):
                        node["client-fingerprint"] = reality["fingerprint"]
                
                # Разделение по категориям
                if any(kw in remark for kw in ru_keywords) or any(kw in tag.lower() for kw in ru_keywords):
                    ru_proxies.append(node)
                else:
                    foreign_proxies.append(node)

            except Exception:
                continue

        # Парсим Hysteria2
        elif protocol == "hysteria":
            try:
                tag = outbound.get("tag", "Hysteria")
                server_addr = outbound["settings"]["address"]
                server_port = int(outbound["settings"]["port"])
                
                node_key = f"{server_addr}:{server_port}"
                if node_key in seen_keys:
                    continue
                seen_keys.add(node_key)

                stream = outbound.get("streamSettings", {})
                tls = stream.get("tlsSettings", {})

                node = {
                    "name": cfg.get("remarks", tag),
                    "type": "hysteria2",
                    "server": server_addr,
                    "port": server_port,
                    "auth": stream.get("hysteriaSettings", {}).get("auth", ""),
                    "sni": tls.get("serverName", ""),
                    "skip-cert-verify": True
                }

                if any(kw in remark for kw in ru_keywords):
                    ru_proxies.append(node)
                else:
                    foreign_proxies.append(node)
            except Exception:
                continue

# Фолбэки, если одна из категорий оказалась пустой
if not foreign_proxies:
    foreign_proxies = ru_proxies
if not ru_proxies:
    ru_proxies = foreign_proxies

# 3. Функция генерации конфигов Clash
def build_clash_config(proxy_list, rules):
    proxy_names = [p["name"] for p in proxy_list]
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxy_list,
        "proxy-groups": [
            {
                "name": "PROXIES",
                "type": "select",
                "proxies": ["AUTO"] + proxy_names
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "http://cp.cloudflare.com/generate_204",
                "interval": 300,
                "proxies": proxy_names
            }
        ],
        "rules": rules
    }

# Наборы правил
rules_split = [
    "GEOIP,private,DIRECT",
    "GEOIP,lan,DIRECT",
    "GEOSITE,category-ru,DIRECT",
    "GEOIP,ru,DIRECT",
    "MATCH,PROXIES"
]

rules_all_proxy = [
    "GEOIP,private,DIRECT",
    "GEOIP,lan,DIRECT",
    "MATCH,PROXIES"
]

rules_ru_for_abroad = [
    "GEOIP,private,DIRECT",
    "GEOIP,lan,DIRECT",
    "GEOSITE,category-ru,PROXIES",
    "GEOIP,ru,PROXIES",
    "MATCH,DIRECT"
]

# 4. Сборка трех конфигураций
cfg_1 = build_clash_config(foreign_proxies, rules_split)
cfg_2 = build_clash_config(ru_proxies, rules_all_proxy)
cfg_3 = build_clash_config(ru_proxies, rules_ru_for_abroad)

# 5. Сохранение результатов
with open("sub_split.yml", "w", encoding="utf-8") as f:
    yaml.dump(cfg_1, f, allow_unicode=True, sort_keys=False)

with open("sub_all_proxy.yml", "w", encoding="utf-8") as f:
    yaml.dump(cfg_2, f, allow_unicode=True, sort_keys=False)

with open("sub_ru_for_abroad.yml", "w", encoding="utf-8") as f:
    yaml.dump(cfg_3, f, allow_unicode=True, sort_keys=False)

# Дефолтный sub.yml (Split-режим)
with open("sub.yml", "w", encoding="utf-8") as f:
    yaml.dump(cfg_1, f, allow_unicode=True, sort_keys=False)

print(f"Готово! Зарубежных серверов: {len(foreign_proxies)}, RU серверов: {len(ru_proxies)}")
