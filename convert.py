import json
import yaml

# 1. Загружаем исходный JSON
try:
    with open("raw_config.json", "r", encoding="utf-8") as f:
        raw = json.load(f)
except Exception as e:
    print(f"Ошибка чтения raw_config.json: {e}")
    raw = []

proxies = []
seen_names = {}

# 2. Извлекаем VLESS ноды
for item in raw:
    outbounds = item.get("outbounds", [])
    for out in outbounds:
        if out.get("protocol") == "vless":
            vnext = out.get("settings", {}).get("vnext", [{}])[0]
            user = vnext.get("users", [{}])[0]
            stream = out.get("streamSettings", {})
            reality = stream.get("realitySettings", {})
            
            raw_name = out.get("tag", "VLESS-Node").strip()
            
            if raw_name in seen_names:
                seen_names[raw_name] += 1
                unique_name = f"{raw_name} - {seen_names[raw_name]}"
            else:
                seen_names[raw_name] = 1
                unique_name = raw_name
            
            node = {
                "name": unique_name,
                "type": "vless",
                "server": vnext.get("address"),
                "port": int(vnext.get("port")),
                "uuid": user.get("id"),
                "udp": True,
                "tls": stream.get("security") in ["tls", "reality"],
                "network": stream.get("network", "tcp")
            }
            
            if user.get("flow"):
                node["flow"] = user.get("flow")
                
            if stream.get("security") == "reality":
                node["reality-opts"] = {}
                if reality.get("publicKey"):
                    node["reality-opts"]["public-key"] = reality.get("publicKey")
                if reality.get("shortId"):
                    node["reality-opts"]["short-id"] = reality.get("shortId")
                if reality.get("serverName"):
                    node["servername"] = reality.get("serverName")
                if reality.get("fingerprint"):
                    node["client-fingerprint"] = reality.get("fingerprint")

            proxies.append(node)

proxy_names = [p["name"] for p in proxies]

# 3. Собираем итоговую конфигурацию Clash Meta с блоком DNS
clash_config = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "dns": {
        "enable": True,
        "listen": "0.0.0.0:5353",
        "enhanced-mode": "fake-ip",
        "nameserver": [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        ],
        "fallback": [
            "tls://1.0.0.1:853",
            "tls://8.8.4.4:853"
        ]
    },
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "PROXIES",
            "type": "select",
            "proxies": ["AUTO"] + proxy_names
        },
        {
            "name": "AUTO",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": proxy_names
        }
    ],
    "rules": [
        "GEOIP,LAN,DIRECT",
        "MATCH,PROXIES"
    ]
}

# 4. Записываем в sub.yml
with open("sub.yml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

print(f"Успешно обработано нод: {len(proxies)}")
