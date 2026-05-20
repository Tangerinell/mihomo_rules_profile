import urllib.request
import urllib.parse
import ipaddress
import os

# 目标 Tracker 列表地址 (支持多个)
URLS = [
    "https://cf.trackerslist.com/all.txt",
    "https://raw.githubusercontent.com/adysec/tracker/refs/heads/main/trackers_all.txt" # 示例: 可以在此按格式继续添加
]
# 输出的 Mihomo 规则集文件名
OUTPUT_FILE = "trackers.yaml"

def main():
    # 伪装 User-Agent，防止被 Cloudflare 拦截
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    all_lines = []
    # 遍历获取所有链接中的内容
    for url in URLS:
        print(f"正在获取: {url}")
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8')
                all_lines.extend(content.splitlines())
        except Exception as e:
            print(f"获取 {url} 失败: {e}")

    domains = set()
    ips = set()

    # 逐行解析 URL
    for line in all_lines:
        line = line.strip()
        if not line:
            continue
        
        try:
            # 提取 hostname (例如 udp://tracker.opentrackr.org:1337/announce -> tracker.opentrackr.org)
            parsed = urllib.parse.urlparse(line)
            hostname = parsed.hostname
            if not hostname:
                continue
            
            # 清理 IPv6 地址可能携带的方括号
            hostname = hostname.strip('[]')
            
            # 判断是 IP 还是 域名
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ips.add(hostname)
            except ValueError:
                # 解析失败说明是域名
                domains.add(hostname)
        except Exception:
            pass

    # 构建 Mihomo classical 格式的规则集
    yaml_lines = ["payload:"]
    
    for domain in sorted(domains):
        yaml_lines.append(f"  - DOMAIN-SUFFIX,{domain}")
        
    for ip in sorted(ips):
        if ':' in ip:
            yaml_lines.append(f"  - IP-CIDR6,{ip}/128")
        else:
            yaml_lines.append(f"  - IP-CIDR,{ip}/32")

    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(yaml_lines) + '\n')
        
    print(f"成功生成 {OUTPUT_FILE}！包含 {len(domains)} 个域名和 {len(ips)} 个 IP。")

if __name__ == "__main__":
    main()