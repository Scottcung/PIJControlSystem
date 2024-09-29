def is_valid_ip(ip):
    """验证 IP 地址的有效性"""
    parts = ip.split('.')
    return (len(parts) == 4 and 
            all(part.isdigit() and 0 <= int(part) <= 255 for part in parts))
