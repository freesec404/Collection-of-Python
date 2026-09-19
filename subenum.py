#!/usr/bin/env python3
"""
subenum.py

从 domain.txt 读取前缀字典，对目标域名进行子域枚举（支持替换 www 的行为）
- 若 target 以 'www.' 开头，则用 prefix 替换掉左侧的 'www'，生成 <prefix>.<rest>
- 否则按 <prefix>.<target> 拼接
解析 DNS（A/AAAA）判断子域是否存在，并将结果写入 found.txt。

Usage:
    python3 subenum.py
    python3 subenum.py -w wordlist.txt -t www.lncc.edu.cn -o results.txt -p 100
"""

import argparse
import socket
import concurrent.futures
import time
import threading
from typing import Optional, Tuple, List

def parse_args():
    p = argparse.ArgumentParser(description="Subdomain enumerator with 'replace www' behavior and progress.")
    p.add_argument("-w", "--wordlist", default="domain.txt", help="子域名前缀字典文件（每行一个前缀）")
    p.add_argument("-t", "--target", default="www.lncc.edu.cn", help="目标域名（如 lncc.edu.cn 或 www.lncc.edu.cn）")
    p.add_argument("-o", "--output", default="found.txt", help="解析成功的子域输出文件")
    p.add_argument("-p", "--workers", type=int, default=50, help="并发线程数")
    p.add_argument("--timeout", type=float, default=3.0, help="DNS 解析超时（秒）")
    return p.parse_args()

def load_wordlist(path: str) -> List[str]:
    prefixes = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            prefixes.append(s)
    return prefixes

def resolve_host(host: str, timeout: float) -> Optional[Tuple[str, list]]:
    try:
        infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
        addrs = []
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            if ip not in addrs:
                addrs.append(ip)
        if addrs:
            return host, addrs
        return None
    except Exception:
        return None

def build_fqdn(prefix: str, target: str) -> str:
    """
    构建要解析的 FQDN：
    - 如果 prefix 看起来像完整域名并且以 target 结尾，则直接返回 prefix（避免重复拼接）。
    - 如果 target 以 'www.' 开头，则用 prefix 替换掉左侧的 'www' -> prefix.rest
    - 否则返回 prefix.target
    """
    prefix = prefix.strip()
    target = target.strip().strip('.')

    # 如果 prefix 是完整域名并且以 target 结尾（例如 prefix == "mail.lncc.edu.cn"），直接使用 prefix
    if "." in prefix and prefix.endswith(target):
        return prefix

    parts = target.split(".")
    if parts and parts[0].lower() == "www":
        # target 形如 www.example.com -> rest = example.com
        rest = ".".join(parts[1:]) if len(parts) > 1 else target
        fqdn = f"{prefix}.{rest}".strip(".")
    else:
        fqdn = f"{prefix}.{target}".strip(".")

    return fqdn

def worker(prefix: str, target: str, timeout: float) -> Optional[Tuple[str, list]]:
    fqdn = build_fqdn(prefix, target)
    return resolve_host(fqdn, timeout)

def format_progress(completed: int, total: int, found_count: int, start_time: float) -> str:
    elapsed = max(1e-6, time.time() - start_time)
    rate = completed / elapsed
    pct = (completed / total) * 100 if total else 0.0
    return f"Processed: {completed}/{total} ({pct:5.1f}%) | Found: {found_count} | Rate: {rate:5.2f} req/s | Elapsed: {int(elapsed)}s"

def main():
    args = parse_args()
    prefixes = load_wordlist(args.wordlist)
    if not prefixes:
        print(f"[!] 字典 {args.wordlist} 为空或未找到。")
        return

    total = len(prefixes)
    print(f"[+] 目标：{args.target}")
    print(f"[+] 词典：{args.wordlist}（{total} 条前缀）")
    print(f"[+] 并发线程：{args.workers}，解析超时：{args.timeout}s")
    print("[+] 开始枚举...（按 Ctrl+C 停止）")

    found = []
    start = time.time()

    lock = threading.Lock()
    completed = 0
    found_count = 0

    def done_callback(fut):
        nonlocal completed, found_count
        res = None
        try:
            res = fut.result(timeout=0)
        except Exception:
            res = None
        with lock:
            completed += 1
            if res:
                fqdn, addrs = res
                found.append((fqdn, addrs))
                found_count += 1
                print(f"\n[FOUND] {fqdn} -> {', '.join(addrs)}")
            prog = format_progress(completed, total, found_count, start)
            print("\r" + prog, end="", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as exe:
        futures = []
        try:
            for pref in prefixes:
                fut = exe.submit(worker, pref, args.target, args.timeout)
                fut.add_done_callback(done_callback)
                futures.append(fut)

            for fut in concurrent.futures.as_completed(futures):
                pass

        except KeyboardInterrupt:
            print("\n[!] 用户中断。正在收集已找到的结果...")
            for fut in futures:
                if not fut.done():
                    fut.cancel()
        except Exception as e:
            print(f"\n[!] 运行中出现异常：{e}")

    elapsed = time.time() - start
    print()
    print(f"[+] 枚举结束，用时 {elapsed:.2f}s，发现 {len(found)} 个可解析子域。")

    with open(args.output, "w", encoding="utf-8") as out:
        for fqdn, addrs in found:
            out.write(f"{fqdn} -> {', '.join(addrs)}\n")

    print(f"[+] 结果已保存到 {args.output}")

if __name__ == "__main__":
    main()
