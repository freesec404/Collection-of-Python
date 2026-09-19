#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart Traceroute Pro + GeoMap + AS-Level Topology + Smart Diagnosis v2
保存: trace_result.json, trace_map.html, as_topology.png
"""
from scapy.all import *
import threading, time, re, requests, statistics, json, os
import folium, networkx as nx, matplotlib.pyplot as plt

# ========== 配置 ==========
MAX_TTL = 30
TIMEOUT = 2
PROBE_COUNT = 3
MODE = "ICMP"
ENABLE_GEOIP = True
LOCK = threading.Lock()

# 存储结构: {ttl: [ {"ip":ip, "rtt":rtt, "geo":{...}, "latlon":... } , ... ] }
ROUTE_HISTORY = {}

# ================= utils =================
def is_valid_ipv4(addr: str) -> bool:
    pattern = r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$"
    return re.match(pattern, addr) is not None

def geoip_lookup(ip: str):
    """
    使用 ipinfo.io 获取 country, city, org, loc
    org 可能包含 'ASxxxxx Name'，我们会从中解析 ASN
    """
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        data = r.json()
        loc = data.get("loc", "")
        latlon = [float(x) for x in loc.split(",")] if loc else None
        org = data.get("org", "") or ""
        # 尝试提取 ASN：形如 "AS15169 Google LLC"
        asn = ""
        m = re.match(r"^(AS\d+)\s*(.*)$", org)
        if m:
            asn = m.group(1)
            as_name = m.group(2).strip()
        else:
            as_name = org
        return {
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "org": org,
            "asn": asn,
            "as_name": as_name,
            "latlon": latlon
        }
    except Exception as e:
        return {"country":"", "city":"", "org":"", "asn":"", "as_name":"", "latlon":None}

def build_probe(dst, ttl):
    if MODE.upper() == "UDP":
        return IP(dst=dst, ttl=ttl)/UDP(dport=33434)
    elif MODE.upper() == "TCP":
        return IP(dst=dst, ttl=ttl)/TCP(dport=80, flags="S")
    else:
        return IP(dst=dst, ttl=ttl)/ICMP()

# ================= core probing =================
def send_probe(dst, ttl, index):
    pkt = build_probe(dst, ttl)
    start = time.time()
    ans, _ = sr(pkt, verbose=0, timeout=TIMEOUT)
    end = time.time()
    rtt = (end - start) * 1000
    with LOCK:
        if ans:
            for snd, rcv in ans:
                ip = rcv.src
                geo = geoip_lookup(ip) if ENABLE_GEOIP else {}
                ROUTE_HISTORY.setdefault(ttl, []).append({
                    "ip": ip,
                    "rtt": rtt,
                    "geo": geo,
                    "latlon": geo.get("latlon")
                })
                print(f"{ttl:<3} {ip:<16} {rtt:>6.2f} ms  {geo.get('asn','')}/{geo.get('as_name','')} {geo.get('country','')}-{geo.get('city','')}")
                if ICMP in rcv and rcv[ICMP].type == 0:
                    print(f"\n🏁 到达目标 {dst} ，追踪结束。\n")
                    analyze_and_visualize(dst)
                    os._exit(0)
        else:
            ROUTE_HISTORY.setdefault(ttl, []).append({
                "ip": "*",
                "rtt": None,
                "geo": {},
                "latlon": None
            })
            print(f"{ttl:<3} * 请求超时")

def traceroute_run(dst):
    print(f"\n目标: {dst} | 模式: {MODE} | 探测次数: {PROBE_COUNT} | 最大TTL: {MAX_TTL}\n")
    threads = []
    for ttl in range(1, MAX_TTL + 1):
        for i in range(PROBE_COUNT):
            t = threading.Thread(target=send_probe, args=(dst, ttl, i))
            t.start()
            threads.append(t)
        time.sleep(0.25)
    for t in threads:
        t.join()
    analyze_and_visualize(dst)

# ================= Analysis + AS topology + Visualization =================
def build_as_path():
    """
    从 ROUTE_HISTORY 中为每个 TTL 取第一个非 '*' 响应的 ASN（如果有）
    返回 as_path (list of asn or None) 与 per_ttl_selected (list of dict)
    """
    as_path = []
    per_ttl_selected = {}
    for ttl in sorted(ROUTE_HISTORY.keys()):
        hops = ROUTE_HISTORY[ttl]
        selected = None
        # prefer first hop that has ASN info
        for h in hops:
            if h.get("ip") and h["ip"] != "*" and h.get("geo") and h["geo"].get("asn"):
                selected = h
                break
        # otherwise pick first non-* ip entry
        if not selected:
            for h in hops:
                if h.get("ip") and h["ip"] != "*":
                    selected = h
                    break
        per_ttl_selected[ttl] = selected
        asn = selected["geo"].get("asn") if selected and selected.get("geo") else None
        as_path.append(asn)
    return as_path, per_ttl_selected

def build_as_graph(per_ttl_selected):
    """
    根据 per_ttl_selected 构造 AS-Level graph (networkx)
    节点使用 ASN (如果缺失则使用 ip)
    """
    G = nx.DiGraph()
    prev_node = None
    ttl_nodes = {}  # ttl -> chosen node label
    for ttl in sorted(per_ttl_selected.keys()):
        sel = per_ttl_selected[ttl]
        if not sel:
            ttl_nodes[ttl] = None
            prev_node = None
            continue
        asn = sel["geo"].get("asn") if sel.get("geo") else None
        label = asn if asn else sel["ip"]
        # add node with metadata
        G.add_node(label, ip=sel.get("ip"), as_name=sel.get("geo", {}).get("as_name",""), country=sel.get("geo", {}).get("country",""))
        ttl_nodes[ttl] = label
        if prev_node and label:
            if not G.has_edge(prev_node, label):
                G.add_edge(prev_node, label, ttls=[])
            G[prev_node][label]['ttls'].append(ttl)
        prev_node = label
    return G, ttl_nodes

def draw_as_topology(G, out_png="as_topology.png"):
    """
    使用 networkx + matplotlib 保存 AS-Level 拓扑图
    """
    plt.figure(figsize=(10,6))
    pos = nx.spring_layout(G, k=0.5, seed=42)
    # drawing nodes with sizes by degree
    degrees = dict(G.degree())
    node_sizes = [300 + (degrees[n]*100) for n in G.nodes()]
    nx.draw_networkx_nodes(G, pos, node_size=node_sizes)
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=12)
    labels = {n: n for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, font_size=8)
    plt.title("AS-Level Topology (nodes labelled by ASN or IP)")
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()
    print(f"📁 AS-Level 拓扑图已保存: {out_png}")

def visualize_on_map(per_ttl_selected, out_html="trace_map.html"):
    """
    在 folium 地图上标注每跳（按 ASN 聚合），连线显示路径。
    当 latlon 缺失时跳过该点。
    """
    hop_points = []
    for ttl in sorted(per_ttl_selected.keys()):
        sel = per_ttl_selected[ttl]
        if not sel:
            continue
        latlon = sel.get("latlon")
        if latlon:
            hop_points.append({
                "ttl": ttl,
                "ip": sel.get("ip"),
                "rtt": sel.get("rtt"),
                "latlon": latlon,
                "asn": sel.get("geo", {}).get("asn",""),
                "as_name": sel.get("geo", {}).get("as_name",""),
                "country": sel.get("geo", {}).get("country","")
            })
    if not hop_points:
        print("⚠️ 没有可用经纬度数据，跳过地图可视化。")
        return None

    # start map centered at first point
    m = folium.Map(location=hop_points[0]["latlon"], zoom_start=3, tiles="OpenStreetMap")
    # create per-AS groupings for layer control
    as_groups = {}
    points = []
    for h in hop_points:
        lat, lon = h["latlon"]
        popup = (f"TTL {h['ttl']}<br>IP: {h['ip']}<br>RTT: {'' if h['rtt'] is None else f'{h['rtt']:.2f} ms'}<br>"
                 f"ASN: {h['asn']} {h['as_name']}<br>Country: {h['country']}")
        grp_name = h['asn'] or "Unknown-AS"
        if grp_name not in as_groups:
            as_groups[grp_name] = folium.FeatureGroup(name=grp_name)
        folium.CircleMarker(location=[lat, lon], radius=6, popup=popup, fill=True).add_to(as_groups[grp_name])
        points.append((lat, lon))
    # add AS groups
    for grp in as_groups.values():
        grp.add_to(m)
    # draw polyline across points in sequence
    folium.PolyLine(points, color="red", weight=2.5, opacity=0.8).add_to(m)
    folium.LayerControl().add_to(m)
    m.save(out_html)
    print(f"🗺️ 地图已生成: {out_html}")
    return out_html

# ================= Smart Diagnosis v2 =================
def smart_diagnosis(as_path, per_ttl_selected):
    """
    更智能的诊断:
    - 检测 AS 切换点（TTL在哪些位置从一个AS换到另一个AS）
    - 检测 AS 循环（AS A -> B -> A）
    - 检测高延迟跃迁（AS 切换时延显著上升）
    - 检测 AS 不稳定（同 TTL 出现多个 ASN）
    输出诊断建议
    """
    print("\n🧠 Smart Diagnosis v2 报告:")
    # AS stability per TTL
    for ttl, hops in ROUTE_HISTORY.items():
        seen_as = set()
        for h in hops:
            asn = h.get("geo", {}).get("asn") if h.get("geo") else None
            if asn:
                seen_as.add(asn)
        if len(seen_as) > 1:
            print(f"⚠️ TTL {ttl} 在多次探测中发现不同 ASN：{', '.join(seen_as)} -> 可能存在跨 AS 的负载均衡或路径抖动。")

    # build simple AS path ignoring Nones
    simple_as = [a for a in as_path if a]
    # detect consecutive duplicates removed
    compact = []
    for a in simple_as:
        if not compact or a != compact[-1]:
            compact.append(a)

    # detect AS loops (A..B..A)
    loops = []
    for i in range(len(compact)):
        for j in range(i+2, len(compact)):
            if compact[i] == compact[j]:
                loops.append((compact[i], i, j))
    if loops:
        print(f"⚠️ 发现 AS 循环: {loops}，可能说明回路或迷路路径（或多路径导致的虚假环）")

    # detect AS transitions and RTT jumps
    print("\n🔎 AS transition / RTT jump analysis:")
    prev_as = None
    prev_avg_rtt = None
    for ttl in sorted(per_ttl_selected.keys()):
        sel = per_ttl_selected[ttl]
        if not sel:
            continue
        asn = sel.get("geo", {}).get("asn")
        avg_rtt = None
        # compute avg rtt for this ttl
        rtts = [h.get("rtt") for h in ROUTE_HISTORY.get(ttl, []) if h.get("rtt")]
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
        if prev_as and asn and asn != prev_as:
            print(f"→ TTL {ttl-1} ({prev_as}) -> TTL {ttl} ({asn}) : AS 切换")
            if prev_avg_rtt and avg_rtt:
                diff = avg_rtt - prev_avg_rtt
                if diff > 80:
                    print(f"   ⚠️ RTT 大幅上升 {diff:.1f} ms，可能为跨境出口或国际链路")
        prev_as = asn or prev_as
        prev_avg_rtt = avg_rtt or prev_avg_rtt

    # suggestions
    print("\n📋 建议:")
    if loops:
        print("- 检查是否存在 MPLS/ISP 内部回环或策略路由；尝试使用不同模式（TCP/UDP）复测以验证。")
    print("- 若遇到跨 AS 的高延迟点，建议从不同时间段、多次采样确认稳定性。")
    print("- 多次出现不同 ASN 的 TTL 建议做更高次数采样以确认是否为负载均衡/任何cast routing。")
    print("- 如需持续监控，加入定时追踪并对比历史 trace_result.json 可发现长期趋势。")

# ================= Analyze & save =================
def analyze_and_visualize(dst):
    print("\n📊 高级路径分析报告（同时生成 AS 拓扑与地图）：")
    # basic per-ttl stats
    for ttl, hops in sorted(ROUTE_HISTORY.items()):
        ips = [h["ip"] for h in hops if h["ip"] and h["ip"] != "*"]
        unique_ips = list(dict.fromkeys(ips))
        if not unique_ips:
            print(f"TTL {ttl:<2} | 无响应")
            continue
        rtts = [h["rtt"] for h in hops if h.get("rtt")]
        avg = (sum(rtts)/len(rtts)) if rtts else None
        stdev = (statistics.stdev(rtts) if len(rtts) > 1 else 0) if rtts else None
        asns = list({h.get("geo", {}).get("asn") for h in hops if h.get("geo") and h.get("geo").get("asn")})
        print(f"TTL {ttl:<2} | IPs: {', '.join(unique_ips)} | ASN(s): {', '.join([a for a in asns if a]) or 'N/A'} | avgRTT={'' if avg is None else f'{avg:.2f}ms'} ±{'' if stdev is None else f'{stdev:.2f}'}")

    # save json
    with open("trace_result.json", "w", encoding="utf-8") as f:
        json.dump(ROUTE_HISTORY, f, indent=4, ensure_ascii=False)
    print("\n📁 结果已保存: trace_result.json")

    # build AS path and per-ttl selection
    as_path, per_ttl_selected = build_as_path()

    # build AS graph
    G, ttl_nodes = build_as_graph(per_ttl_selected)
    if len(G.nodes()) > 0:
        draw_as_topology(G, out_png="as_topology.png")
    else:
        print("⚠️ 无 AS 节点，跳过 AS 拓扑图生成。")

    # folium map with AS grouping
    visualize_on_map(per_ttl_selected, out_html="trace_map.html")

    # smart diagnosis
    smart_diagnosis(as_path, per_ttl_selected)

# ================= main =================
if __name__ == "__main__":
    print("=== Smart Traceroute Pro - AS Level + SmartDiagnosis v2 ===")
    dst = input("请输入目标 IPv4 地址（如 8.8.8.8）：").strip()
    while not is_valid_ipv4(dst):
        print("❌ 无效地址，请重试")
        dst = input("请输入目标 IPv4 地址：").strip()
    traceroute_run(dst)
