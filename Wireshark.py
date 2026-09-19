import pyshark
import time
import numpy as np
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import json
import logging
from datetime import datetime
import ipaddress
import socket
import threading


class AdvancedPortScanDetector:
    def __init__(self, config=None):
        # 默认配置
        self.config = {
            'interface': 'eth0',
            'scan_window': 60,  # 检测时间窗口(秒)
            'vertical_threshold': 30,  # 垂直扫描的端口阈值
            'horizontal_threshold': 20,  # 水平扫描的IP阈值
            'syn_completion_threshold': 0.2,  # SYN握手完成率阈值
            'connect_duration_threshold': 1.0,  # 全连接扫描的持续时间阈值(秒)
            'udp_port_threshold': 50,  # UDP扫描的端口阈值
            'udp_response_threshold': 0.3,  # UDP响应比例阈值
            'max_workers': 4,  # 线程池大小
            'log_level': 'INFO',  # 日志级别
            'whitelist': ['8.8.8.8', '1.1.1.1'],  # IP白名单
            'network_scope': '192.168.0.0/16',  # 监控的网络范围
            'output_file': 'scan_detections.json'  # 输出文件
        }

        # 更新用户自定义配置
        if config:
            self.config.update(config)

        # 设置日志
        logging.basicConfig(
            level=getattr(logging, self.config['log_level']),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('PortScanDetector')

        # 解析网络范围
        self.network_scope = ipaddress.ip_network(self.config['network_scope'], strict=False)
        self.logger.info(f"监控网络范围: {self.network_scope}")

        # 初始化数据结构
        self.reset_detectors()
        self.detections = []
        self.last_cleanup = time.time()

        # 创建数据包捕获
        self.capture = pyshark.LiveCapture(
            interface=self.config['interface'],
            display_filter='tcp or udp or icmp',
            custom_parameters={'-l': None}  # 实时刷新输出
        )

        # 统计锁
        self.lock = threading.Lock()

    def reset_detectors(self):
        """重置所有检测器的状态"""
        # SYN扫描检测器 - 垂直扫描
        self.syn_vertical_scans = defaultdict(
            lambda: {'ports': set(), 'syn_time': [], 'synack_count': 0}
        )

        # SYN扫描检测器 - 水平扫描
        self.syn_horizontal_scans = defaultdict(
            lambda: {'targets': set(), 'syn_time': [], 'synack_count': 0}
        )

        # TCP全连接扫描检测器
        self.connect_scans = defaultdict(
            lambda: {'connections': {}, 'start_time': []}
        )

        # UDP扫描检测器
        self.udp_scans = defaultdict(
            lambda: {'ports': set(), 'sent_time': [], 'response_count': 0}
        )

        # 可疑IP标记
        self.suspicious_ips = set()

    def is_whitelisted(self, ip):
        """检查IP是否在白名单中"""
        return ip in self.config['whitelist']

    def is_in_scope(self, ip):
        """检查IP是否在监控范围内"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj in self.network_scope
        except ValueError:
            return False

    def calculate_entropy(self, data):
        """计算数据分布的熵值"""
        if not data:
            return 0.0

        # 确保数据是整数
        try:
            int_data = [int(x) for x in data]
            counts = np.bincount(int_data)
            probs = counts / counts.sum()
            return -np.sum(probs * np.log2(probs + 1e-10))
        except Exception:
            return 0.0

    def cleanup_old_entries(self):
        """清理过期的记录"""
        current_time = time.time()
        window = self.config['scan_window']

        # 清理SYN垂直扫描记录
        for src_ip in list(self.syn_vertical_scans.keys()):
            data = self.syn_vertical_scans[src_ip]
            data['syn_time'] = [
                t for t in data['syn_time']
                if current_time - t < window
            ]
            if not data['syn_time']:
                del self.syn_vertical_scans[src_ip]

        # 清理SYN水平扫描记录
        for src_ip in list(self.syn_horizontal_scans.keys()):
            data = self.syn_horizontal_scans[src_ip]
            data['syn_time'] = [
                t for t in data['syn_time']
                if current_time - t < window
            ]
            if not data['syn_time']:
                del self.syn_horizontal_scans[src_ip]

        # 清理TCP全连接扫描记录
        for src_ip in list(self.connect_scans.keys()):
            # 清理过期连接
            active_conns = {}
            for conn_id, conn_data in self.connect_scans[src_ip]['connections'].items():
                if current_time - conn_data['start_time'] < window:
                    active_conns[conn_id] = conn_data

            self.connect_scans[src_ip]['connections'] = active_conns
            self.connect_scans[src_ip]['start_time'] = [
                t for t in self.connect_scans[src_ip]['start_time']
                if current_time - t < window
            ]

            if not self.connect_scans[src_ip]['start_time']:
                del self.connect_scans[src_ip]

        # 清理UDP扫描记录
        for src_ip in list(self.udp_scans.keys()):
            data = self.udp_scans[src_ip]
            data['sent_time'] = [
                t for t in data['sent_time']
                if current_time - t < window
            ]
            if not data['sent_time']:
                del self.udp_scans[src_ip]

        self.last_cleanup = current_time
        self.logger.debug("清理过期记录完成")

    def detect_syn_scan(self, pkt):
        """检测SYN扫描(半开扫描)"""
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            if not self.is_in_scope(dst_ip) or self.is_whitelisted(src_ip):
                return

            # 检测SYN包(第一次握手)
            if hasattr(pkt.tcp, 'flags_syn') and pkt.tcp.flags_syn == '1' and \
                    hasattr(pkt.tcp, 'flags_ack') and pkt.tcp.flags_ack == '0':
                dst_port = int(pkt.tcp.dstport)

                # 使用锁保护共享资源
                with self.lock:
                    # 垂直扫描记录：同一目标IP的不同端口
                    self.syn_vertical_scans[src_ip]['ports'].add(dst_port)
                    self.syn_vertical_scans[src_ip]['syn_time'].append(time.time())

                    # 水平扫描记录：同一目标端口的不同目标IP
                    self.syn_horizontal_scans[src_ip]['targets'].add(dst_ip)
                    self.syn_horizontal_scans[src_ip]['syn_time'].append(time.time())

                    # 可疑特征检测
                    if hasattr(pkt.ip, 'ttl'):
                        try:
                            ttl = int(pkt.ip.ttl)
                            if ttl not in range(30, 65):
                                self.suspicious_ips.add(src_ip)
                                self.logger.debug(f"可疑TTL值: {src_ip} TTL={ttl}")
                        except ValueError:
                            pass

            # 检测SYN/ACK响应(第二次握手)
            elif hasattr(pkt.tcp, 'flags_syn') and pkt.tcp.flags_syn == '1' and \
                    hasattr(pkt.tcp, 'flags_ack') and pkt.tcp.flags_ack == '1':
                scanner_ip = pkt.ip.dst  # 响应包的目标IP是扫描器

                with self.lock:
                    if scanner_ip in self.syn_vertical_scans:
                        self.syn_vertical_scans[scanner_ip]['synack_count'] += 1
                    if scanner_ip in self.syn_horizontal_scans:
                        self.syn_horizontal_scans[scanner_ip]['synack_count'] += 1
        except AttributeError as e:
            self.logger.debug(f"SYN扫描检测属性错误: {e}")
        except Exception as e:
            self.logger.error(f"SYN扫描检测出错: {e}")

    def detect_connect_scan(self, pkt):
        """检测TCP全连接扫描"""
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            if not self.is_in_scope(dst_ip) or self.is_whitelisted(src_ip):
                return

            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
            conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

            # 检测连接建立(第三次握手完成)
            if hasattr(pkt.tcp, 'flags_syn') and pkt.tcp.flags_syn == '0' and \
                    hasattr(pkt.tcp, 'flags_ack') and pkt.tcp.flags_ack == '1':
                # 检查是否完成了三次握手
                if 'tcp' in pkt and hasattr(pkt.tcp, 'analysis_acks_frame'):
                    with self.lock:
                        self.connect_scans[src_ip]['connections'][conn_id] = {
                            'start_time': time.time(),
                            'end_time': None,
                            'dst_port': dst_port,
                            'dst_ip': dst_ip
                        }
                        self.connect_scans[src_ip]['start_time'].append(time.time())

            # 检测连接关闭(RST或FIN)
            if (hasattr(pkt.tcp, 'flags_reset') and pkt.tcp.flags_reset == '1') or \
                    (hasattr(pkt.tcp, 'flags_fin') and pkt.tcp.flags_fin == '1'):
                with self.lock:
                    if src_ip in self.connect_scans and conn_id in self.connect_scans[src_ip]['connections']:
                        conn_data = self.connect_scans[src_ip]['connections'][conn_id]
                        if conn_data['end_time'] is None:
                            conn_data['end_time'] = time.time()
        except AttributeError as e:
            self.logger.debug(f"全连接扫描检测属性错误: {e}")
        except Exception as e:
            self.logger.error(f"全连接扫描检测出错: {e}")

    def detect_udp_scan(self, pkt):
        """检测UDP扫描"""
        try:
            # 处理UDP探测包
            if 'UDP' in pkt:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                if not self.is_in_scope(dst_ip) or self.is_whitelisted(src_ip):
                    return

                dst_port = int(pkt.udp.dstport)

                with self.lock:
                    self.udp_scans[src_ip]['ports'].add(dst_port)
                    self.udp_scans[src_ip]['sent_time'].append(time.time())

            # 处理ICMP端口不可达响应
            elif 'ICMP' in pkt:
                if hasattr(pkt.icmp, 'type') and pkt.icmp.type == '3' and \
                        hasattr(pkt.icmp, 'code') and pkt.icmp.code == '3':
                    # 提取原始UDP包信息
                    if hasattr(pkt.icmp, 'data_ip_src') and hasattr(pkt.icmp, 'data_udp_dstport'):
                        scanner_ip = pkt.icmp.data_ip_src
                        if self.is_whitelisted(scanner_ip):
                            return

                        dst_port = int(pkt.icmp.data_udp_dstport)

                        with self.lock:
                            if scanner_ip in self.udp_scans:
                                self.udp_scans[scanner_ip]['response_count'] += 1
        except AttributeError as e:
            self.logger.debug(f"UDP扫描检测属性错误: {e}")
        except Exception as e:
            self.logger.error(f"UDP扫描检测出错: {e}")

    def analyze_packet(self, pkt):
        """分析单个数据包"""
        try:
            if 'IP' not in pkt:
                return

            # 定期清理旧数据
            if time.time() - self.last_cleanup > self.config['scan_window'] / 2:
                with self.lock:
                    self.cleanup_old_entries()

            # 分派到对应的检测器
            if 'TCP' in pkt:
                self.detect_syn_scan(pkt)
                self.detect_connect_scan(pkt)
            elif 'UDP' in pkt or 'ICMP' in pkt:
                self.detect_udp_scan(pkt)

        except Exception as e:
            self.logger.error(f"处理数据包时出错: {e}", exc_info=True)

    def run_detection(self):
        """运行扫描检测逻辑"""
        current_time = time.time()
        window = self.config['scan_window']

        # 使用锁保护共享资源
        with self.lock:
            # SYN垂直扫描检测
            for src_ip in list(self.syn_vertical_scans.keys()):
                data = self.syn_vertical_scans[src_ip]
                port_count = len(data['ports'])
                syn_count = len(data['syn_time'])

                if syn_count == 0:
                    continue

                completion_ratio = data['synack_count'] / syn_count

                # 计算端口熵值
                try:
                    port_entropy = self.calculate_entropy(list(data['ports']))
                except Exception:
                    port_entropy = 0.0

                # 检查是否达到检测阈值
                if port_count >= self.config['vertical_threshold'] and \
                        completion_ratio < self.config['syn_completion_threshold']:

                    scan_type = "Vertical"
                    if port_entropy > 4.0:
                        scan_type += " | Stealth Random"
                    if src_ip in self.suspicious_ips:
                        scan_type += " | Suspicious TTL"

                    detection = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': src_ip,
                        'scan_type': f"SYN Scan ({scan_type})",
                        'scanned_ports': port_count,
                        'completion_rate': completion_ratio,
                        'port_entropy': port_entropy,
                        'evidence': sorted(data['ports'])[:10]  # 只显示前10个端口
                    }
                    self.detections.append(detection)
                    self.logger.warning(
                        f"检测到垂直扫描: {src_ip} 扫描端口数: {port_count} "
                        f"半开率: {completion_ratio:.1%} 熵值: {port_entropy:.2f}"
                    )
                    del self.syn_vertical_scans[src_ip]  # 避免重复报告

            # SYN水平扫描检测
            for src_ip in list(self.syn_horizontal_scans.keys()):
                data = self.syn_horizontal_scans[src_ip]
                target_count = len(data['targets'])
                syn_count = len(data['syn_time'])

                if syn_count == 0:
                    continue

                completion_ratio = data['synack_count'] / syn_count

                # 检查是否达到检测阈值
                if target_count >= self.config['horizontal_threshold'] and \
                        completion_ratio < self.config['syn_completion_threshold']:

                    scan_type = "Horizontal"
                    if src_ip in self.suspicious_ips:
                        scan_type += " | Suspicious TTL"

                    detection = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': src_ip,
                        'scan_type': f"SYN Scan ({scan_type})",
                        'scanned_targets': target_count,
                        'completion_rate': completion_ratio,
                        'evidence': sorted(data['targets'])[:5]  # 只显示前5个目标
                    }
                    self.detections.append(detection)
                    self.logger.warning(
                        f"检测到水平扫描: {src_ip} 扫描目标数: {target_count} "
                        f"半开率: {completion_ratio:.1%}"
                    )
                    del self.syn_horizontal_scans[src_ip]  # 避免重复报告

            # TCP全连接扫描检测
            for src_ip in list(self.connect_scans.keys()):
                data = self.connect_scans[src_ip]
                port_count = len(set([c['dst_port'] for c in data['connections'].values() if 'dst_port' in c]))
                short_conns = 0
                total_conns = len(data['connections'])

                for conn_id, conn_data in data['connections'].items():
                    if conn_data['end_time'] is not None:
                        duration = conn_data['end_time'] - conn_data['start_time']
                        if duration < self.config['connect_duration_threshold']:
                            short_conns += 1

                if port_count > self.config['vertical_threshold'] and short_conns / port_count > 0.8:
                    detection = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': src_ip,
                        'scan_type': "TCP Connect Scan",
                        'scanned_ports': port_count,
                        'short_connections': short_conns,
                        'total_connections': total_conns,
                        'evidence': sorted(set([c['dst_port'] for c in data['connections'].values()]))[:10]
                    }
                    self.detections.append(detection)
                    self.logger.warning(f"检测到TCP全连接扫描: {src_ip} 扫描端口数: {port_count}")
                    del self.connect_scans[src_ip]

            # UDP扫描检测
            for src_ip in list(self.udp_scans.keys()):
                data = self.udp_scans[src_ip]
                port_count = len(data['ports'])
                udp_count = len(data['sent_time'])

                if udp_count == 0:
                    continue

                response_ratio = data['response_count'] / udp_count

                if (port_count >= self.config['udp_port_threshold'] and
                        response_ratio > self.config['udp_response_threshold']):
                    detection = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': src_ip,
                        'scan_type': "UDP Scan",
                        'scanned_ports': port_count,
                        'response_rate': response_ratio,
                        'evidence': sorted(data['ports'])[:10]
                    }
                    self.detections.append(detection)
                    self.logger.warning(
                        f"检测到UDP扫描: {src_ip} 扫描端口数: {port_count} 响应率: {response_ratio:.1%}")
                    del self.udp_scans[src_ip]

    def save_detections(self):
        """保存检测结果到文件"""
        if not self.detections:
            return

        try:
            with open(self.config['output_file'], 'a') as f:
                for detection in self.detections:
                    f.write(json.dumps(detection) + '\n')
            self.logger.info(f"保存 {len(self.detections)} 条检测结果到 {self.config['output_file']}")
            self.detections = []  # 清空已保存的结果
        except Exception as e:
            self.logger.error(f"保存检测结果失败: {e}")

    def start(self):
        """开始捕获和分析流量"""
        self.logger.info("启动端口扫描检测器")
        self.logger.info(f"监听接口: {self.config['interface']}")
        self.logger.info(f"检测配置: 垂直阈值={self.config['vertical_threshold']}端口, "
                         f"水平阈值={self.config['horizontal_threshold']}目标")

        try:
            # 使用线程池处理数据包
            with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                last_detection_time = 0
                last_save_time = 0

                for pkt in self.capture.sniff_continuously():
                    executor.submit(self.analyze_packet, pkt)

                    current_time = time.time()
                    # 每5秒运行一次检测逻辑
                    if current_time - last_detection_time >= 5:
                        self.run_detection()
                        last_detection_time = current_time

                    # 每30秒保存一次结果
                    if current_time - last_save_time >= 30:
                        self.save_detections()
                        last_save_time = current_time

        except KeyboardInterrupt:
            self.logger.info("捕获终止")
        except Exception as e:
            self.logger.critical(f"捕获过程中发生严重错误: {e}", exc_info=True)
        finally:
            self.save_detections()
            self.logger.info("端口扫描检测器已停止")


if __name__ == "__main__":
    # 自定义配置示例
    custom_config = {
        'interface': 'en0',  # macOS常用接口
        'vertical_threshold': 20,  # 垂直扫描阈值
        'horizontal_threshold': 15,  # 水平扫描阈值
        'log_level': 'DEBUG',
        'whitelist': ['192.168.1.1', '10.0.0.1'],  # 添加本地网关
        'network_scope': '192.168.0.0/16'  # 监控的网络范围
    }

    detector = AdvancedPortScanDetector(config=custom_config)
    detector.start()