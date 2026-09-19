import socket
import os
import time


def check_vnc_connection(host, port=5900, timeout=3):
    """
    验证VNC服务器是否可连接
    :param host: 目标主机名/IP
    :param port: VNC端口（默认5900）
    :param timeout: 连接超时时间（秒）
    :return: 元组 (是否可连接, 协议版本/错误信息, 响应时间)
    """
    start_time = time.time()
    try:
        # 创建socket连接
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            response = sock.recv(12)
            response_time = round((time.time() - start_time) * 1000, 2)

            # 检查VNC协议标识
            if response.startswith(b'RFB'):
                protocol = response.decode('utf-8', errors='ignore').strip()
                return True, protocol, response_time
            return True, "Non-VNC Service", response_time

    except socket.timeout:
        return False, "Connection Timeout", 0
    except ConnectionRefusedError:
        return False, "Connection Refused", 0
    except socket.gaierror:
        return False, "Hostname Resolution Failed", 0
    except Exception as e:
        return False, f"Error: {str(e)}", 0


def single_ip_mode():
    """单IP手动输入模式"""
    print("\n" + "=" * 40)
    print("VNC连接测试 - 单IP模式")
    print("=" * 40)

    host = input("请输入目标主机/IP: ").strip()
    port_input = input("请输入端口 (默认5900): ").strip()
    port = int(port_input) if port_input else 5900

    print("\n测试中...")
    success, message, rtt = check_vnc_connection(host, port)

    print("\n测试结果:")
    print(f"目标地址: {host}:{port}")
    print(f"连接状态: {'成功' if success else '失败'}")
    print(f"协议/错误: {message}")
    if rtt > 0:
        print(f"响应时间: {rtt} ms")


def batch_file_mode():
    """批量文件读取模式"""
    print("\n" + "=" * 40)
    print("VNC连接测试 - 批量模式")
    print("=" * 40)

    file_path = input("请输入包含IP列表的文件路径: ").strip()

    if not os.path.exists(file_path):
        print(f"\n错误: 文件不存在 - {file_path}")
        return

    targets = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # 解析IP:端口格式
            if ':' in line:
                parts = line.split(':')
                host = parts[0].strip()
                try:
                    port = int(parts[1].strip())
                except ValueError:
                    port = 5900
                targets.append((host, port))
            else:
                targets.append((line, 5900))

    if not targets:
        print("\n错误: 文件中未找到有效的IP地址")
        return

    print(f"\n找到 {len(targets)} 个目标, 开始测试...")
    print("\n测试结果:")
    print("-" * 65)
    print(f"{'目标地址':<25}{'状态':<10}{'协议/错误':<25}{'响应时间':<10}")
    print("-" * 65)

    successful = 0
    for host, port in targets:
        success, message, rtt = check_vnc_connection(host, port)
        status = "成功" if success else "失败"
        if success:
            successful += 1

        rtt_str = f"{rtt} ms" if rtt > 0 else "N/A"
        print(f"{host + ':' + str(port):<25}{status:<10}{message:<25}{rtt_str:<10}")

    print("-" * 65)
    print(f"总计: {len(targets)} 个目标, 成功: {successful}, 失败: {len(targets) - successful}")
    print(f"成功率: {successful / len(targets) * 100:.2f}%")


def main():
    """主菜单"""
    while True:
        print("\n" + "=" * 40)
        print("VNC连接验证工具")
        print("=" * 40)
        print("1. 单IP测试模式")
        print("2. 批量文件测试模式")
        print("3. 退出程序")

        choice = input("\n请选择操作模式 (1-3): ").strip()

        if choice == '1':
            single_ip_mode()
        elif choice == '2':
            batch_file_mode()
        elif choice == '3':
            print("\n程序已退出")
            break
        else:
            print("\n无效选择，请重新输入")


if __name__ == "__main__":
    main()