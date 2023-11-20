import concurrent.futures
import re
import httpx
from tqdm import tqdm
import pandas as pd
import logging
import argparse
import os
from colorama import Fore, Style
from colorama import init as colorama_init

colorama_init(autoreset=True)

# 配置基础日志
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# 为提高效率预编译正则表达式
ip_port_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}')


def create_output_folder(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)


def extract_and_filter_ip_ports(file_path, remove_ports=None, save_to_excel=True, output_folder=None):
    create_output_folder(output_folder)

    try:
        with open(file_path, "r") as file:
            text = file.read()

        ip_port_list = ip_port_pattern.findall(text)

        # 保存所有原始数据到 Excel
        if save_to_excel:
            ips, ports = zip(*(item.split(':') for item in ip_port_list))
            df = pd.DataFrame({'IP': ips, 'Port': ports})
            output_excel_path = os.path.join(output_folder, "all_ip_ports.xlsx")
            df.to_excel(output_excel_path, index=False)

        if remove_ports:
            remove_ports_set = set(map(str, remove_ports))  # 将整数端口号转换为字符串
            filtered_ip_port_list = [item for item in ip_port_list if not item.split(':')[1] in remove_ports_set]
        else:
            filtered_ip_port_list = ip_port_list

        output_txt_path = os.path.join(output_folder, "filtered_ip_ports.txt")
        with open(output_txt_path, "w") as output_file:
            output_file.write("\n".join(filtered_ip_port_list))

        return filtered_ip_port_list
    except Exception as e:
        logging.error(f"在extract_and_filter_ip_ports中出错: {e}")
        return []


def append_to_file(output_folder, filename, data):
    output_path = os.path.join(output_folder, filename)
    try:
        with open(output_path, 'a') as file:
            file.write(data + "\n")
        logging.info(f"数据已附加到 {output_path}")
    except Exception as e:
        logging.error(f"在append_to_file中出错: {e}")


def check_web_service(url, timeout=2, silent=False, output_folder=None):
    try:
        with httpx.Client() as client:
            response = client.get("http://" + url, timeout=timeout)
            if response.status_code == 200:
                append_to_file(output_folder, "200.txt", url)
                color = Fore.GREEN
            elif 300 <= response.status_code < 400:
                append_to_file(output_folder, "300.txt", url)
                color = Fore.BLUE
            elif 400 <= response.status_code < 500:
                append_to_file(output_folder, "400.txt", url)
                color = Fore.YELLOW
            else:
                append_to_file(output_folder, "500.txt", url)
                color = Fore.RED

            if not silent:
                logging.info(f"{color}URL '{url}' 返回状态码: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        if not silent:
            logging.error(f"{Fore.RED}在检查 '{url}' 时出错: {e}{Style.RESET_ALL}")
        append_to_file(output_folder, "errors.txt", url)


def main(file_path, only_extract=False, max_workers=10, continue_scan=False, silent=False, output_folder=None, exclude_ports=None):
    if not output_folder:
        file_name = os.path.splitext(os.path.basename(file_path))[0]
        output_folder = os.path.join(os.path.dirname(file_path), file_name)

    create_output_folder(output_folder)

    try:
        scanned_urls = set()
        scanned_urls_file = os.path.join(output_folder, 'scanned_urls.txt')
        if continue_scan:
            try:
                with open(scanned_urls_file, 'r') as f:
                    scanned_urls = set(f.read().splitlines())
            except FileNotFoundError:
                logging.info("没有找到之前的扫描记录，将开始新的扫描。")

        if not os.path.exists(file_path):
            logging.error("文件路径不存在。")
            return

        filtered_ip_port_list = extract_and_filter_ip_ports(file_path, remove_ports=exclude_ports, output_folder=output_folder)

        if not only_extract:
            progress_bar = tqdm(total=len(filtered_ip_port_list), unit='URLs', leave=False, disable=silent)

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(check_web_service, url, timeout=2, silent=silent, output_folder=output_folder): url
                    for url in filtered_ip_port_list if url not in scanned_urls}

                for future in concurrent.futures.as_completed(futures):
                    url = futures[future]
                    progress_bar.update(1)
                    if continue_scan:
                        scanned_urls.add(url)
                        with open(scanned_urls_file, 'a') as f:
                            f.write(url + '\n')

            progress_bar.close()
    except KeyboardInterrupt:
        logging.info("程序被用户中断。正在退出...")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP地址和端口提取器及网络服务检查器")
    parser.add_argument('file_path', type=str, help="包含IP地址和端口的文件路径")
    parser.add_argument('-e', '--only_extract', action='store_true', help="是否仅运行提取和过滤过程")
    parser.add_argument('-t', '--max_workers', type=int, default=10, help="并发执行的最大工作线程数")
    parser.add_argument('-c', '--continue_scan', action='store_true', help="从上次的断点继续扫描")
    parser.add_argument('-s', '--silent', action='store_true', help="静默模式，只显示进度条")
    parser.add_argument('-o', '--output', type=str, help="指定输出文件夹的路径")
    parser.add_argument('-x', '--exclude_ports', nargs='+', type=int, default=[], help="要排除的端口列表")
    args = parser.parse_args()

    main(args.file_path, args.only_extract, args.max_workers, args.continue_scan, args.silent, args.output, args.exclude_ports)

