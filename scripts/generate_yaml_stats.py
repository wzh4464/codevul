#!/usr/bin/env python3
"""
从已生成的 YAML 文件提取统计信息并生成 CSV
使用轻量级文本处理，避免加载整个文件
"""

import sys
import csv
import re
from collections import defaultdict

def extract_stats_from_yaml(yaml_path):
    """从 YAML 文件提取统计（流式处理）"""
    print(f"读取 YAML 文件: {yaml_path}")

    stats = defaultdict(int)
    current_language = None
    pending_cwes = []  # 存储在看到 Language 之前遇到的 CWE 统计

    with open(yaml_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            # 匹配 Language 行（可能在 CWEs 之后）
            lang_match = re.match(r'^\s+Language:\s*(.+)', line)
            if lang_match:
                current_language = lang_match.group(1).strip()
                # 将待处理的 CWE 统计与当前语言关联
                for cwe, count in pending_cwes:
                    stats[(current_language, cwe)] = count
                pending_cwes = []
                continue

            # 匹配 CWD Number 行
            cwe_match = re.match(r'^\s+- CWD Number:\s*(.+)', line)
            if cwe_match:
                # 这是一个新的 CWE 块
                cwe = cwe_match.group(1).strip()
                pending_cwes.append((cwe, 0))  # 初始化计数为 0
                continue

            # 匹配 sample 行（"- CWE:" 开头）
            sample_match = re.match(r'^\s+- CWE:\s*', line)
            if sample_match and pending_cwes:
                # 增加当前 CWE 的样本计数
                cwe, count = pending_cwes[-1]
                pending_cwes[-1] = (cwe, count + 1)

            if line_num % 100000 == 0:
                print(f"  已处理 {line_num:,} 行...")

    # 处理最后剩余的 CWE
    if current_language and pending_cwes:
        for cwe, count in pending_cwes:
            stats[(current_language, cwe)] = count

    print(f"处理完成，共提取 {len(stats)} 个 (language, CWE) 组合的统计")
    return stats

def save_stats_csv(stats, output_path):
    """保存统计到 CSV"""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['language', 'cwe', 'count'])

        for (language, cwe), count in sorted(stats.items()):
            writer.writerow([language, cwe, count])

    print(f"已保存统计 CSV: {output_path}")

def print_stats(stats):
    """打印统计信息"""
    by_language = defaultdict(list)
    for (language, cwe), count in stats.items():
        by_language[language].append((cwe, count))

    total_samples = sum(stats.values())

    print(f"\n总样本数: {total_samples}")
    print(f"语言数: {len(by_language)}")
    print(f"(language, CWE) 组合数: {len(stats)}")

    print("\n按语言统计:")
    for language in sorted(by_language.keys()):
        cwes = by_language[language]
        lang_total = sum(count for _, count in cwes)
        print(f"  {language}: {lang_total} 个样本, {len(cwes)} 个 CWE")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <yaml_file> <output_csv>")
        sys.exit(1)

    yaml_path = sys.argv[1]
    output_path = sys.argv[2]

    stats = extract_stats_from_yaml(yaml_path)
    print_stats(stats)
    save_stats_csv(stats, output_path)
