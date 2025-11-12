#!/usr/bin/env python3
"""
分析 YAML 文件中的 CWE 统计信息

统计：
1. 每个 CWE 有多少 samples
2. 每个 CWE 中有多少比例的 samples 是单一 CWE（没有 other CWEs）
"""

import sys
import re
from collections import defaultdict

def analyze_yaml_cwe_stats(yaml_path):
    """
    从 YAML 文件分析 CWE 统计（流式处理）

    Returns:
        cwe_stats: {cwe: {'total': int, 'single': int, 'multi': int}}
    """
    print(f"读取 YAML 文件: {yaml_path}")

    cwe_stats = defaultdict(lambda: {'total': 0, 'single': 0, 'multi': 0})
    current_language = None
    current_cwe = None
    in_sample = False
    sample_cwe = None
    has_other_cwes = False

    with open(yaml_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            # 匹配 Language 行
            lang_match = re.match(r'^\s+Language:\s*(.+)', line)
            if lang_match:
                current_language = lang_match.group(1).strip()
                continue

            # 匹配 CWD Number 行（定义当前处理的 CWE 组）
            cwe_match = re.match(r'^\s+- CWD Number:\s*(.+)', line)
            if cwe_match:
                current_cwe = cwe_match.group(1).strip()
                continue

            # 匹配 sample 开始（以 "- CWE:" 开头）
            sample_start_match = re.match(r'^\s+- CWE:\s*(.+)', line)
            if sample_start_match:
                in_sample = True
                sample_cwe = sample_start_match.group(1).strip()
                has_other_cwes = False
                continue

            # 如果在 sample 内，检查是否有 other CWEs 字段
            if in_sample:
                other_cwes_match = re.match(r'^\s+other CWEs\(CWDs\):\s*(.+)', line)
                if other_cwes_match:
                    # 有 other CWEs 字段
                    other_cwes_str = other_cwes_match.group(1).strip()
                    # 检查是否为空列表
                    if other_cwes_str and other_cwes_str != '[]':
                        has_other_cwes = True

                # 检查是否是下一个 sample 的开始（新的 "- CWE:" 或 "- benign_code:"）
                next_sample_match = re.match(r'^\s+- (?:CWE|benign_code):', line)
                if next_sample_match and sample_cwe:
                    # 当前 sample 结束，记录统计
                    cwe_stats[sample_cwe]['total'] += 1
                    if has_other_cwes:
                        cwe_stats[sample_cwe]['multi'] += 1
                    else:
                        cwe_stats[sample_cwe]['single'] += 1

                    # 如果是新 sample 开始
                    if line.strip().startswith('- CWE:'):
                        sample_cwe = re.match(r'^\s+- CWE:\s*(.+)', line).group(1).strip()
                        has_other_cwes = False
                    else:
                        in_sample = False
                        sample_cwe = None

            if line_num % 100000 == 0:
                print(f"  已处理 {line_num:,} 行...")

    # 处理最后一个 sample
    if in_sample and sample_cwe:
        cwe_stats[sample_cwe]['total'] += 1
        if has_other_cwes:
            cwe_stats[sample_cwe]['multi'] += 1
        else:
            cwe_stats[sample_cwe]['single'] += 1

    print(f"处理完成，共找到 {len(cwe_stats)} 个不同的 CWE")
    return dict(cwe_stats)


def print_cwe_statistics(cwe_stats):
    """打印 CWE 统计信息"""

    # 按样本数排序
    sorted_cwes = sorted(cwe_stats.items(), key=lambda x: x[1]['total'], reverse=True)

    print("\n" + "="*80)
    print(" "*25 + "CWE 统计分析报告")
    print("="*80)

    # 总体统计
    total_samples = sum(s['total'] for s in cwe_stats.values())
    total_single = sum(s['single'] for s in cwe_stats.values())
    total_multi = sum(s['multi'] for s in cwe_stats.values())

    print(f"\n【总体统计】")
    print(f"  CWE 种类数: {len(cwe_stats)}")
    print(f"  总样本数: {total_samples:,}")
    print(f"  单一 CWE 样本数: {total_single:,} ({total_single/total_samples*100:.1f}%)")
    print(f"  多 CWE 样本数: {total_multi:,} ({total_multi/total_samples*100:.1f}%)")

    # 详细统计
    print(f"\n【各 CWE 详细统计】（按样本数降序）")
    print("-"*80)
    print(f"{'CWE':<15} {'总样本数':>10} {'单一CWE':>10} {'多CWE':>10} {'单一比例':>10}")
    print("-"*80)

    for cwe, stats in sorted_cwes[:50]:  # 只显示前 50 个
        total = stats['total']
        single = stats['single']
        multi = stats['multi']
        single_ratio = single / total * 100 if total > 0 else 0

        print(f"{cwe:<15} {total:>10,} {single:>10,} {multi:>10,} {single_ratio:>9.1f}%")

    if len(sorted_cwes) > 50:
        print(f"\n... 还有 {len(sorted_cwes) - 50} 个 CWE")

    print("-"*80)

    # 单一 CWE 比例分布
    print(f"\n【单一 CWE 比例分布】")
    print("-"*80)
    ratio_ranges = [
        (0, 20, "0-20%"),
        (20, 40, "20-40%"),
        (40, 60, "40-60%"),
        (60, 80, "60-80%"),
        (80, 100, "80-100%"),
        (100, 101, "100%")
    ]

    for low, high, label in ratio_ranges:
        count = sum(1 for stats in cwe_stats.values()
                   if low <= (stats['single'] / stats['total'] * 100) < high)
        print(f"  {label:<15} {count:>5} 个 CWE")

    print("="*80)


def save_detailed_csv(cwe_stats, output_path):
    """保存详细统计到 CSV"""
    import csv

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['cwe', 'total_samples', 'single_cwe_samples', 'multi_cwe_samples', 'single_ratio'])

        # 按样本数降序
        sorted_cwes = sorted(cwe_stats.items(), key=lambda x: x[1]['total'], reverse=True)

        for cwe, stats in sorted_cwes:
            total = stats['total']
            single = stats['single']
            multi = stats['multi']
            single_ratio = single / total * 100 if total > 0 else 0

            writer.writerow([cwe, total, single, multi, f"{single_ratio:.2f}"])

    print(f"\n详细统计已保存到: {output_path}")


def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <yaml_file> [output_csv]")
        sys.exit(1)

    yaml_path = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else None

    # 分析 CWE 统计
    cwe_stats = analyze_yaml_cwe_stats(yaml_path)

    # 打印统计
    print_cwe_statistics(cwe_stats)

    # 保存 CSV
    if output_csv:
        save_detailed_csv(cwe_stats, output_csv)


if __name__ == '__main__':
    main()
