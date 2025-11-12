#!/usr/bin/env python3
"""
从 JSONL 文件分析 CWE 统计

统计：
1. 每个 CWE 有多少 samples
2. 每个 CWE 中有多少比例的 samples 是单一 CWE（没有 other CWEs）
"""

import json
import sys
from collections import defaultdict

def analyze_jsonl_cwe_stats(jsonl_path):
    """分析 JSONL 文件中的 CWE 统计"""

    print(f"读取 JSONL 文件: {jsonl_path}")

    cwe_stats = defaultdict(lambda: {'total': 0, 'single': 0, 'multi': 0})
    total_lines = 0
    skipped = 0

    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                sample = json.loads(line)
                total_lines += 1

                # 获取主 CWE
                cwe = sample.get('cwe', sample.get('CWE'))
                if not cwe or cwe.lower() == 'unknown':
                    skipped += 1
                    continue

                # 检查是否有其他 CWEs
                other_cwes = sample.get('other_cwes', sample.get('other CWEs', []))
                has_other_cwes = isinstance(other_cwes, list) and len(other_cwes) > 0

                # 统计
                cwe_stats[cwe]['total'] += 1
                if has_other_cwes:
                    cwe_stats[cwe]['multi'] += 1
                else:
                    cwe_stats[cwe]['single'] += 1

                if line_num % 1000 == 0:
                    print(f"  已处理 {line_num:,} 行...")

            except json.JSONDecodeError as e:
                print(f"  警告: 第 {line_num} 行 JSON 解析失败: {e}")
                continue

    print(f"\n处理完成:")
    print(f"  总行数: {total_lines:,}")
    print(f"  跳过 Unknown CWE: {skipped}")
    print(f"  有效样本: {sum(s['total'] for s in cwe_stats.values()):,}")
    print(f"  CWE 种类数: {len(cwe_stats)}")

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

    # 详细统计 - Top 50
    print(f"\n【各 CWE 详细统计】（按样本数降序，仅显示前 50）")
    print("-"*80)
    print(f"{'CWE':<15} {'总样本数':>10} {'单一CWE':>10} {'多CWE':>10} {'单一比例':>10}")
    print("-"*80)

    for cwe, stats in sorted_cwes[:50]:
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
        print(f"用法: {sys.argv[0]} <jsonl_file> [output_csv]")
        sys.exit(1)

    jsonl_path = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else None

    # 分析 CWE 统计
    cwe_stats = analyze_jsonl_cwe_stats(jsonl_path)

    # 打印统计
    print_cwe_statistics(cwe_stats)

    # 保存 CSV
    if output_csv:
        save_detailed_csv(cwe_stats, output_csv)


if __name__ == '__main__':
    main()
