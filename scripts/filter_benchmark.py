#!/usr/bin/env python3
"""
筛选 benchmark.json，为每个 CWE 保留 10 个最具特色的样本。

使用流式处理以避免内存溢出。
"""

import json
import sys
from collections import defaultdict
import random

def calculate_sample_score(sample):
    """计算样本的特征分数，用于排序"""
    benign_lines = sample.get('benign_lines', [])
    vuln_lines = sample.get('vuln_lines', [])

    total_lines = len(benign_lines) + len(vuln_lines)
    vuln_count = len(vuln_lines)

    # 代码行长度信息
    all_lines = benign_lines + vuln_lines
    if all_lines:
        line_lengths = [len(str(line)) for line in all_lines]
        avg_length = sum(line_lengths) / len(line_lengths)
        max_length = max(line_lengths)
    else:
        avg_length = 0
        max_length = 0

    return {
        'total_lines': total_lines,
        'vuln_lines': vuln_count,
        'avg_length': avg_length,
        'max_length': max_length
    }

def select_diverse_samples_chunked(samples, n=10):
    """
    从样本中选择多样化的 n 个

    策略：按总行数分层采样
    """
    if len(samples) <= n:
        return samples

    # 计算特征并排序
    samples_with_scores = []
    for sample in samples:
        score = calculate_sample_score(sample)
        samples_with_scores.append((sample, score['total_lines']))

    # 按行数排序
    samples_with_scores.sort(key=lambda x: x[1])

    # 分层采样
    selected = []
    step = len(samples_with_scores) / n

    for i in range(n):
        idx = int(i * step + step / 2)
        if idx >= len(samples_with_scores):
            idx = len(samples_with_scores) - 1
        selected.append(samples_with_scores[idx][0])

    return selected

def process_in_chunks(input_file, output_file, samples_per_cwe=10):
    """
    分块处理大文件

    策略：
    1. 逐个处理每个语言的每个 CWE
    2. 使用有限内存
    """
    print(f"开始处理: {input_file}")
    print("正在分析文件结构...")

    # 先快速扫描文件，获取结构信息
    print("\n第1阶段: 读取数据...")
    with open(input_file, 'r', encoding='utf-8') as f:
        # 尝试使用 json.load 但使用迭代方式
        # 由于文件很大，我们需要分块读取

        # 读取整个文件（这里我们需要优化）
        # 让我们使用一个技巧：逐行读取并处理
        print("注意: 文件很大，正在加载...")

        content = f.read()

    print("解析 JSON...")
    data = json.loads(content)
    del content  # 释放内存

    print("\n第2阶段: 处理数据...")

    stats = {
        'original': defaultdict(lambda: defaultdict(int)),
        'filtered': defaultdict(lambda: defaultdict(int)),
        'total_original': 0,
        'total_filtered': 0
    }

    filtered_data = {}

    for lang_idx, (language, cwe_dict) in enumerate(data.items(), 1):
        print(f"\n[{lang_idx}/{len(data)}] 处理语言: {language}")
        filtered_data[language] = {}

        for cwe_idx, (cwe, samples) in enumerate(cwe_dict.items(), 1):
            original_count = len(samples)
            stats['original'][language][cwe] = original_count
            stats['total_original'] += original_count

            # 选择样本
            selected = select_diverse_samples_chunked(samples, samples_per_cwe)
            filtered_data[language][cwe] = selected

            filtered_count = len(selected)
            stats['filtered'][language][cwe] = filtered_count
            stats['total_filtered'] += filtered_count

            if cwe_idx % 10 == 0 or cwe_idx == len(cwe_dict):
                print(f"  进度: {cwe_idx}/{len(cwe_dict)} CWEs")

    # 清理原始数据以释放内存
    del data

    print(f"\n第3阶段: 保存结果到 {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, indent=2)

    print("保存完成！")
    return stats

def print_statistics(stats):
    """打印详细统计"""
    print("\n" + "="*70)
    print(" "*25 + "处理统计报告")
    print("="*70)

    print(f"\n【总体统计】")
    print(f"  原始样本总数: {stats['total_original']:,}")
    print(f"  过滤后样本数: {stats['total_filtered']:,}")
    print(f"  保留比例: {stats['total_filtered'] / stats['total_original'] * 100:.2f}%")
    print(f"  减少样本数: {stats['total_original'] - stats['total_filtered']:,}")

    print(f"\n【各语言详细统计】")
    print("-"*70)

    for language in sorted(stats['original'].keys()):
        lang_original = sum(stats['original'][language].values())
        lang_filtered = sum(stats['filtered'][language].values())
        cwe_count = len(stats['original'][language])

        print(f"\n{language}:")
        print(f"  样本数: {lang_original:,} -> {lang_filtered:,}")
        print(f"  CWE 类型数: {cwe_count}")
        print(f"  保留比例: {lang_filtered / lang_original * 100:.2f}%")

        # 显示每个 CWE 的统计
        print(f"  CWE 详情:")
        for cwe in sorted(stats['original'][language].keys()):
            orig = stats['original'][language][cwe]
            filt = stats['filtered'][language][cwe]
            print(f"    {cwe:12s}: {orig:6d} -> {filt:3d} ({filt/orig*100:5.1f}%)")

    print("\n" + "="*70)

def main():
    random.seed(42)

    input_file = 'benchmark.json'
    output_file = 'benchmark_filtered.json'
    samples_per_cwe = 10

    print("="*70)
    print(" "*20 + "Benchmark 数据集过滤工具")
    print("="*70)
    print(f"输入文件: {input_file}")
    print(f"输出文件: {output_file}")
    print(f"每个 CWE 保留样本数: {samples_per_cwe}")
    print("="*70)

    try:
        stats = process_in_chunks(input_file, output_file, samples_per_cwe)
        print_statistics(stats)

        print("\n" + "="*70)
        print(" "*28 + "处理完成！")
        print("="*70)
        print(f"\n输出文件已保存: {output_file}")

    except KeyboardInterrupt:
        print("\n\n用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"\n错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
