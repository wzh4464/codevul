#!/usr/bin/env python3
"""
统计 JSONL 文件中每个 CWE 的数量
"""
import json
from collections import Counter
import sys

def count_cwe(jsonl_file):
    """
    统计 JSONL 文件中每个 CWE 的数量
    """
    print(f"正在读取文件: {jsonl_file}")

    cwe_counter = Counter()
    total_count = 0

    try:
        with open(jsonl_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    item = json.loads(line)
                    cwe = item.get('cwe', 'Unknown')
                    cwe_counter[cwe] += 1
                    total_count += 1

                    # 每处理 10000 条记录打印进度
                    if total_count % 10000 == 0:
                        print(f"已处理 {total_count} 条记录...")

                except json.JSONDecodeError as e:
                    print(f"第 {line_num} 行 JSON 解析错误: {e}")
                    continue

    except FileNotFoundError:
        print(f"文件不存在: {jsonl_file}")
        sys.exit(1)
    except Exception as e:
        print(f"读取文件失败: {e}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"CWE 统计结果 (共 {total_count} 条记录)")
    print(f"{'='*60}\n")

    # 按 CWE 编号排序
    sorted_cwes = sorted(cwe_counter.items(), key=lambda x: x[0])

    for cwe, count in sorted_cwes:
        percentage = (count / total_count) * 100
        print(f"{cwe:20s}: {count:6d} ({percentage:5.2f}%)")

    print(f"\n{'='*60}")
    print(f"总共 {len(cwe_counter)} 种不同的 CWE")
    print(f"{'='*60}")

    # 输出前 10 个最常见的 CWE
    print(f"\n前 10 个最常见的 CWE:")
    print(f"{'-'*60}")
    for cwe, count in cwe_counter.most_common(10):
        percentage = (count / total_count) * 100
        print(f"{cwe:20s}: {count:6d} ({percentage:5.2f}%)")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        jsonl_file = sys.argv[1]
    else:
        jsonl_file = 'benchmark_filtered.jsonl'

    count_cwe(jsonl_file)
