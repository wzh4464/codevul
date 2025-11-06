#!/usr/bin/env python3
"""
将 benchmark_filtered.json 转换为 JSONL 格式
每个嵌套对象作为单独的一行
"""
import json
import sys

def json_to_jsonl(input_file, output_file):
    """
    将嵌套的 JSON 文件转换为 JSONL 格式

    输入格式: { "语言": { "CWE": [ {...}, {...} ] } }
    输出格式: 每个对象一行
    """
    print(f"正在读取文件: {input_file}")

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"读取文件失败: {e}")
        sys.exit(1)

    print(f"开始转换为 JSONL 格式...")

    count = 0
    with open(output_file, 'w', encoding='utf-8') as f:
        # 遍历语言层级
        for language, cwes in data.items():
            # 遍历 CWE 层级
            for cwe, items in cwes.items():
                # 遍历每个项目
                for item in items:
                    # 添加元数据信息
                    item_with_meta = {
                        'language': language,
                        'cwe': cwe,
                        **item
                    }
                    # 写入一行 JSON
                    f.write(json.dumps(item_with_meta, ensure_ascii=False) + '\n')
                    count += 1

                    # 每处理 10000 条记录打印进度
                    if count % 10000 == 0:
                        print(f"已处理 {count} 条记录...")

    print(f"转换完成! 共转换 {count} 条记录")
    print(f"输出文件: {output_file}")

if __name__ == '__main__':
    input_file = 'benchmark_filtered.json'
    output_file = 'benchmark_filtered.jsonl'

    json_to_jsonl(input_file, output_file)
