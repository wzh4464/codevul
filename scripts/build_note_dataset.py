#!/usr/bin/env python3
"""
生成符合 example.yaml 格式的数据集

支持两种模式：
- fast: 从 benchmark_filtered.jsonl 快速读取
- full: 从 benchmark.json 完整读取

特性：
- 跳过 CWE 为 "Unknown" 的样本
- 优先级：填充度 > 有benign代码与url > 多样性（embedding或长度分层）
- 语言启发式提取 class/func/context
- 输出 YAML 格式到 standardized/ 目录
- 生成统计 CSV
"""

import json
import os
import sys
import argparse
import re
import csv
import logging
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional, Iterator
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 尝试导入可选依赖
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger.warning("numpy 未安装，将使用简化的多样性选择")

try:
    from ruamel.yaml import YAML
    RUAMEL_AVAILABLE = True
except ImportError:
    RUAMEL_AVAILABLE = False
    logger.warning("ruamel.yaml 未安装，将使用 PyYAML")
    try:
        import yaml
        PYYAML_AVAILABLE = True
    except ImportError:
        PYYAML_AVAILABLE = False
        logger.error("需要安装 ruamel.yaml 或 PyYAML: pip install ruamel.yaml")
        sys.exit(1)


# ============================================================================
# 数据读取与归一化
# ============================================================================

def read_jsonl(file_path: str) -> Iterator[Dict[str, Any]]:
    """读取 JSONL 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    logger.warning(f"跳过无效的 JSON 行: {e}")
                    continue


def read_json(file_path: str) -> Iterator[Dict[str, Any]]:
    """读取 JSON 文件并展平为样本迭代器"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 假设结构为: { language: { cwe: [samples] } }
    for language, cwe_dict in data.items():
        for cwe, samples in cwe_dict.items():
            for sample in samples:
                # 添加 language 和 cwe 字段
                sample['language'] = language
                sample['cwe'] = cwe
                yield sample


def normalize_samples(samples_iter: Iterator[Dict[str, Any]], skip_unknown: bool = True) -> List[Dict[str, Any]]:
    """
    归一化样本并按 (language, CWE) 分组

    Args:
        samples_iter: 样本迭代器
        skip_unknown: 是否跳过 CWE 为 "Unknown" 的样本

    Returns:
        分组后的样本字典: {(language, cwe): [samples]}
    """
    grouped = defaultdict(list)
    skipped = 0
    total = 0

    for sample in samples_iter:
        total += 1

        # 提取 language 和 CWE
        language = sample.get('language', 'Unknown')
        cwe = sample.get('cwe', sample.get('CWE', 'Unknown'))

        # 跳过 Unknown CWE
        if skip_unknown and cwe.lower() == 'unknown':
            skipped += 1
            continue

        # 确保样本有 language 和 cwe 字段
        sample['language'] = language
        sample['cwe'] = cwe

        grouped[(language, cwe)].append(sample)

    logger.info(f"读取 {total} 个样本，跳过 {skipped} 个 Unknown CWE")
    logger.info(f"分组后: {len(grouped)} 个 (language, CWE) 组合")

    return grouped


# ============================================================================
# 评分与候选池
# ============================================================================

def calculate_fill_score(sample: Dict[str, Any]) -> float:
    """
    计算样本的填充度评分

    检查字段：benign_lines, vuln_lines, source, commit, context, class, func
    """
    score = 0.0

    # 检查代码行
    benign_lines = sample.get('benign_lines', [])
    vuln_lines = sample.get('vuln_lines', [])

    if benign_lines and len(benign_lines) > 0:
        score += 2.0
    if vuln_lines and len(vuln_lines) > 0:
        score += 2.0

    # 检查元数据
    if sample.get('source'):
        score += 1.0
    if sample.get('commit'):
        score += 1.0

    # 检查结构字段
    if sample.get('context'):
        score += 0.5
    if sample.get('class'):
        score += 0.5
    if sample.get('func'):
        score += 0.5

    return score


def score_samples(samples: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """
    为样本评分并返回 (sample, score_dict) 列表

    评分包括：
    - has_benign: 是否有 benign 代码
    - has_url: 是否有 source URL
    - fill_score: 填充度评分
    """
    scored = []

    for sample in samples:
        benign_lines = sample.get('benign_lines', [])
        has_benign = len(benign_lines) > 0 if benign_lines else False
        has_url = bool(sample.get('source'))
        fill_score = calculate_fill_score(sample)

        score_dict = {
            'has_benign': has_benign,
            'has_url': has_url,
            'fill_score': fill_score,
        }

        scored.append((sample, score_dict))

    return scored


def filter_candidates(scored_samples: List[Tuple[Dict[str, Any], Dict[str, Any]]],
                     k: int,
                     multiplier: int = 4) -> List[Dict[str, Any]]:
    """
    根据评分筛选候选池

    排序键：has_benign desc, has_url desc, fill_score desc
    """
    # 排序
    sorted_samples = sorted(
        scored_samples,
        key=lambda x: (x[1]['has_benign'], x[1]['has_url'], x[1]['fill_score']),
        reverse=True
    )

    # 截断到 k * multiplier
    max_candidates = min(k * multiplier, len(sorted_samples))
    candidates = [sample for sample, score in sorted_samples[:max_candidates]]

    return candidates


# ============================================================================
# 多样性选择
# ============================================================================

def select_diverse_length_based(samples: List[Dict[str, Any]], k: int) -> List[Dict[str, Any]]:
    """
    基于长度分层的多样性选择（兜底方案）

    类似 filter_benchmark.py 的策略
    """
    if len(samples) <= k:
        return samples

    # 计算总行数
    samples_with_length = []
    for sample in samples:
        benign_lines = sample.get('benign_lines', [])
        vuln_lines = sample.get('vuln_lines', [])
        total_lines = len(benign_lines) + len(vuln_lines)
        samples_with_length.append((sample, total_lines))

    # 按行数排序
    samples_with_length.sort(key=lambda x: x[1])

    # 分层采样
    selected = []
    step = len(samples_with_length) / k

    for i in range(k):
        idx = int(i * step + step / 2)
        if idx >= len(samples_with_length):
            idx = len(samples_with_length) - 1
        selected.append(samples_with_length[idx][0])

    return selected


def select_diverse_embedding_based(samples: List[Dict[str, Any]],
                                  k: int,
                                  embedding_cache_dir: str = 'embeddings_cache') -> Optional[List[Dict[str, Any]]]:
    """
    基于 embedding 的多样性选择

    使用 max-min 贪心算法或 k-means

    Returns:
        选中的样本列表，如果 embedding 不可用则返回 None
    """
    if not NUMPY_AVAILABLE:
        return None

    # TODO: 实现 embedding 多样性选择
    # 这需要从 cluster_benchmark.py 复用逻辑
    # 目前先返回 None，使用兜底方案
    logger.warning("Embedding 多样性选择暂未实现，使用长度分层兜底")
    return None


def select_diverse(samples: List[Dict[str, Any]], k: int) -> List[Dict[str, Any]]:
    """
    多样性选择主函数

    优先使用 embedding，失败则回退到长度分层
    """
    if len(samples) <= k:
        return samples

    # 尝试 embedding 方法
    selected = select_diverse_embedding_based(samples, k)

    # 回退到长度分层
    if selected is None:
        selected = select_diverse_length_based(samples, k)

    return selected


# ============================================================================
# 代码结构提取
# ============================================================================

def extract_c_cpp_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """提取 C/C++ 代码的 class 和 func"""
    # 类正则
    class_pattern = r'class\s+(\w+)\s*[:{]'
    class_match = re.search(class_pattern, code)
    class_name = class_match.group(1) if class_match else None

    # 函数正则 (简化版)
    func_pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*\{'
    func_match = re.search(func_pattern, code)
    func_name = func_match.group(2) if func_match else None

    return class_name, func_name


def extract_java_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """提取 Java 代码的 class 和 func"""
    # 类正则
    class_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:class|interface|enum)\s+(\w+)'
    class_match = re.search(class_pattern, code)
    class_name = class_match.group(1) if class_match else None

    # 方法正则
    func_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*\{'
    func_match = re.search(func_pattern, code)
    func_name = func_match.group(1) if func_match else None

    return class_name, func_name


def extract_python_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """提取 Python 代码的 class 和 func"""
    # 类正则
    class_pattern = r'^class\s+(\w+)'
    class_match = re.search(class_pattern, code, re.MULTILINE)
    class_name = class_match.group(1) if class_match else None

    # 函数正则
    func_pattern = r'^def\s+(\w+)\s*\('
    func_match = re.search(func_pattern, code, re.MULTILINE)
    func_name = func_match.group(1) if func_match else None

    return class_name, func_name


def extract_js_ts_structure(code: str) -> Tuple[Optional[str], Optional[str]]:
    """提取 JavaScript/TypeScript 代码的 class 和 func"""
    # 类正则
    class_pattern = r'class\s+(\w+)'
    class_match = re.search(class_pattern, code)
    class_name = class_match.group(1) if class_match else None

    # 函数正则 (function 或 arrow function)
    func_pattern = r'(?:function\s+(\w+)|const\s+(\w+)\s*=.*?=>)'
    func_match = re.search(func_pattern, code)
    func_name = func_match.group(1) or func_match.group(2) if func_match else None

    return class_name, func_name


def extract_structure(code: str, language: str) -> Dict[str, Optional[str]]:
    """
    根据语言提取代码结构

    Returns:
        {context: str, class: str, func: str}
    """
    language_lower = language.lower()

    class_name = None
    func_name = None

    # 根据语言选择提取方法
    if 'c' in language_lower or 'cpp' in language_lower:
        class_name, func_name = extract_c_cpp_structure(code)
    elif 'java' in language_lower:
        class_name, func_name = extract_java_structure(code)
    elif 'python' in language_lower or 'py' in language_lower:
        class_name, func_name = extract_python_structure(code)
    elif 'javascript' in language_lower or 'typescript' in language_lower or 'js' in language_lower or 'ts' in language_lower:
        class_name, func_name = extract_js_ts_structure(code)

    # 返回结果
    return {
        'context': code,
        'class': class_name,
        'func': func_name
    }


def prepare_code_for_yaml(sample: Dict[str, Any], code_type: str) -> Dict[str, Any]:
    """
    准备代码数据用于 YAML 输出

    Args:
        sample: 样本数据
        code_type: 'benign' 或 'vulnerable'

    Returns:
        {context, class, func}
    """
    # 获取代码行
    if code_type == 'benign':
        lines = sample.get('benign_lines', [])
    else:
        lines = sample.get('vuln_lines', sample.get('vulnerable_lines', []))

    # 如果没有代码行，返回空结构
    if not lines:
        return {'context': None, 'class': None, 'func': None}

    # 合并代码行
    if isinstance(lines, list):
        code = '\n'.join(str(line) for line in lines)
    else:
        code = str(lines)

    # 检查是否已有结构字段
    existing_context = sample.get('context')
    existing_class = sample.get('class')
    existing_func = sample.get('func')

    if existing_context or existing_class or existing_func:
        # 使用已有的结构字段
        return {
            'context': existing_context or code,
            'class': existing_class,
            'func': existing_func
        }

    # 否则做启发式提取
    language = sample.get('language', 'Unknown')
    structure = extract_structure(code, language)

    return structure


# ============================================================================
# YAML 输出
# ============================================================================

def build_yaml_structure(grouped_samples: Dict[Tuple[str, str], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    构建符合 example.yaml 的数据结构

    结构：
    [
        {
            'Language': 'C',
            'CWEs': [
                {
                    'CWD Number': 'CWE-79',
                    'samples': [...]
                }
            ]
        }
    ]
    """
    # 按语言分组
    by_language = defaultdict(lambda: defaultdict(list))

    for (language, cwe), samples in grouped_samples.items():
        by_language[language][cwe] = samples

    # 构建最终结构
    result = []

    for language in sorted(by_language.keys()):
        language_entry = {
            'Language': language,
            'CWEs': []
        }

        for cwe in sorted(by_language[language].keys()):
            samples = by_language[language][cwe]

            # 转换样本格式
            formatted_samples = []
            for sample in samples:
                benign_code = prepare_code_for_yaml(sample, 'benign')
                vulnerable_code = prepare_code_for_yaml(sample, 'vulnerable')

                formatted_sample = {
                    'benign_code': benign_code,
                    'vulnerable_code': vulnerable_code,
                    'CWE': sample.get('cwe', sample.get('CWE')),
                    'source': sample.get('source', ''),
                    'commit': sample.get('commit', ''),
                }

                # 添加 other CWEs 字段（如果有）
                other_cwes = sample.get('other_cwes', sample.get('other CWEs', []))
                if other_cwes:
                    formatted_sample['other CWEs(CWDs)'] = other_cwes

                formatted_samples.append(formatted_sample)

            cwe_entry = {
                'CWD Number': cwe,
                'samples': formatted_samples
            }

            language_entry['CWEs'].append(cwe_entry)

        result.append(language_entry)

    return result


def save_yaml(data: List[Dict[str, Any]], output_path: str):
    """保存数据为 YAML 格式"""
    if RUAMEL_AVAILABLE:
        yaml = YAML()
        yaml.default_flow_style = False
        yaml.indent(mapping=2, sequence=2, offset=2)

        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f)
    elif PYYAML_AVAILABLE:
        import yaml
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, indent=2)
    else:
        raise RuntimeError("需要安装 ruamel.yaml 或 PyYAML")

    logger.info(f"已保存 YAML 文件: {output_path}")


# ============================================================================
# 统计输出
# ============================================================================

def generate_statistics(grouped_samples: Dict[Tuple[str, str], List[Dict[str, Any]]]) -> Dict[Tuple[str, str], int]:
    """生成统计信息"""
    stats = {}
    for (language, cwe), samples in grouped_samples.items():
        stats[(language, cwe)] = len(samples)
    return stats


def print_statistics(stats: Dict[Tuple[str, str], int]):
    """打印统计信息到终端"""
    logger.info("\n" + "="*60)
    logger.info("统计报告")
    logger.info("="*60)

    # 按语言分组
    by_language = defaultdict(list)
    for (language, cwe), count in stats.items():
        by_language[language].append((cwe, count))

    total_samples = sum(stats.values())

    logger.info(f"\n总样本数: {total_samples}")
    logger.info(f"语言数: {len(by_language)}")
    logger.info(f"(language, CWE) 组合数: {len(stats)}")

    logger.info("\n按语言统计:")
    for language in sorted(by_language.keys()):
        cwes = by_language[language]
        lang_total = sum(count for _, count in cwes)
        logger.info(f"\n  {language}: {lang_total} 个样本, {len(cwes)} 个 CWE")

        # 显示前 10 个 CWE
        cwes_sorted = sorted(cwes, key=lambda x: x[1], reverse=True)
        for cwe, count in cwes_sorted[:10]:
            logger.info(f"    {cwe}: {count}")

        if len(cwes) > 10:
            logger.info(f"    ... (还有 {len(cwes) - 10} 个 CWE)")


def save_statistics_csv(stats: Dict[Tuple[str, str], int], output_path: str):
    """保存统计信息到 CSV"""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['language', 'cwe', 'count'])

        for (language, cwe), count in sorted(stats.items()):
            writer.writerow([language, cwe, count])

    logger.info(f"已保存统计 CSV: {output_path}")


# ============================================================================
# 主流程
# ============================================================================

def process_mode(mode: str,
                input_path: str,
                k: int,
                output_path: str,
                stats_path: Optional[str] = None):
    """
    处理单个模式的主流程

    Args:
        mode: 'fast' 或 'full'
        input_path: 输入文件路径
        k: 每个 (language, CWE) 保留的样本数
        output_path: 输出 YAML 路径
        stats_path: 统计 CSV 路径（可选）
    """
    logger.info(f"\n开始处理: mode={mode}, k={k}")
    logger.info(f"输入: {input_path}")
    logger.info(f"输出: {output_path}")

    # 读取数据
    if mode == 'fast':
        samples_iter = read_jsonl(input_path)
    else:  # full
        samples_iter = read_json(input_path)

    # 归一化并分组
    logger.info("归一化样本...")
    grouped = normalize_samples(samples_iter, skip_unknown=True)

    # 对每个组进行处理
    logger.info(f"处理 {len(grouped)} 个 (language, CWE) 组合...")

    final_grouped = {}

    for idx, ((language, cwe), samples) in enumerate(grouped.items(), 1):
        if idx % 10 == 0:
            logger.info(f"  进度: {idx}/{len(grouped)}")

        # 如果样本数已经 <= k，直接保留
        if len(samples) <= k:
            final_grouped[(language, cwe)] = samples
            continue

        # 评分
        scored = score_samples(samples)

        # 筛选候选池
        candidates = filter_candidates(scored, k, multiplier=4)

        # 多样性选择
        selected = select_diverse(candidates, k)

        final_grouped[(language, cwe)] = selected

    logger.info("处理完成！")

    # 构建 YAML 结构
    logger.info("构建 YAML 结构...")
    yaml_data = build_yaml_structure(final_grouped)

    # 保存 YAML
    logger.info("保存 YAML...")
    save_yaml(yaml_data, output_path)

    # 生成统计
    logger.info("生成统计...")
    stats = generate_statistics(final_grouped)
    print_statistics(stats)

    # 保存统计 CSV
    if stats_path:
        save_statistics_csv(stats, stats_path)

    logger.info(f"\n完成！输出文件: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='生成符合 example.yaml 格式的数据集'
    )

    parser.add_argument('--mode',
                       choices=['fast', 'full'],
                       required=True,
                       help='处理模式: fast (从 JSONL) 或 full (从 JSON)')

    parser.add_argument('--k',
                       type=int,
                       required=True,
                       help='每个 (language, CWE) 保留的样本数 (10 或 300)')

    parser.add_argument('--input',
                       type=str,
                       required=True,
                       help='输入文件路径')

    parser.add_argument('--output',
                       type=str,
                       required=True,
                       help='输出 YAML 文件路径')

    parser.add_argument('--stats',
                       type=str,
                       help='统计 CSV 输出路径（可选）')

    args = parser.parse_args()

    # 检查输入文件
    if not os.path.exists(args.input):
        logger.error(f"输入文件不存在: {args.input}")
        sys.exit(1)

    # 确保输出目录存在
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    if args.stats:
        stats_dir = os.path.dirname(args.stats)
        if stats_dir:
            os.makedirs(stats_dir, exist_ok=True)

    # 处理
    try:
        process_mode(
            mode=args.mode,
            input_path=args.input,
            k=args.k,
            output_path=args.output,
            stats_path=args.stats
        )
    except Exception as e:
        logger.error(f"处理失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
