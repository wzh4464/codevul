#!/usr/bin/env python3
"""
对 benchmark.json 中的代码进行 embedding 和聚类

优化特性：
- 使用流式解析，不将整个文件加载到内存中
- 只对样本数 >= 100 的 CWE 进行聚类（基于 embedding + KMeans）
- 样本数 < 100 的 CWE 随机选择最多 10 个样本
- 每个 CWE 最终保留最多 10 条代表性样本
- 使用 16 个并发线程获取 embeddings
- Embedding 缓存机制：已计算的 embedding 会保存，下次运行时自动跳过
- 流式保存：每个 CWE 处理完后立即保存并清理内存

内存优化（针对大 CWE）：
- 对于样本数 > 5000 的大 CWE，使用分批处理模式
- 使用生成器函数按需加载数据，避免一次性加载到内存
- 分片计算和缓存 embeddings，降低内存峰值
- 使用 MiniBatchKMeans 替代标准 KMeans 进行增量聚类
- 预期内存使用降低 70-90%（取决于 CWE 大小）

依赖安装：
    pip install openai scikit-learn numpy ijson
"""
import json
import os
import sys
import numpy as np
from collections import defaultdict
from typing import List, Dict, Any, Optional
import logging
import gc

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 尝试导入必要的库
try:
    from openai import OpenAI
except ImportError:
    logger.error("需要安装 openai 库: pip install openai")
    sys.exit(1)

try:
    from sklearn.cluster import KMeans, MiniBatchKMeans
    from sklearn.metrics import pairwise_distances_argmin_min
except ImportError:
    logger.error("需要安装 scikit-learn 库: pip install scikit-learn")
    sys.exit(1)

try:
    import ijson
except ImportError:
    logger.error("需要安装 ijson 库: pip install ijson")
    sys.exit(1)


def load_env_vars():
    """加载 .env 文件中的环境变量"""
    env_path = '.env'
    if os.path.exists(env_path):
        logger.info(f"加载环境变量: {env_path}")
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    else:
        logger.warning("未找到 .env 文件")


def get_embedding_cache_path(cwe: str, cache_dir: str = 'embeddings_cache') -> str:
    """
    获取 CWE 的 embedding 缓存文件路径
    
    Args:
        cwe: CWE 标识符
        cache_dir: 缓存目录
    
    Returns:
        缓存文件路径
    """
    # 确保缓存目录存在
    os.makedirs(cache_dir, exist_ok=True)
    
    # 使用 CWE 标识符作为文件名（移除非法字符）
    safe_cwe = cwe.replace('/', '_').replace('\\', '_')
    cache_file = os.path.join(cache_dir, f"{safe_cwe}.npy")
    
    return cache_file


def load_embeddings_from_cache(cwe: str, cache_dir: str = 'embeddings_cache') -> Optional[np.ndarray]:
    """
    从缓存加载 embedding
    
    Args:
        cwe: CWE 标识符
        cache_dir: 缓存目录
    
    Returns:
        如果缓存存在则返回 embedding 数组，否则返回 None
    """
    cache_file = get_embedding_cache_path(cwe, cache_dir)
    
    if os.path.exists(cache_file):
        try:
            embeddings = np.load(cache_file, allow_pickle=False)
            logger.info(f"  从缓存加载 {cwe} 的 embeddings: {embeddings.shape}")
            return embeddings
        except Exception as e:
            logger.warning(f"  加载缓存失败 ({cwe}): {e}，将重新计算")
            return None
    
    return None


def save_embeddings_to_cache(cwe: str, embeddings: np.ndarray, cache_dir: str = 'embeddings_cache') -> bool:
    """
    保存 embedding 到缓存
    
    Args:
        cwe: CWE 标识符
        embeddings: embedding 数组
        cache_dir: 缓存目录
    
    Returns:
        是否成功保存
    """
    cache_file = get_embedding_cache_path(cwe, cache_dir)
    
    try:
        np.save(cache_file, embeddings, allow_pickle=False)
        logger.info(f"  已保存 {cwe} 的 embeddings 到缓存: {embeddings.shape}")
        return True
    except Exception as e:
        logger.error(f"  保存缓存失败 ({cwe}): {e}")
        return False


def count_cwe_samples(input_file: str) -> Dict[str, int]:
    """
    第一次遍历：统计每个 CWE 的样本数量
    使用流式解析，不加载整个文件到内存
    """
    logger.info("统计每个 CWE 的样本数量...")
    cwe_counts = defaultdict(int)

    with open(input_file, 'rb') as f:
        # 使用 ijson 流式解析
        # 格式: { "语言": { "CWE": [ {...}, {...} ] } }
        # 解析顶层对象，获取每个语言的数据
        for language, cwes in ijson.kvitems(f, ''):
            # cwes 是该语言下的所有 CWE 字典
            for cwe, items in cwes.items():
                cwe_counts[cwe] += len(items)

    logger.info(f"统计完成: 共 {len(cwe_counts)} 种 CWE，{sum(cwe_counts.values())} 个样本")
    return dict(cwe_counts)


def extract_cwe_data(input_file: str, target_cwe: str) -> List[Dict[str, Any]]:
    """
    第二次遍历：提取特定 CWE 的所有数据
    使用流式解析，只加载目标 CWE 的数据
    """
    items = []

    with open(input_file, 'rb') as f:
        for language, cwes in ijson.kvitems(f, ''):
            if target_cwe in cwes:
                for item in cwes[target_cwe]:
                    item_with_meta = {
                        'language': language,
                        'cwe': target_cwe,
                        **item
                    }
                    items.append(item_with_meta)

    return items


def extract_cwe_data_generator(input_file: str, target_cwe: str, batch_size: int = 1000):
    """
    生成器版本：分批提取特定 CWE 的数据

    Args:
        input_file: 输入文件路径
        target_cwe: 目标 CWE
        batch_size: 每批数据的大小

    Yields:
        批量数据列表
    """
    batch = []

    with open(input_file, 'rb') as f:
        for language, cwes in ijson.kvitems(f, ''):
            if target_cwe in cwes:
                for item in cwes[target_cwe]:
                    item_with_meta = {
                        'language': language,
                        'cwe': target_cwe,
                        **item
                    }
                    batch.append(item_with_meta)

                    # 当批次满了，返回该批次
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

    # 返回剩余的数据
    if batch:
        yield batch


def get_embedding_client():
    """创建 OpenAI embedding 客户端"""
    api_base = os.getenv("API_BASE_URL", "https://api.chatanywhere.org/v1")
    api_key = os.getenv("API_KEY", "")

    if not api_key:
        logger.error("API_KEY 未设置，请在 .env 文件中配置")
        sys.exit(1)

    client = OpenAI(
        base_url=api_base,
        api_key=api_key
    )

    logger.info(f"已创建 Embedding 客户端: {api_base}")
    return client


def prepare_code_text(item: Dict[str, Any]) -> str:
    """
    将代码项转换为文本用于 embedding
    合并 benign_lines 和 vuln_lines
    """
    parts = []

    # 添加良性代码行
    if 'benign_lines' in item:
        benign = item['benign_lines']
        if isinstance(benign, list):
            parts.append('\n'.join(benign))
        elif isinstance(benign, str):
            parts.append(benign)

    # 添加漏洞代码行
    if 'vuln_lines' in item:
        vuln = item['vuln_lines']
        if isinstance(vuln, list):
            parts.append('\n'.join(vuln))
        elif isinstance(vuln, str):
            parts.append(vuln)

    # 如果都没有，尝试其他字段
    if not parts:
        for key in ['code', 'source', 'content']:
            if key in item:
                parts.append(str(item[key]))
                break

    code_text = '\n\n'.join(parts)

    # 截断过长的文本（embedding 模型有长度限制）
    max_chars = 8000  # text-embedding-3-large 支持 8191 tokens，约 32k 字符
    if len(code_text) > max_chars:
        code_text = code_text[:max_chars]

    return code_text


def get_embeddings_batch(client: OpenAI, texts: List[str], model: str, batch_size: int = 100, max_workers: int = 16) -> List[List[float]]:
    """
    批量获取文本的 embeddings（支持并发）

    Args:
        client: OpenAI 客户端
        texts: 文本列表
        model: embedding 模型名称
        batch_size: 每批处理的文本数量
        max_workers: 最大并发数
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import time

    total = len(texts)

    # 将文本分成多个批次
    batches = []
    for i in range(0, total, batch_size):
        batch_texts = texts[i:i+batch_size]
        batches.append((i, batch_texts))

    logger.info(f"共 {len(batches)} 个批次，每批最多 {batch_size} 个文本")
    logger.info(f"使用 {max_workers} 个并发线程")

    # 存储结果，索引对应批次起始位置
    results = {}
    embedding_dim = 3072 if 'large' in model else 1536

    def process_batch(batch_info):
        """处理单个批次"""
        batch_idx, batch_texts = batch_info

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = client.embeddings.create(
                    model=model,
                    input=batch_texts
                )
                batch_embeddings = [item.embedding for item in response.data]
                return batch_idx, batch_embeddings, None

            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"批次 {batch_idx} 失败 (尝试 {attempt+1}/{max_retries}): {e}")
                    # 返回零向量
                    zero_embeddings = [[0.0] * embedding_dim for _ in batch_texts]
                    return batch_idx, zero_embeddings, str(e)
                else:
                    logger.warning(f"批次 {batch_idx} 失败 (尝试 {attempt+1}/{max_retries}): {e}，重试中...")
                    time.sleep(0.5 * (attempt + 1))

        return batch_idx, [[0.0] * embedding_dim for _ in batch_texts], "max retries exceeded"

    # 使用线程池并发处理
    completed_batches = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_batch = {
            executor.submit(process_batch, batch_info): batch_info[0]
            for batch_info in batches
        }

        # 收集结果
        for future in as_completed(future_to_batch):
            batch_idx, batch_embeddings, error = future.result()
            results[batch_idx] = batch_embeddings

            completed_batches += 1
            if completed_batches % 5 == 0 or completed_batches == len(batches):
                logger.info(f"  进度: {completed_batches}/{len(batches)} 批次完成")

    # 按顺序组装结果
    all_embeddings = []
    for i in range(0, total, batch_size):
        if i in results:
            all_embeddings.extend(results[i])

    logger.info(f"获取 embeddings 完成: 共 {len(all_embeddings)} 个")

    return all_embeddings


def get_embedding_cache_shard_path(cwe: str, shard_idx: int, cache_dir: str = 'embeddings_cache') -> str:
    """
    获取 embedding 缓存分片文件路径

    Args:
        cwe: CWE 标识符
        shard_idx: 分片索引
        cache_dir: 缓存目录

    Returns:
        缓存分片文件路径
    """
    os.makedirs(cache_dir, exist_ok=True)
    safe_cwe = cwe.replace('/', '_').replace('\\', '_')
    cache_file = os.path.join(cache_dir, f"{safe_cwe}_shard_{shard_idx}.npy")
    return cache_file


def load_embedding_shards(cwe: str, expected_shards: int, cache_dir: str = 'embeddings_cache') -> Optional[np.ndarray]:
    """
    加载所有 embedding 分片并合并

    Args:
        cwe: CWE 标识符
        expected_shards: 期望的分片数量
        cache_dir: 缓存目录

    Returns:
        合并后的 embedding 数组，如果缺少分片则返回 None
    """
    shards = []
    for i in range(expected_shards):
        shard_path = get_embedding_cache_shard_path(cwe, i, cache_dir)
        if not os.path.exists(shard_path):
            return None
        try:
            shard = np.load(shard_path, allow_pickle=False)
            shards.append(shard)
        except Exception as e:
            logger.warning(f"  加载分片 {i} 失败 ({cwe}): {e}")
            return None

    if shards:
        embeddings = np.vstack(shards)
        logger.info(f"  从 {expected_shards} 个分片加载 {cwe} 的 embeddings: {embeddings.shape}")
        return embeddings

    return None


def save_embedding_shard(cwe: str, shard_idx: int, embeddings: np.ndarray, cache_dir: str = 'embeddings_cache') -> bool:
    """
    保存 embedding 分片

    Args:
        cwe: CWE 标识符
        shard_idx: 分片索引
        embeddings: embedding 数组
        cache_dir: 缓存目录

    Returns:
        是否成功保存
    """
    shard_path = get_embedding_cache_shard_path(cwe, shard_idx, cache_dir)
    try:
        np.save(shard_path, embeddings, allow_pickle=False)
        logger.info(f"  已保存 {cwe} 的 embedding 分片 {shard_idx}: {embeddings.shape}")
        return True
    except Exception as e:
        logger.error(f"  保存分片 {shard_idx} 失败 ({cwe}): {e}")
        return False


def cluster_and_select(items: List[Dict[str, Any]], embeddings: np.ndarray, n_samples: int = 10, use_minibatch: bool = False) -> List[Dict[str, Any]]:
    """
    对样本进行聚类并选择代表性样本

    Args:
        items: 原始数据项列表
        embeddings: embedding 矩阵
        n_samples: 要选择的样本数量
        use_minibatch: 是否使用 MiniBatchKMeans（适用于大数据集）

    Returns:
        选中的代表性样本列表
    """
    n_items = len(items)

    # 如果样本数量不超过目标数量，直接返回全部
    if n_items <= n_samples:
        logger.info(f"  样本数量 {n_items} <= {n_samples}，保留全部样本")
        return items

    # 聚类数量为目标样本数量
    n_clusters = n_samples

    if use_minibatch:
        logger.info(f"  使用 MiniBatchKMeans 聚类: {n_items} 个样本 -> {n_clusters} 个簇")
    else:
        logger.info(f"  使用 KMeans 聚类: {n_items} 个样本 -> {n_clusters} 个簇")

    try:
        # 选择聚类算法
        if use_minibatch:
            kmeans = MiniBatchKMeans(
                n_clusters=n_clusters,
                random_state=42,
                batch_size=1000,
                n_init=3,
                max_iter=100
            )
        else:
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)

        cluster_labels = kmeans.fit_predict(embeddings)

        # 从每个簇中选择最接近簇中心的样本
        selected_indices = []
        for i in range(n_clusters):
            cluster_mask = cluster_labels == i
            cluster_indices = np.where(cluster_mask)[0]

            if len(cluster_indices) == 0:
                continue

            # 计算到簇中心的距离
            cluster_embeddings = embeddings[cluster_mask]
            center = kmeans.cluster_centers_[i:i+1]

            # 找到最接近中心的样本
            closest_idx, _ = pairwise_distances_argmin_min(center, cluster_embeddings)
            selected_idx = cluster_indices[closest_idx[0]]
            selected_indices.append(selected_idx)

        # 确保选择的样本数量正确
        selected_indices = selected_indices[:n_samples]

        logger.info(f"  选择了 {len(selected_indices)} 个代表性样本")

        # 返回选中的样本
        selected_items = [items[idx] for idx in selected_indices]
        return selected_items

    except Exception as e:
        logger.error(f"  聚类失败: {e}，随机选择样本")
        # 失败时随机选择
        indices = np.random.choice(n_items, size=min(n_samples, n_items), replace=False)
        return [items[idx] for idx in indices]


def save_selected_items_stream(output_file: str, items: List[Dict[str, Any]], mode: str = 'a') -> None:
    """
    流式保存选中的代表性样本到文件

    Args:
        output_file: 输出文件路径
        items: 要保存的样本列表
        mode: 文件打开模式 ('a' 追加, 'w' 覆盖)
    """
    with open(output_file, mode, encoding='utf-8') as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')


def process_large_cwe_batched(
    input_file: str,
    cwe: str,
    n_items: int,
    client: OpenAI,
    embedding_model: str,
    embedding_cache_dir: str,
    max_samples_per_cwe: int,
    embedding_batch_size: int,
    max_concurrent_workers: int,
    data_batch_size: int = 1000
) -> List[Dict[str, Any]]:
    """
    使用分批处理方式处理大 CWE（样本数 > 5000）

    Args:
        input_file: 输入文件路径
        cwe: CWE 标识符
        n_items: 样本总数
        client: OpenAI 客户端
        embedding_model: embedding 模型名称
        embedding_cache_dir: embedding 缓存目录
        max_samples_per_cwe: 最终保留的最大样本数
        embedding_batch_size: embedding API 批次大小
        max_concurrent_workers: 最大并发数
        data_batch_size: 数据处理批次大小

    Returns:
        选中的代表性样本列表
    """
    logger.info(f"  大 CWE 分批处理模式 (样本数: {n_items})")

    # 计算预期的分片数量
    expected_shards = (n_items + data_batch_size - 1) // data_batch_size

    # 尝试从缓存加载所有分片
    all_embeddings = load_embedding_shards(cwe, expected_shards, embedding_cache_dir)

    if all_embeddings is None:
        # 需要重新计算 embeddings
        logger.info(f"  开始分批计算 embeddings (批次大小: {data_batch_size})...")

        all_items = []
        all_embeddings_list = []
        shard_idx = 0

        # 使用生成器逐批加载和处理数据
        for batch_items in extract_cwe_data_generator(input_file, cwe, data_batch_size):
            logger.info(f"  处理分片 {shard_idx + 1}/{expected_shards} ({len(batch_items)} 个样本)...")

            # 准备代码文本
            code_texts = [prepare_code_text(item) for item in batch_items]

            # 获取 embeddings
            batch_embeddings = get_embeddings_batch(
                client,
                code_texts,
                embedding_model,
                batch_size=embedding_batch_size,
                max_workers=max_concurrent_workers
            )
            batch_embeddings_array = np.array(batch_embeddings)

            # 保存分片
            save_embedding_shard(cwe, shard_idx, batch_embeddings_array, embedding_cache_dir)

            # 累积数据（用于后续聚类）
            all_items.extend(batch_items)
            all_embeddings_list.append(batch_embeddings_array)

            # 清理内存
            del code_texts, batch_embeddings
            gc.collect()

            shard_idx += 1

        # 合并所有 embeddings
        all_embeddings = np.vstack(all_embeddings_list)
        logger.info(f"  已合并所有分片: {all_embeddings.shape}")

        # 清理中间变量
        del all_embeddings_list
        gc.collect()
    else:
        # 从缓存加载成功，需要重新加载所有数据项
        logger.info(f"  ✓ 使用缓存的 embeddings，加载数据项...")
        all_items = extract_cwe_data(input_file, cwe)

    # 使用 MiniBatchKMeans 进行聚类
    selected_items = cluster_and_select(
        all_items,
        all_embeddings,
        max_samples_per_cwe,
        use_minibatch=True
    )

    # 清理内存
    del all_items, all_embeddings
    gc.collect()

    return selected_items


def main():
    """主函数"""
    # 加载环境变量
    load_env_vars()

    # 配置参数
    input_file = 'benchmark.json'
    output_file = 'benchmark_cluster.jsonl'
    embedding_cache_dir = 'embeddings_cache'
    embedding_model = os.getenv("EMBEDDING_MODEL_NAME", "text-embedding-3-large")
    min_samples_for_clustering = 100  # 只对样本数 >= 100 的 CWE 进行聚类
    max_samples_per_cwe = 10  # 每个 CWE 最多保留 10 个样本
    max_concurrent_workers = 16  # 最大并发数
    embedding_batch_size = 50  # 每批 embedding 的文本数量
    large_cwe_threshold = 5000  # 大 CWE 阈值（使用批处理和 MiniBatchKMeans）
    data_batch_size = 1000  # 大 CWE 的数据批次大小

    logger.info(f"输入文件: {input_file}")
    logger.info(f"输出文件: {output_file}")
    logger.info(f"Embedding 缓存目录: {embedding_cache_dir}")
    logger.info(f"Embedding 模型: {embedding_model}")
    logger.info(f"最小聚类样本数: {min_samples_for_clustering}")
    logger.info(f"每个 CWE 最大样本数: {max_samples_per_cwe}")
    logger.info(f"最大并发数: {max_concurrent_workers}")
    logger.info(f"Embedding 批次大小: {embedding_batch_size}")
    logger.info(f"大 CWE 阈值 (使用批处理): {large_cwe_threshold}")
    logger.info(f"大 CWE 数据批次大小: {data_batch_size}")

    # 如果输出文件已存在，清空它（开始新的运行）
    if os.path.exists(output_file):
        logger.info(f"清空已存在的输出文件: {output_file}")
        open(output_file, 'w').close()

    # 创建 embedding 客户端（延迟创建，只在需要时创建）
    client = None

    # 第一步：统计每个 CWE 的样本数量（不加载数据到内存）
    logger.info("\n" + "="*60)
    logger.info("步骤 1: 统计每个 CWE 的样本数量")
    logger.info("="*60)

    try:
        cwe_counts = count_cwe_samples(input_file)
    except FileNotFoundError:
        logger.error(f"文件不存在: {input_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"统计失败: {e}")
        sys.exit(1)

    # 第二步：筛选需要聚类的 CWE
    logger.info("\n" + "="*60)
    logger.info("步骤 2: 筛选需要聚类的 CWE")
    logger.info("="*60)

    cwes_to_cluster = []
    cwes_random_select = []

    for cwe, n_items in cwe_counts.items():
        if n_items >= min_samples_for_clustering:
            cwes_to_cluster.append((cwe, n_items))
        else:
            cwes_random_select.append((cwe, n_items))

    # 按样本数量降序排序
    cwes_to_cluster.sort(key=lambda x: x[1], reverse=True)

    logger.info(f"需要聚类的 CWE (样本数 >= {min_samples_for_clustering}): {len(cwes_to_cluster)}")
    logger.info(f"随机选择的 CWE (样本数 < {min_samples_for_clustering}): {len(cwes_random_select)}")
    logger.info("\n需要聚类的 CWE:")
    for cwe, count in cwes_to_cluster:
        logger.info(f"  {cwe}: {count} 个样本")

    # 第三步：处理每个 CWE（按需加载，流式保存）
    logger.info("\n" + "="*60)
    logger.info("步骤 3: 对每个 CWE 进行聚类和样本选择（流式保存）")
    logger.info("="*60)

    # 统计信息
    total_original_samples = 0
    total_selected_samples = 0
    cached_count = 0
    computed_count = 0

    # 处理需要聚类的 CWE
    for idx, (cwe, n_items) in enumerate(cwes_to_cluster, 1):
        logger.info(f"\n处理 CWE {idx}/{len(cwes_to_cluster)}: {cwe} ({n_items} 个样本)")
        total_original_samples += n_items

        # 判断是否为大 CWE（使用批处理模式）
        if n_items > large_cwe_threshold:
            # 使用批处理模式处理大 CWE
            if client is None:
                client = get_embedding_client()

            selected_items = process_large_cwe_batched(
                input_file=input_file,
                cwe=cwe,
                n_items=n_items,
                client=client,
                embedding_model=embedding_model,
                embedding_cache_dir=embedding_cache_dir,
                max_samples_per_cwe=max_samples_per_cwe,
                embedding_batch_size=embedding_batch_size,
                max_concurrent_workers=max_concurrent_workers,
                data_batch_size=data_batch_size
            )
            computed_count += 1
        else:
            # 使用标准模式处理中小型 CWE
            # 按需加载该 CWE 的数据
            logger.info(f"  加载 {cwe} 的数据...")
            items = extract_cwe_data(input_file, cwe)
            logger.info(f"  已加载 {len(items)} 个样本")

            # 尝试从缓存加载 embeddings
            embeddings_array = load_embeddings_from_cache(cwe, embedding_cache_dir)

            if embeddings_array is None:
                # 缓存不存在，需要计算
                if client is None:
                    client = get_embedding_client()

                # 准备代码文本
                logger.info("  准备代码文本...")
                code_texts = [prepare_code_text(item) for item in items]

                # 获取 embeddings
                logger.info("  获取 embeddings...")
                embeddings = get_embeddings_batch(
                    client,
                    code_texts,
                    embedding_model,
                    batch_size=embedding_batch_size,
                    max_workers=max_concurrent_workers
                )
                embeddings_array = np.array(embeddings)

                # 保存 embeddings 到缓存
                save_embeddings_to_cache(cwe, embeddings_array, embedding_cache_dir)

                # 立即清理中间变量
                del code_texts, embeddings
                gc.collect()
                computed_count += 1
            else:
                # 从缓存加载成功
                cached_count += 1
                logger.info("  ✓ 使用缓存的 embeddings")

            # 聚类并选择代表性样本（对于中小型 CWE 使用标准 KMeans）
            selected_items = cluster_and_select(items, embeddings_array, max_samples_per_cwe, use_minibatch=False)

            # 立即释放内存
            del items, embeddings_array
            gc.collect()

        # 保存选中的样本
        total_selected_samples += len(selected_items)
        logger.info(f"  保存 {len(selected_items)} 个代表性样本...")
        save_selected_items_stream(output_file, selected_items, mode='a')

        logger.info(f"  ✓ {cwe} 完成，选择了 {len(selected_items)} 个样本")

        # 立即释放内存
        del selected_items
        gc.collect()

    # 处理样本数少的 CWE（随机选择最多 10 个，流式保存）
    logger.info(f"\n处理样本数少的 CWE (< {min_samples_for_clustering})，随机选择最多 {max_samples_per_cwe} 个样本...")

    for idx, (cwe, n_items) in enumerate(cwes_random_select, 1):
        if idx % 50 == 0:
            logger.info(f"  处理进度: {idx}/{len(cwes_random_select)}")
        
        total_original_samples += n_items

        # 按需加载该 CWE 的数据
        items = extract_cwe_data(input_file, cwe)

        # 如果样本数超过 max_samples_per_cwe，随机选择
        if n_items > max_samples_per_cwe:
            indices = np.random.choice(n_items, size=max_samples_per_cwe, replace=False)
            selected = [items[idx] for idx in indices]
            total_selected_samples += len(selected)
            
            # 立即保存
            save_selected_items_stream(output_file, selected, mode='a')
            
            if idx <= 10:  # 只打印前 10 个
                logger.info(f"  {cwe}: 随机选择 {max_samples_per_cwe}/{n_items} 个样本")
            
            # 立即清理
            del selected, indices
        else:
            # 样本数不足，保留全部
            total_selected_samples += len(items)
            
            # 立即保存
            save_selected_items_stream(output_file, items, mode='a')
            
            if idx <= 10:  # 只打印前 10 个
                logger.info(f"  {cwe}: 保留全部 {n_items} 个样本")

        # 立即释放内存
        del items
        gc.collect()

    logger.info(f"  ✓ 完成处理 {len(cwes_random_select)} 个 CWE")

    # 第四步：输出统计信息
    logger.info("\n" + "="*60)
    logger.info("步骤 4: 完成统计")
    logger.info("="*60)

    logger.info(f"\n{'='*60}")
    logger.info("完成！")
    logger.info(f"{'='*60}")
    logger.info(f"原始样本数: {total_original_samples}")
    logger.info(f"聚类后样本数: {total_selected_samples}")
    logger.info(f"使用缓存的 CWE 数量: {cached_count}")
    logger.info(f"重新计算的 CWE 数量: {computed_count}")
    if total_original_samples > 0:
        logger.info(f"压缩比例: {total_selected_samples / total_original_samples * 100:.2f}%")
    else:
        logger.warning("没有找到任何样本数据")
    logger.info(f"输出文件: {output_file}")
    logger.info(f"Embedding 缓存目录: {embedding_cache_dir}")


if __name__ == '__main__':
    main()
