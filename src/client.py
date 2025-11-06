###
# File: ./client.py
# Created Date: Friday, October 31st 2025
# Author: Zihan
# -----
# Last Modified: Friday, 31st October 2025 11:30:23 am
# Modified By: the developer formerly known as Zihan at <wzh4464@gmail.com>
# -----
# HISTORY:
# Date      		By   	Comments
# ----------		------	---------------------------------------------------------
###

"""LLM client implementations compatible with SVEN."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
import requests
import time
import logging
import os
from pathlib import Path

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

logger = logging.getLogger(__name__)


def load_env_vars():
    """Load environment variables from .env file"""
    # Try multiple possible locations for .env file
    possible_paths = [
        Path(__file__).parent.parent.parent / '.env',  # From package structure
        Path.cwd() / '.env',  # From current working directory
        Path(__file__).parent.parent.parent.parent / '.env'  # One level up from src
    ]
    
    for env_path in possible_paths:
        if env_path.exists():
            logger.debug(f"Loading .env from: {env_path}")
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
            return
    
    logger.warning("No .env file found in any expected location")


# Load environment variables at module level
load_env_vars()


class LLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from a prompt."""
        pass
    
    @abstractmethod 
    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        """Generate text for multiple prompts."""
        pass


class SVENLLMClient(LLMClient):
    """SVEN-compatible LLM client using custom API endpoints."""
    
    def __init__(
        self,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        max_concurrency: int = 16
    ):
        # Get configuration from environment or parameters
        self.api_base = api_base or os.getenv("API_BASE_URL", "https://api.chatanywhere.tech/v1")
        self.api_key = api_key or os.getenv("API_KEY", "")
        self.model_name = model_name or os.getenv("MODEL_NAME", "gpt-4o")
        self.backup_api_base = os.getenv("BACKUP_API_BASE_URL", "https://newapi.aicohere.org/v1")
        
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_concurrency = max_concurrency
        
        if not self.api_key:
            raise ValueError("API_KEY not found. Please set it in .env file or environment variable.")
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        })
        
        logger.info(f"Initialized SVEN LLM Client with model: {self.model_name}")
        logger.info(f"Primary API: {self.api_base}")
        logger.info(f"Backup API: {self.backup_api_base}")
        logger.info(f"Max concurrency: {self.max_concurrency}")
    
    def _make_request(self, messages: List[Dict], temperature: float = 0.1, max_tokens: int = None) -> str:
        """Make API request with fallback support."""
        data = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature
        }
        if max_tokens is not None:
            data["max_tokens"] = max_tokens
        
        # Try primary API first, then backup API
        apis_to_try = [self.api_base, self.backup_api_base]
        
        for attempt in range(self.max_retries):
            for api_base in apis_to_try:
                try:
                    response = self.session.post(
                        f"{api_base}/chat/completions",
                        json=data,
                        timeout=30
                    )
                    response.raise_for_status()
                    
                    result = response.json()
                    content = result['choices'][0]['message']['content'].strip()
                    
                    logger.debug(f"Successful API call to {api_base}")
                    return content
                    
                except Exception as e:
                    logger.warning(f"API call failed for {api_base} (attempt {attempt + 1}): {e}")
                    if api_base == apis_to_try[-1] and attempt == self.max_retries - 1:
                        raise Exception(f"All API endpoints failed after {self.max_retries} attempts. Last error: {e}")
                    continue
            
            # Wait before next retry
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay * (2 ** attempt))
        
        raise Exception("All API endpoints and retries exhausted")
    
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from a single prompt."""
        messages = [{"role": "user", "content": prompt}]
        
        # Extract parameters
        temperature = kwargs.get("temperature", 0.1)
        max_tokens = kwargs.get("max_tokens", None)
        task = kwargs.get("task", False)
        
        result = self._make_request(messages, temperature, max_tokens)
        
        # Task-oriented truncation (like SVEN)
        if task:
            result = result.split("\n\n")[0]
        
        return result
    
    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        """Generate text for multiple prompts with automatic async optimization and batch processing."""
        batch_size = kwargs.get("batch_size", 8)  # Default batch size is 8
        concurrent = kwargs.get("concurrent", False)  # Default concurrent is False
        
        # Check if we should use async for better performance
        use_async = kwargs.get("use_async", len(prompts) > 5)  # Use async for larger batches
        
        if use_async:
            # Use async client for better performance
            try:
                from .async_client import sven_llm_query_sync
                max_concurrency = kwargs.get("max_concurrency", self.max_concurrency)
                logger.info(f"Using async processing with concurrency {max_concurrency} for {len(prompts)} prompts")
                return sven_llm_query_sync(prompts, max_concurrency=max_concurrency, **kwargs)
            except ImportError:
                logger.warning("Async client not available, falling back to sequential processing")
        
        # Sequential implementation with batch processing
        results = []
        delay = kwargs.get("delay", 0.1 if not use_async else 0)  # No delay for async fallback
        total_prompts = len(prompts)
        
        concurrent_text = "并发" if concurrent else "顺序"
        logger.info(f"Using {concurrent_text} batch processing for {total_prompts} prompts (batch size: {batch_size})")
        
        # Process in batches
        for batch_start in range(0, total_prompts, batch_size):
            batch_end = min(batch_start + batch_size, total_prompts)
            batch_prompts = prompts[batch_start:batch_end]
            
            logger.info(f"Processing batch {batch_start//batch_size + 1}/{(total_prompts + batch_size - 1)//batch_size}: prompts {batch_start+1}-{batch_end}")
            
            if concurrent and len(batch_prompts) > 1:
                # 并发处理模式
                logger.info(f"  🚀 并发处理 {len(batch_prompts)} 个请求")
                batch_results = self._process_batch_concurrent(batch_prompts, **kwargs)
            else:
                # 顺序处理模式
                if concurrent:
                    logger.info(f"  🔄 单个请求，使用顺序处理")
                batch_results = []
                for i, prompt in enumerate(batch_prompts):
                    try:
                        result = self.generate(prompt, **kwargs)
                        batch_results.append(result)
                        
                        # Progress indicator
                        global_idx = batch_start + i + 1
                        if global_idx % 10 == 0:
                            logger.info(f"Processed {global_idx}/{total_prompts} queries")
                        
                        # Rate limiting (skip for concurrent)
                        if delay > 0 and not concurrent:
                            time.sleep(delay)
                            
                    except Exception as e:
                        logger.error(f"Query {batch_start + i + 1} failed: {e}")
                        batch_results.append("error")
            
            results.extend(batch_results)
            
            # Brief rest between batches (only for sequential)
            if batch_end < total_prompts and delay > 0 and not concurrent:
                logger.info(f"Batch {batch_start//batch_size + 1} completed, brief rest...")
                time.sleep(delay * 2)
        
        return results
    
    def _process_batch_concurrent(self, prompts: List[str], **kwargs) -> List[str]:
        """并发处理一个批次的请求"""
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def query_with_retry(prompt):
            """带重试的单次查询"""
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    return self.generate(prompt, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.warning(f"    ⚠️ 请求失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                        return "error"
                    time.sleep(0.5 * (attempt + 1))  # 递增延时
        
        results = ["error"] * len(prompts)  # 预分配结果数组
        
        # 使用线程池并发处理
        with ThreadPoolExecutor(max_workers=min(len(prompts), 8)) as executor:
            # 提交所有任务
            future_to_index = {
                executor.submit(query_with_retry, prompt): i 
                for i, prompt in enumerate(prompts)
            }
            
            # 收集结果
            completed = 0
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result(timeout=30)  # 30秒超时
                    results[index] = result
                except Exception as e:
                    logger.error(f"    ❌ 并发请求 {index + 1} 异常: {e}")
                    results[index] = "error"
                
                completed += 1
                if completed % 4 == 0 or completed == len(prompts):
                    logger.info(f"    📊 并发进度: {completed}/{len(prompts)}")
        
        success_count = sum(1 for r in results if r != "error")
        logger.info(f"    ✅ 并发批次完成: {success_count}/{len(prompts)} 成功")
        
        return results
    
    def paraphrase(self, sentence: Union[str, List[str]], temperature: float = 0.7) -> Union[str, List[str]]:
        """Paraphrase sentences while keeping semantic meaning."""
        if isinstance(sentence, list):
            prompts = [
                f"Generate a variation of the following instruction while keeping the semantic meaning.\nInput: {s}\nOutput:"
                for s in sentence
            ]
            return self.batch_generate(prompts, temperature=temperature)
        else:
            prompt = f"Generate a variation of the following instruction while keeping the semantic meaning.\nInput: {sentence}\nOutput:"
            return self.generate(prompt, temperature=temperature)


class OpenAICompatibleClient(LLMClient):
    """OpenAI-compatible client for ModelScope and other services."""
    
    def __init__(
        self,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None, 
        model_name: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        if not HAS_OPENAI:
            raise ImportError("OpenAI library not installed. Install with: pip install openai")
            
        # Get configuration from environment or parameters
        self.api_base = api_base or os.getenv("API_BASE_URL", "https://api.chatanywhere.tech/v1")
        self.api_key = api_key or os.getenv("API_KEY", "")
        self.model_name = model_name or os.getenv("MODEL_NAME", "gpt-3.5-turbo")
        
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        if not self.api_key:
            raise ValueError("API_KEY not found. Please set it in .env file or environment variable.")
        
        # Initialize OpenAI client
        self.client = OpenAI(
            base_url=self.api_base,
            api_key=self.api_key
        )
        
        logger.info(f"Initialized OpenAI-compatible client with model: {self.model_name}")
        logger.info(f"API Base: {self.api_base}")
    
    def _make_request(self, messages: List[Dict], temperature: float = 0.1, max_tokens: int = None) -> str:
        """Make API request using OpenAI client."""
        for attempt in range(self.max_retries):
            try:
                params = {
                    "model": self.model_name,
                    "messages": messages,
                    "temperature": temperature,
                    "stream": False  # Non-streaming for simplicity
                }
                if max_tokens is not None:
                    params["max_tokens"] = max_tokens
                    
                response = self.client.chat.completions.create(**params)
                
                content = response.choices[0].message.content.strip()
                logger.debug(f"Successful API call (attempt {attempt + 1})")
                return content
                
            except Exception as e:
                logger.warning(f"API call failed (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    raise Exception(f"All API attempts failed. Last error: {e}")
                
                # Exponential backoff
                time.sleep(self.retry_delay * (2 ** attempt))
        
        raise Exception("All API attempts exhausted")
    
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from a single prompt."""
        messages = [{"role": "user", "content": prompt}]
        
        # Extract parameters
        temperature = kwargs.get("temperature", 0.1)
        max_tokens = kwargs.get("max_tokens", None)
        task = kwargs.get("task", False)
        
        result = self._make_request(messages, temperature, max_tokens)
        
        # Task-oriented truncation (like SVEN)
        if task:
            result = result.split("\n\n")[0]
        
        return result
    
    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        """Generate text for multiple prompts with batch processing and concurrent support."""
        results = []
        delay = kwargs.get("delay", 0.1)
        batch_size = kwargs.get("batch_size", 8)  # Default batch size is 8
        concurrent = kwargs.get("concurrent", False)  # Default concurrent is False
        total_prompts = len(prompts)
        
        concurrent_text = "并发" if concurrent else "顺序"
        logger.info(f"Using {concurrent_text} batch processing for {total_prompts} prompts (batch size: {batch_size})")
        
        # Process in batches
        for batch_start in range(0, total_prompts, batch_size):
            batch_end = min(batch_start + batch_size, total_prompts)
            batch_prompts = prompts[batch_start:batch_end]
            
            logger.info(f"Processing batch {batch_start//batch_size + 1}/{(total_prompts + batch_size - 1)//batch_size}: prompts {batch_start+1}-{batch_end}")
            
            if concurrent and len(batch_prompts) > 1:
                # 并发处理模式
                logger.info(f"  🚀 并发处理 {len(batch_prompts)} 个请求")
                batch_results = self._process_batch_concurrent(batch_prompts, **kwargs)
            else:
                # 顺序处理模式
                if concurrent:
                    logger.info(f"  🔄 单个请求，使用顺序处理")
                batch_results = []
                for i, prompt in enumerate(batch_prompts):
                    try:
                        result = self.generate(prompt, **kwargs)
                        batch_results.append(result)
                        
                        # Progress indicator
                        global_idx = batch_start + i + 1
                        if global_idx % 10 == 0:
                            logger.info(f"Processed {global_idx}/{total_prompts} queries")
                        
                        # Rate limiting (skip for concurrent)
                        if delay > 0 and not concurrent:
                            time.sleep(delay)
                            
                    except Exception as e:
                        logger.error(f"Query {batch_start + i + 1} failed: {e}")
                        batch_results.append("error")
            
            results.extend(batch_results)
            
            # Brief rest between batches (only for sequential)
            if batch_end < total_prompts and delay > 0 and not concurrent:
                logger.info(f"Batch {batch_start//batch_size + 1} completed, brief rest...")
                time.sleep(delay * 2)
        
        return results
    
    def _process_batch_concurrent(self, prompts: List[str], **kwargs) -> List[str]:
        """并发处理一个批次的请求"""
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def query_with_retry(prompt):
            """带重试的单次查询"""
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    return self.generate(prompt, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.warning(f"    ⚠️ 请求失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                        return "error"
                    time.sleep(0.5 * (attempt + 1))  # 递增延时
        
        results = ["error"] * len(prompts)  # 预分配结果数组
        
        # 使用线程池并发处理
        with ThreadPoolExecutor(max_workers=min(len(prompts), 8)) as executor:
            # 提交所有任务
            future_to_index = {
                executor.submit(query_with_retry, prompt): i 
                for i, prompt in enumerate(prompts)
            }
            
            # 收集结果
            completed = 0
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result(timeout=30)  # 30秒超时
                    results[index] = result
                except Exception as e:
                    logger.error(f"    ❌ 并发请求 {index + 1} 异常: {e}")
                    results[index] = "error"
                
                completed += 1
                if completed % 4 == 0 or completed == len(prompts):
                    logger.info(f"    📊 并发进度: {completed}/{len(prompts)}")
        
        success_count = sum(1 for r in results if r != "error")
        logger.info(f"    ✅ 并发批次完成: {success_count}/{len(prompts)} 成功")
        
        return results
    
    def paraphrase(self, sentence: Union[str, List[str]], temperature: float = 0.7) -> Union[str, List[str]]:
        """Paraphrase sentences while keeping semantic meaning."""
        if isinstance(sentence, list):
            prompts = [
                f"Generate a variation of the following instruction while keeping the semantic meaning.\nInput: {s}\nOutput:"
                for s in sentence
            ]
            return self.batch_generate(prompts, temperature=temperature)
        else:
            prompt = f"Generate a variation of the following instruction while keeping the semantic meaning.\nInput: {sentence}\nOutput:"
            return self.generate(prompt, temperature=temperature)


class LocalLLMClient(LLMClient):
    """Client for local LLM models (using transformers)."""
    
    def __init__(
        self,
        model_name: str,
        device: str = "auto",
        **model_kwargs
    ):
        self.model_name = model_name
        self.device = device
        self.model_kwargs = model_kwargs
        self._model = None
        self._tokenizer = None
        
    @property
    def model(self):
        """Lazy load model."""
        if self._model is None:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                device_map=self.device,
                **self.model_kwargs
            )
            
            # Add pad token if missing
            if self._tokenizer.pad_token is None:
                self._tokenizer.pad_token = self._tokenizer.eos_token
                
        return self._model, self._tokenizer
        
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text using local model."""
        model, tokenizer = self.model
        
        # Set default parameters
        kwargs.setdefault("max_new_tokens", 150)
        kwargs.setdefault("temperature", 0.7)
        kwargs.setdefault("do_sample", True)
        kwargs.setdefault("pad_token_id", tokenizer.eos_token_id)
        
        # Tokenize input
        inputs = tokenizer(prompt, return_tensors="pt", padding=True)
        
        # Generate
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                **kwargs
            )
            
        # Decode output
        generated_text = tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1]:], 
            skip_special_tokens=True
        )
        
        return generated_text.strip()
        
    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        """Generate text for multiple prompts in batch."""
        model, tokenizer = self.model
        
        # Set default parameters
        kwargs.setdefault("max_new_tokens", 150)  
        kwargs.setdefault("temperature", 0.7)
        kwargs.setdefault("do_sample", True)
        kwargs.setdefault("pad_token_id", tokenizer.eos_token_id)
        
        # Tokenize inputs
        inputs = tokenizer(prompts, return_tensors="pt", padding=True, truncation=True)
        
        # Generate
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                **kwargs
            )
            
        # Decode outputs
        results = []
        for i, output in enumerate(outputs):
            input_length = inputs["input_ids"][i].shape[0]
            generated_text = tokenizer.decode(
                output[input_length:],
                skip_special_tokens=True
            )
            results.append(generated_text.strip())
            
        return results


def create_llm_client(llm_type: str = None, **kwargs) -> LLMClient:
    """Factory function to create LLM clients."""
    # Use OpenAI-compatible client as default (ModelScope)
    if llm_type is None or llm_type in ["openai", "modelscope", "default"]:
        return OpenAICompatibleClient(**kwargs)
    elif llm_type in ["sven"]:
        return SVENLLMClient(**kwargs)
    elif llm_type.startswith("gpt-") or llm_type.startswith("text-davinci") or llm_type.startswith("Qwen/"):
        # Use OpenAI client for OpenAI and Qwen models
        return OpenAICompatibleClient(model_name=llm_type, **kwargs)
    elif llm_type.startswith("kimi"):
        # Use SVEN client for kimi models (requires different API format)
        return SVENLLMClient(model_name=llm_type, **kwargs)
    else:
        # Use local client for local models
        return LocalLLMClient(model_name=llm_type, **kwargs)


# Compatibility functions for SVEN integration - now uses OpenAI client as default
def sven_llm_init(api_base: str = None, api_key: str = None, model_name: str = None):
    """Initialize SVEN-style LLM client (compatibility function) - now uses ModelScope."""
    return OpenAICompatibleClient(api_base, api_key, model_name)


def sven_llm_query(data: Union[str, List[str]], client: LLMClient, task: bool = False, 
                  temperature: float = 0.1, batch_size: int = 8, **kwargs) -> Union[str, List[str]]:
    """
    SVEN-style LLM query function (compatibility function).
    
    Args:
        data: Single prompt or list of prompts
        client: SVEN LLM client
        task: Whether task-oriented (will truncate multi-paragraph responses)
        temperature: Temperature parameter
        batch_size: Batch size for processing, default 8
        **kwargs: Other parameters
    
    Returns:
        Single response or list of responses
    """
    kwargs.update({"task": task, "temperature": temperature, "batch_size": batch_size})
    
    if isinstance(data, list):
        return client.batch_generate(data, **kwargs)
    else:
        return client.generate(data, **kwargs)


# Main entry point - use OpenAI-compatible client as default  
def create_default_client(model_name: Optional[str] = None, api_base: Optional[str] = None, api_key: Optional[str] = None):
    """Create default OpenAI-compatible LLM client for code analysis."""
    model = model_name or os.getenv("MODEL_NAME", None)
    base = api_base or os.getenv("API_BASE_URL", None)
    key = api_key or os.getenv("API_KEY", None)
    return OpenAICompatibleClient(model_name=model, api_base=base, api_key=key)


def create_meta_prompt_client(
    model_name: Optional[str] = None,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
) -> LLMClient:
    """Create LLM client dedicated to meta-prompt evolution."""
    meta_model = model_name or os.getenv("META_MODEL_NAME", "claude-sonnet-4-5-20250929-thinking")
    meta_base = api_base or os.getenv("META_API_BASE_URL") or os.getenv("API_BASE_URL")
    meta_key = api_key or os.getenv("META_API_KEY") or os.getenv("API_KEY")
    return OpenAICompatibleClient(model_name=meta_model, api_base=meta_base, api_key=meta_key)
