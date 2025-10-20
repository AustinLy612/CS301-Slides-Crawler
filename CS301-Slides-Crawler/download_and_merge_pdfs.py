#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Optional

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from tqdm import tqdm
from pypdf import PdfWriter, PdfReader

# ------------ 日志配置 ------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger("pdf_crawler")

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

REQUEST_TIMEOUT = (10, 30)  # (连接超时, 读取超时)
CHUNK_SIZE = 1024 * 256     # 256KB

# ------------ 工具函数 ------------

def fetch_html(url: str, session: Session) -> str:
    """获取网页 HTML 内容（使用登录会话）。"""
    logger.info(f"获取网页: {url}")
    try:
        resp = session.get(url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}: 无法访问 {url}")
        resp.encoding = resp.encoding or resp.apparent_encoding
        return resp.text
    except requests.RequestException as e:
        raise RuntimeError(f"网络错误: {e}") from e


def _is_pdf_url(href: Optional[str]) -> bool:
    if not href:
        return False
    # 允许大小写变体及带 query 的情况
    parsed = urlparse(href)
    path = parsed.path.lower()
    return path.endswith(".pdf")


def filename_from_url(pdf_url: str) -> str:
    """根据 URL 提取文件名（无 query），如无文件名则生成安全名称。"""
    parsed = urlparse(pdf_url)
    name = os.path.basename(parsed.path)
    if not name:
        # 兜底：将域名和路径组合为安全名称
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.netloc + parsed.path)
        return safe or "file.pdf"
    return name


def extract_number_from_name(name: str) -> Optional[int]:
    """从文件名中提取第一个连续数字，若无则返回 None。"""
    m = re.search(r"(\d+)", name)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def natural_sort_key(name: str) -> Tuple:
    """用于无数字文件的次级排序键：不区分大小写的字母数字拆分。"""
    return tuple(int(text) if text.isdigit() else text.lower() for text in re.findall(r"\d+|\D+", name))


def find_pdf_links(html: str, base_url: str) -> List[Tuple[str, str]]:
    """在 HTML 中查找所有 PDF 链接，返回 (绝对URL, 文件名)。"""
    soup = BeautifulSoup(html, "html.parser")
    candidates: List[str] = []

    # a 标签
    for a in soup.find_all("a"):
        href = a.get("href")
        if _is_pdf_url(href):
            candidates.append(href)

    # 其他可能嵌入 PDF 的标签
    for tag_name in ("iframe", "embed", "object"):
        for tag in soup.find_all(tag_name):
            src = tag.get("src") or tag.get("data")
            if _is_pdf_url(src):
                candidates.append(src)

    # 去重并规范化
    abs_urls = []
    seen = set()
    for href in candidates:
        abs_url = urljoin(base_url, href)
        if abs_url not in seen:
            seen.add(abs_url)
            abs_urls.append(abs_url)

    results: List[Tuple[str, str]] = []
    for url in abs_urls:
        name = filename_from_url(url)
        results.append((url, name))

    return results


def sort_by_numeric_then_name(items: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """按文件名中的数字编号排序；无数字的排在后面，内部自然排序。"""
    def key(item: Tuple[str, str]):
        _, name = item
        num = extract_number_from_name(name)
        return (
            1 if num is None else 0,  # 先有数字的
            10**12 if num is None else num,  # 无数字的统一大值
            natural_sort_key(name),
        )

    return sorted(items, key=key)


def download_file(url: str, dest_path: Path, session: Session) -> None:
    """下载单个文件（带进度与错误处理，使用会话）。"""
    try:
        with session.get(url, headers=DEFAULT_HEADERS, stream=True, timeout=REQUEST_TIMEOUT) as r:
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}: 下载失败 {url}")
            total = int(r.headers.get("Content-Length")) if r.headers.get("Content-Length") else None
            with open(dest_path, "wb") as f, tqdm(
                total=total,
                unit="B",
                unit_scale=True,
                desc=dest_path.name,
                disable=total is None,
            ) as pbar:
                for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                    if chunk:
                        f.write(chunk)
                        if total is not None:
                            pbar.update(len(chunk))
    except requests.RequestException as e:
        raise RuntimeError(f"网络错误: {e}") from e
    except OSError as e:
        raise RuntimeError(f"文件写入错误: {dest_path} -> {e}") from e


def merge_pdfs(pdf_paths: List[Path], output_path: Path) -> None:
    """将多个 PDF 合并为一个文件。"""
    writer = PdfWriter()
    for path in pdf_paths:
        try:
            reader = PdfReader(str(path))
            for page in reader.pages:
                writer.add_page(page)
        except Exception as e:
            raise RuntimeError(f"合并失败: 无法读取 {path.name} -> {e}") from e

    try:
        with open(output_path, "wb") as f:
            writer.write(f)
    except OSError as e:
        raise RuntimeError(f"输出文件写入失败: {output_path} -> {e}") from e


def cleanup_downloads(pdf_paths: List[Path]) -> None:
    errors = []
    for p in pdf_paths:
        try:
            if p.exists() and p.is_file() and p.suffix.lower() == ".pdf":
                p.unlink()
                logger.info(f"已删除: {p.name}")
        except Exception as e:
            errors.append(f"{p}: {e}")
    if errors:
        logger.warning("部分文件删除失败: " + "; ".join(errors))


# ------------ 主流程 ------------

def main_multi(urls: List[str], out_dir: Path, output_file: Path, session: Session) -> None:
    all_pdfs: List[Tuple[str, str]] = []
    for u in urls:
        html = fetch_html(u, session)
        pdfs = find_pdf_links(html, u)
        all_pdfs.extend(pdfs)
    # 跨页面去重
    dedup: List[Tuple[str, str]] = []
    seen = set()
    for pdf_url, name in all_pdfs:
        if pdf_url not in seen:
            seen.add(pdf_url)
            dedup.append((pdf_url, name))
    if not dedup:
        raise RuntimeError("未在提供的页面中发现任何 PDF 链接。若页面需要登录或权限，请检查访问配置。")
    sorted_pdfs = sort_by_numeric_then_name(dedup)
    out_dir.mkdir(parents=True, exist_ok=True)
    downloaded_paths: List[Path] = []
    for pdf_url, name in sorted_pdfs:
        dest = out_dir / name
        logger.info(f"下载: {name} <- {pdf_url}")
        download_file(pdf_url, dest, session)
        downloaded_paths.append(dest)
    logger.info(f"合并 {len(downloaded_paths)} 个 PDF -> {output_file}")
    merge_pdfs(downloaded_paths, output_file)
    logger.info("合并完成")
    cleanup_downloads(downloaded_paths)
    logger.info("已删除下载的 PDF 文件")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="从网页下载并合并 PDF 文件（支持登录；URL 终端输入）")
    parser.add_argument(
        "--out-dir",
        default="downloads",
        help="PDF 下载保存目录（默认: downloads）",
    )
    parser.add_argument(
        "--output",
        default="merged.pdf",
        help="合并输出的 PDF 文件路径（默认: merged.pdf）",
    )
    # 登录相关参数
    parser.add_argument("--login-url", default=None, help="登录页面或登录接口的 URL")
    parser.add_argument("--username", default=None, help="登录用户名")
    parser.add_argument("--password", default=None, help="登录密码")
    parser.add_argument("--user-field", default="username", help="用户名字段名（默认: username）")
    parser.add_argument("--pass-field", default="password", help="密码字段名（默认: password）")
    parser.add_argument("--extra-field", action="append", default=[], help="附加字段，如 key=value，可重复")
    parser.add_argument("--cookie-header", default=None, help="直接提供 Cookie 头，用于已登录会话")
    parser.add_argument("--auth-token", default=None, help="提供 Bearer Token 进行鉴权")
    parser.add_argument("--login-method", choices=["POST", "GET"], default="POST", help="登录请求方法，默认 POST")
    parser.add_argument("--login-success-pattern", default=None, help="登录成功的页面文本标识，用于校验")
    return parser.parse_args(argv)


def _parse_kv_pairs(pairs: Optional[List[str]]) -> dict:
    data = {}
    if not pairs:
        return data
    for item in pairs:
        if "=" not in item:
            logger.warning(f"忽略无效 extra-field: {item}")
            continue
        k, v = item.split("=", 1)
        data[k] = v
    return data


def _extract_hidden_inputs(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    hidden = {}
    for inp in soup.find_all("input"):
        typ = (inp.get("type") or "").lower()
        name = inp.get("name")
        if typ == "hidden" and name:
            hidden[name] = inp.get("value") or ""
    return hidden


def perform_login(session: Session, login_url: str, username: Optional[str], password: Optional[str], user_field: str, pass_field: str, extra_fields: dict, method: str = "POST", success_pattern: Optional[str] = None) -> None:
    """执行通用表单登录（可带隐藏字段/额外字段）。"""
    if not login_url:
        return
    if not username or password is None:
        logger.warning("已提供 login-url，但未提供用户名或密码，跳过登录。")
        return
    try:
        pre = session.get(login_url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        if pre.status_code != 200:
            raise RuntimeError(f"无法访问登录页: HTTP {pre.status_code}")
        base_payload = _extract_hidden_inputs(pre.text)
        base_payload[user_field] = username
        base_payload[pass_field] = password
        base_payload.update(extra_fields or {})
        if method.upper() == "GET":
            resp = session.get(login_url, params=base_payload, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        else:
            resp = session.post(login_url, data=base_payload, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        if resp.status_code not in (200, 302):
            raise RuntimeError(f"登录失败: HTTP {resp.status_code}")
        if success_pattern and success_pattern not in resp.text:
            raise RuntimeError("登录可能失败：未匹配到成功标识。")
        logger.info("登录完成，已建立会话。")
    except requests.RequestException as e:
        raise RuntimeError(f"登录网络错误: {e}") from e


def build_session(args) -> Session:
    """创建并配置会话，支持 Cookie/Bearer 以及表单登录。"""
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    if getattr(args, "cookie_header", None):
        s.headers["Cookie"] = args.cookie_header
    if getattr(args, "auth_token", None):
        s.headers["Authorization"] = f"Bearer {args.auth_token}"
    extra = _parse_kv_pairs(getattr(args, "extra_field", None))
    perform_login(
        s,
        getattr(args, "login_url", None),
        getattr(args, "username", None),
        getattr(args, "password", None),
        getattr(args, "user_field", "username"),
        getattr(args, "pass_field", "password"),
        extra,
        getattr(args, "login_method", "POST"),
        getattr(args, "login_success_pattern", None),
    )
    return s


def prompt_urls() -> List[str]:
    print("请输入要爬取的网页 URL（每行一个，空行结束）：")
    urls: List[str] = []
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
        if not line:
            break
        urls.append(line)
    if not urls:
        raise RuntimeError("未输入任何 URL。")
    return urls


if __name__ == "__main__":
    args = parse_args()
    try:
        urls = prompt_urls()
        session = build_session(args)
        main_multi(urls, Path(args.out_dir), Path(args.output), session)
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)