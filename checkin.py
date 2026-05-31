#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
import urllib.parse
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'
SAFE_ACCEPT_ENCODING = 'gzip, deflate'
PROXY_ENV_KEYS = ['OUTBOUND_PROXY', 'ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY']
COMPAT_API_USER_KEYS = [
	'new-api-user',
	'New-API-User',
	'Veloera-User',
	'voapi-user',
	'User-id',
	'Rix-Api-User',
	'neo-api-user',
]


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


def resolve_proxy_url() -> str | None:
	"""从环境变量读取代理 URL。"""
	for key in PROXY_ENV_KEYS:
		value = str(os.getenv(key, '') or '').strip()
		if value:
			return value
	return None


def sanitize_proxy_url(proxy_url: str | None) -> str:
	"""隐藏代理凭据，仅保留协议、主机和端口用于日志。"""
	if not proxy_url:
		return ''
	parsed = urllib.parse.urlparse(proxy_url)
	if not parsed.scheme or not parsed.hostname:
		return proxy_url
	host = parsed.hostname
	if ':' in host and not host.startswith('['):
		host = f'[{host}]'
	port_part = f':{parsed.port}' if parsed.port else ''
	return f'{parsed.scheme}://{host}{port_part}'


def parse_playwright_proxy_settings(proxy_url: str | None) -> dict | None:
	"""将代理 URL 转换为 Playwright 需要的 proxy 配置。"""
	if not proxy_url:
		return None
	parsed = urllib.parse.urlparse(proxy_url)
	if not parsed.scheme or not parsed.hostname:
		raise ValueError(f'Invalid proxy URL: {proxy_url}')
	host = parsed.hostname
	if ':' in host and not host.startswith('['):
		host = f'[{host}]'
	server = f'{parsed.scheme}://{host}'
	if parsed.port:
		server += f':{parsed.port}'
	settings = {'server': server}
	if parsed.username:
		settings['username'] = urllib.parse.unquote(parsed.username)
	if parsed.password is not None:
		settings['password'] = urllib.parse.unquote(parsed.password)
	return settings


def create_http_client(proxy_url: str | None = None):
	"""创建 HTTP 客户端；配置了代理时显式走代理，未配置则不走代理。"""
	client_kwargs = {'http2': True, 'timeout': 30.0, 'trust_env': False}
	if proxy_url:
		client_kwargs['proxy'] = proxy_url
	return httpx.Client(**client_kwargs)


def build_base_headers(provider_config, api_user: str) -> dict:
	"""构建 HTTP 请求基础 headers。"""
	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Accept-Encoding': SAFE_ACCEPT_ENCODING,
		'Referer': provider_config.domain,
		'Origin': provider_config.domain,
		'Connection': 'keep-alive',
		'Sec-Fetch-Dest': 'empty',
		'Sec-Fetch-Mode': 'cors',
		'Sec-Fetch-Site': 'same-origin',
	}

	for header_key in [*COMPAT_API_USER_KEYS, provider_config.api_user_key]:
		if header_key:
			headers[header_key] = api_user

	return headers


def build_browser_api_headers(provider_config, api_user: str, include_json_body: bool) -> dict:
	"""构建页面上下文 fetch 可用的 headers。"""
	headers = {
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'X-Requested-With': 'XMLHttpRequest',
	}

	if include_json_body:
		headers['Content-Type'] = 'application/json'

	for header_key in [*COMPAT_API_USER_KEYS, provider_config.api_user_key]:
		if header_key:
			headers[header_key] = api_user

	return headers


def build_playwright_entry_candidates(provider_config, entry_path: str | None = '/console') -> list[str]:
	"""构建浏览器预热页面候选列表，优先控制台页面，其次首页，最后登录页。"""
	candidates = []

	def add_candidate(entry: str | None):
		entry = str(entry or '').strip()
		if not entry:
			return
		if entry.startswith('http://') or entry.startswith('https://'):
			target_url = entry
		else:
			target_url = f"{provider_config.domain}{entry if entry.startswith('/') else '/' + entry}"
		if target_url not in candidates:
			candidates.append(target_url)

	add_candidate(entry_path)
	add_candidate('/console/token')
	add_candidate('/console')
	add_candidate('/')
	add_candidate(provider_config.login_path)
	return candidates


def _contains_already_checked(text: str) -> bool:
	text_lower = str(text or '').lower()
	return any(kw in text_lower for kw in ALREADY_CHECKED_IN_KEYWORDS)


def _safe_response_preview(response, limit: int = 120) -> str:
	raw = getattr(response, 'content', b'')
	if isinstance(raw, bytes):
		text = raw.decode('utf-8', errors='replace')
	else:
		text = str(raw)
	text = text.replace('\r', ' ').replace('\n', ' ')
	return text[:limit]


def _format_user_info_result(data: dict, error_prefix: str = 'Failed to get user info') -> dict:
	if isinstance(data, dict) and data.get('success'):
		user_data = data.get('data', {}) or {}
		quota = round(user_data.get('quota', 0) / 500000, 2)
		used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
		return {
			'success': True,
			'quota': quota,
			'used_quota': used_quota,
			'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
		}

	message = ''
	if isinstance(data, dict):
		message = str(data.get('message') or data.get('msg') or data.get('error') or '').strip()
	if not message:
		message = 'API returned unsuccessful response'
	return {'success': False, 'error': f'{error_prefix}: {message}'}


def _format_check_in_result(payload, response_text: str = '') -> dict:
	if isinstance(payload, dict):
		if payload.get('ret') == 1 or payload.get('code') == 0 or payload.get('success'):
			return {'success': True, 'already': False, 'error': ''}

		error_msg = str(payload.get('msg') or payload.get('message') or payload.get('error') or 'Unknown error')
		if _contains_already_checked(error_msg):
			return {'success': True, 'already': True, 'error': ''}
		return {'success': False, 'already': False, 'error': error_msg}

	if 'success' in str(response_text or '').lower():
		return {'success': True, 'already': False, 'error': ''}

	return {'success': False, 'already': False, 'error': 'Invalid response format'}


def _cookie_domain_matches(cookie_domain: str, host: str) -> bool:
	cookie_host = str(cookie_domain or '').lstrip('.').lower()
	host = str(host or '').lower()
	return bool(cookie_host) and (host == cookie_host or host.endswith('.' + cookie_host))


def _extract_cookie_artifacts(cookie_items: list[dict], host: str) -> tuple[dict, str]:
	cookie_map = {}
	for item in cookie_items or []:
		name = str(item.get('name') or '').strip()
		value = item.get('value')
		domain = item.get('domain')
		if name and value is not None and _cookie_domain_matches(domain, host):
			cookie_map[name] = str(value)
	full_cookie = '; '.join(f'{key}={value}' for key, value in cookie_map.items())
	return cookie_map, full_cookie


def _apply_refreshed_cookies(client, all_cookies: dict, playwright_result: dict):
	cookie_map = dict(playwright_result.get('cookies') or {})
	if cookie_map:
		all_cookies.update(cookie_map)
		if client is not None and getattr(client, 'cookies', None) is not None:
			client.cookies.update(cookie_map)
	return cookie_map


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')
	proxy_settings = parse_playwright_proxy_settings(resolve_proxy_url())

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				proxy=proxy_settings,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in required_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
					await context.close()
					return None

				print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
				await context.close()
				return None


def get_user_info_http(client, headers, user_info_url: str):
	"""通过 HTTP 获取用户信息。"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			try:
				data = response.json()
			except Exception as e:
				preview = _safe_response_preview(response)
				return {
					'success': False,
					'error': f'Failed to get user info: invalid JSON response ({e}). Preview: {preview}',
					'status_code': response.status_code,
				}

			result = _format_user_info_result(data)
			result['status_code'] = response.status_code
			return result

		return {
			'success': False,
			'error': f'Failed to get user info: HTTP {response.status_code}',
			'status_code': response.status_code,
		}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:120]}', 'status_code': 0}


async def perform_playwright_api_request(
	account_name: str,
	account: AccountConfig,
	provider_config,
	all_cookies: dict,
	url: str,
	method: str = 'GET',
	payload: dict | None = None,
	entry_path: str | None = '/console',
):
	"""在浏览器页面上下文中执行 API 请求。"""
	print(f'[PROCESSING] {account_name}: Retrying via Playwright page context...')

	parsed = urllib.parse.urlparse(provider_config.domain)
	if not parsed.scheme or not parsed.hostname:
		return {'ok': False, 'status_code': 0, 'error': f'Invalid provider domain: {provider_config.domain}'}
	proxy_settings = parse_playwright_proxy_settings(resolve_proxy_url())

	cookies = []
	for name, value in (all_cookies or {}).items():
		cookies.append(
			{
				'name': str(name),
				'value': str(value),
				'domain': parsed.hostname,
				'path': '/',
				'secure': parsed.scheme == 'https',
			}
		)

	entry_candidates = build_playwright_entry_candidates(provider_config, entry_path)

	async with async_playwright() as p:
		browser = await p.chromium.launch(
			headless=True,
			proxy=proxy_settings,
			args=[
				'--disable-blink-features=AutomationControlled',
				'--disable-dev-shm-usage',
				'--disable-web-security',
				'--disable-features=VizDisplayCompositor',
				'--no-sandbox',
			],
		)
		context = await browser.new_context(
			user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			viewport={'width': 1920, 'height': 1080},
		)
		try:
			if cookies:
				await context.add_cookies(cookies)

			page = await context.new_page()
			last_error = None
			for target_url in entry_candidates:
				try:
					await page.goto(target_url, wait_until='domcontentloaded', timeout=60000)
					await page.wait_for_timeout(1200)
					last_error = None
					break
				except Exception as e:
					last_error = e

			if last_error is not None:
				return {'ok': False, 'status_code': 0, 'error': f'Unable to open provider page: {last_error}'}

			js_headers = build_browser_api_headers(provider_config, account.api_user, method.upper() != 'GET')
			result = await page.evaluate(
				"""
				async ({ url, method, headers, payload }) => {
					try {
						const options = { method, headers, credentials: 'include' };
						if (payload !== null && payload !== undefined) {
							options.body = JSON.stringify(payload);
						}
						const resp = await fetch(url, options);
						const text = await resp.text();
						let body = null;
						try {
							body = text ? JSON.parse(text) : null;
						} catch (e) {}
						return { ok: resp.ok, status_code: resp.status, body, text };
					} catch (error) {
						return { ok: false, status_code: 0, error: String(error), body: null, text: '' };
					}
				}
				""",
				{'url': url, 'method': method.upper(), 'headers': js_headers, 'payload': payload},
			)
			browser_cookies, full_cookie = _extract_cookie_artifacts(await context.cookies(), parsed.hostname)
			if isinstance(result, dict):
				result.setdefault('cookies', browser_cookies)
				result.setdefault('full_cookie', full_cookie)
				return result
			return {
				'ok': False,
				'status_code': 0,
				'error': 'Invalid Playwright response',
				'cookies': browser_cookies,
				'full_cookie': full_cookie,
			}
		finally:
			await context.close()
			await browser.close()


async def get_user_info_with_fallback(
	client,
	headers: dict,
	user_info_url: str,
	account_name: str,
	account: AccountConfig,
	provider_config,
	all_cookies: dict,
):
	"""HTTP 失败后回退 Playwright 获取用户信息。"""
	http_result = get_user_info_http(client, headers, user_info_url)
	if http_result.get('success'):
		return http_result

	playwright_result = await perform_playwright_api_request(
		account_name,
		account,
		provider_config,
		all_cookies,
		user_info_url,
		method='GET',
		entry_path='/console',
	)
	if _apply_refreshed_cookies(client, all_cookies, playwright_result):
		retry_result = get_user_info_http(client, headers, user_info_url)
		if retry_result.get('success'):
			return retry_result

	if playwright_result.get('ok'):
		result = _format_user_info_result(playwright_result.get('body') or {})
		result['status_code'] = playwright_result.get('status_code', 0)
		if result.get('success'):
			return result
		if playwright_result.get('text'):
			result['error'] = f"{result['error']}. Preview: {str(playwright_result.get('text'))[:120]}"
		return result

	return {
		'success': False,
		'error': playwright_result.get('error') or http_result.get('error', 'Failed to get user info'),
		'status_code': playwright_result.get('status_code', http_result.get('status_code', 0)),
	}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


ALREADY_CHECKED_IN_KEYWORDS = ['已经签到', '已签到', '签过到', 'already', 'already checked', 'already signed']


def execute_check_in_http(client, account_name: str, provider_config, headers: dict) -> dict:
	"""执行 HTTP 签到请求。"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, json={}, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
		except Exception:
			result = None

		check_in_result = _format_check_in_result(result, _safe_response_preview(response))
		check_in_result['status_code'] = response.status_code
		if check_in_result['success'] and check_in_result.get('already'):
			print(f'[SUCCESS] {account_name}: Already checked in today')
		elif check_in_result['success']:
			print(f'[SUCCESS] {account_name}: Check-in successful!')
		else:
			print(f'[FAILED] {account_name}: Check-in failed - {check_in_result["error"]}')
		return check_in_result

	print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
	return {'success': False, 'already': False, 'error': f'HTTP {response.status_code}', 'status_code': response.status_code}


async def execute_check_in_with_fallback(
	client,
	account_name: str,
	account: AccountConfig,
	provider_config,
	headers: dict,
	all_cookies: dict,
) -> dict:
	"""HTTP 失败后回退 Playwright 执行签到。"""
	http_result = execute_check_in_http(client, account_name, provider_config, headers)
	if http_result.get('success'):
		return http_result

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	playwright_result = await perform_playwright_api_request(
		account_name,
		account,
		provider_config,
		all_cookies,
		sign_in_url,
		method='POST',
		payload={},
		entry_path='/console',
	)
	if _apply_refreshed_cookies(client, all_cookies, playwright_result):
		retry_result = execute_check_in_http(client, account_name, provider_config, headers)
		if retry_result.get('success'):
			return retry_result

	if playwright_result.get('ok'):
		check_in_result = _format_check_in_result(playwright_result.get('body'), playwright_result.get('text', ''))
		check_in_result['status_code'] = playwright_result.get('status_code', 0)
		print(f'[RESPONSE] {account_name}: Playwright response status code {check_in_result["status_code"]}')
		if check_in_result['success'] and check_in_result.get('already'):
			print(f'[SUCCESS] {account_name}: Already checked in today')
		elif check_in_result['success']:
			print(f'[SUCCESS] {account_name}: Check-in successful!')
		else:
			print(f'[FAILED] {account_name}: Check-in failed - {check_in_result["error"]}')
		return check_in_result

	return {
		'success': False,
		'already': False,
		'error': playwright_result.get('error') or http_result.get('error', 'Check-in failed'),
		'status_code': playwright_result.get('status_code', http_result.get('status_code', 0)),
	}


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None

	proxy_url = resolve_proxy_url()
	client = create_http_client(proxy_url)

	try:
		client.cookies.update(all_cookies)

		headers = build_base_headers(provider_config, account.api_user)

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'

		if provider_config.needs_manual_check_in():
			# 签到前查询余额
			before_info = await get_user_info_with_fallback(
				client, headers, user_info_url, account_name, account, provider_config, all_cookies
			)
			before_quota = None
			if before_info and before_info.get('success'):
				before_quota = before_info['quota']
				print(f'[INFO] {account_name}: Balance before check-in: ${before_quota}')

			# 执行签到
			check_in_result = await execute_check_in_with_fallback(
				client, account_name, account, provider_config, headers, all_cookies
			)
			success = check_in_result.get('success', False)
			already = check_in_result.get('already', False)

			# 签到后查询余额
			user_info = await get_user_info_with_fallback(
				client, headers, user_info_url, account_name, account, provider_config, all_cookies
			)
			if user_info and user_info.get('success'):
				print(user_info['display'])
				if already:
					user_info['already'] = True
				elif before_quota is not None:
					reward = round(user_info['quota'] - before_quota, 2)
					user_info['reward'] = reward
					if reward > 0:
						print(f'[INFO] {account_name}: Check-in reward: +${reward}')
			elif user_info:
				print(user_info.get('error', 'Unknown error'))

			return success, user_info
		else:
			# 查询用户信息时自动完成签到
			user_info = await get_user_info_with_fallback(
				client, headers, user_info_url, account_name, account, provider_config, all_cookies
			)
			if user_info and user_info.get('success'):
				print(user_info['display'])
			elif user_info:
				print(user_info.get('error', 'Unknown error'))
			print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
			return True, user_info

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, None
	finally:
		client.close()


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
	proxy_url = resolve_proxy_url()
	if proxy_url:
		print(f'[INFO] Outbound proxy enabled: {sanitize_proxy_url(proxy_url)}')
	else:
		print('[INFO] Outbound proxy disabled')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')

	accounts = load_accounts_config()
	if not accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	notification_content = []
	current_balances = {}
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	# 并发签到，最多同时3个
	MAX_CONCURRENT = 3
	semaphore = asyncio.Semaphore(MAX_CONCURRENT)
	print(f'[INFO] Concurrency limit: {MAX_CONCURRENT}')

	# 按索引预分配结果槽位，保证顺序
	results = [None] * total_count

	async def process_account(i, account):
		"""带信号量的单账号处理"""
		async with semaphore:
			try:
				success, user_info = await check_in_account(account, i, app_config)
				return i, success, user_info
			except Exception as e:
				account_name = account.get_display_name(i)
				print(f'[FAILED] {account_name} processing exception: {e}')
				return i, False, {'error': str(e)[:50]}

	# 并发执行所有账号
	tasks = [process_account(i, account) for i, account in enumerate(accounts)]
	results = await asyncio.gather(*tasks)

	# 按原始顺序处理结果
	for i, success, user_info in results:
		account = accounts[i]
		account_key = f'account_{i + 1}'

		if success:
			success_count += 1

		should_notify_this_account = False

		if not success:
			should_notify_this_account = True
			need_notify = True
			account_name = account.get_display_name(i)
			print(f'[NOTIFY] {account_name} failed, will send notification')

		if user_info and isinstance(user_info, dict) and user_info.get('success'):
			current_quota = user_info['quota']
			current_used = user_info['used_quota']
			reward = user_info.get('reward')
			already = user_info.get('already', False)
			current_balances[account_key] = {'quota': current_quota, 'used': current_used, 'reward': reward, 'already': already}

		if should_notify_this_account:
			account_name = account.get_display_name(i)
			icon = '\u2705' if success else '\u274c'
			already = user_info.get('already', False) if isinstance(user_info, dict) else False
			suffix = '  <i>(already checked in)</i>' if already else ''
			line = f'{icon} <b>{account_name}</b>{suffix}'
			if isinstance(user_info, dict) and user_info.get('success'):
				line += f'\n    \U0001f4b0 ${user_info["quota"]}  \u2502  Used ${user_info["used_quota"]}'
				reward = user_info.get('reward')
				if reward is not None and reward > 0:
					line += f'\n    \U0001f381 Reward <b>+${reward}</b>'
			elif isinstance(user_info, dict) and 'error' in user_info:
				line += f'\n    \u26a0\ufe0f {user_info.get("error", "Unknown error")}'
			notification_content.append(line)

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		# 收集已在通知中的账号名（精确匹配，避免子串误判）
		notified_names = set()
		for item in notification_content:
			for i2, acc2 in enumerate(accounts):
				n = acc2.get_display_name(i2)
				if f'<b>{n}</b>' in item:
					notified_names.add(n)

		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in current_balances:
				account_name = account.get_display_name(i)
				bal = current_balances[account_key]
				already = bal.get('already', False)
				suffix = '  <i>(already checked in)</i>' if already else ''
				line = f'\u2705 <b>{account_name}</b>{suffix}'
				line += f'\n    \U0001f4b0 ${bal["quota"]}  \u2502  Used ${bal["used"]}'
				reward = bal.get('reward')
				if reward is not None and reward > 0:
					line += f'\n    \U0001f381 Reward <b>+${reward}</b>'
				# 检查是否已经在通知内容中（避免重复，使用精确匹配）
				if account_name not in notified_names:
					notification_content.append(line)
					notified_names.add(account_name)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify and notification_content:
		# 构建通知内容
		failed_count = total_count - success_count
		if success_count == total_count:
			status_line = f'\u2705 All {total_count} accounts successful'
		elif success_count > 0:
			status_line = f'\u26a0\ufe0f {success_count} success / {failed_count} failed'
		else:
			status_line = f'\u274c All {total_count} accounts failed'

		header = f'\U0001f4cb <b>Check-in Report</b>\n\u23f0 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\U0001f4ca {status_line}'
		separator = '\u2500' * 20
		accounts_block = '\n\n'.join(f'<b>{idx+1}.</b> {item}' for idx, item in enumerate(notification_content))
		notify_content = f'{header}\n\n{separator}\n\n{accounts_block}\n\n{separator}'

		print(notify_content)
		notify.push_message('\U0001f4cb AnyRouter Check-in', notify_content, msg_type='html')
		print('[NOTIFY] Notification sent due to failures or balance changes')
	else:
		print('[INFO] All accounts successful and no balance changes detected, notification skipped')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
