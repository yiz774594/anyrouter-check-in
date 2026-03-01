#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


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


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
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


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
				}
		return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


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


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求，返回 (success: bool, already_checked_in: bool)"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True, False
			else:
				error_msg = result.get('msg', result.get('message', 'Unknown error'))
				# 检查是否是"已签到"
				if any(kw in error_msg.lower() for kw in ALREADY_CHECKED_IN_KEYWORDS):
					print(f'[SUCCESS] {account_name}: Already checked in today')
					return True, True
				print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
				return False, False
		except json.JSONDecodeError:
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True, False
			else:
				print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
				return False, False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False, False


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

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'

		if provider_config.needs_manual_check_in():
			# 签到前查询余额
			before_info = get_user_info(client, headers, user_info_url)
			before_quota = None
			if before_info and before_info.get('success'):
				before_quota = before_info['quota']
				print(f'[INFO] {account_name}: Balance before check-in: ${before_quota}')

			# 执行签到
			success, already = execute_check_in(client, account_name, provider_config, headers)

			# 签到后查询余额
			user_info = get_user_info(client, headers, user_info_url)
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
			user_info = get_user_info(client, headers, user_info_url)
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
