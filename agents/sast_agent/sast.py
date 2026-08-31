import os
import re
import json
import uuid
import datetime
import hashlib
import math
import sys
import ast
import concurrent.futures
import urllib.request
import urllib.parse
import urllib.error
import tempfile
import subprocess
import shutil
import random
import time
import textwrap
import ssl
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque

# --- Terminal Colors for Fancy Output ---
class Colors:
	HEADER = '\033[95m'
	BLUE = '\033[94m'
	CYAN = '\033[96m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	MAGENTA = '\033[35m'
	WHITE = '\033[97m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	DIM = '\033[2m'
	END = '\033[0m'
	BG_RED = '\033[41m'
	BG_GREEN = '\033[42m'

# --- GitDumper Integration Class ---
class GitDumper:
	"""
	Integrates logic to dump exposed .git directories from a web server.
	Adapted from GitDumper (https://github.com/internetwache/GitTools)
	"""
	def __init__(self, base_url: str, dest_dir: str):
		self.base_url = base_url
		self.dest_dir = dest_dir
		self.git_dir = os.path.join(dest_dir, ".git")
		self.queue = deque()
		self.downloaded = set()

		# Setup SSL context to ignore verification errors (equivalent to curl -k)
		self.ssl_context = ssl.create_default_context()
		self.ssl_context.check_hostname = False
		self.ssl_context.verify_mode = ssl.CERT_NONE

		# Ensure destination directory exists
		if not os.path.exists(self.git_dir):
			os.makedirs(self.git_dir)

	def _download_item(self, objname: str):
		# Check if already downloaded
		if objname in self.downloaded:
			return

		url = self.base_url + objname
		target = os.path.join(self.git_dir, objname)

		# Create folder structure
		obj_dir = os.path.dirname(objname)
		if obj_dir:
			full_dir_path = os.path.join(self.git_dir, obj_dir)
			if not os.path.exists(full_dir_path):
				os.makedirs(full_dir_path, exist_ok=True)

		# Download file
		req = urllib.request.Request(
			url,
			headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"}
		)

		file_exists = False
		try:
			with urllib.request.urlopen(req, context=self.ssl_context, timeout=10) as response:
				content = response.read()
				with open(target, "wb") as f:
					f.write(content)
				file_exists = True
		except urllib.error.HTTPError:
			pass
		except urllib.error.URLError:
			pass
		except Exception:
			pass

		self.downloaded.add(objname)

		if not file_exists or not os.path.exists(target):
			return

		# print(f"{Colors.GREEN}[+] Downloaded: {objname}{Colors.END}")

		hashes = []
		packs = []

		# Read file content for parsing
		with open(target, "rb") as f:
			target_content = f.read()

		# Check if we have an object hash
		if re.search(r'/[a-f0-9]{2}/[a-f0-9]{38}', objname):
			cwd = os.getcwd()
			os.chdir(self.dest_dir)

			try:
				clean_hash = objname.replace("objects", "").replace("/", "")

				# Check if it's a valid git object and parse it
				try:
					type_proc = subprocess.run(
						["git", "cat-file", "-t", clean_hash],
						capture_output=True,
						text=True,
						timeout=5
					)

					if type_proc.returncode == 0:
						cat_proc = subprocess.run(
							["git", "cat-file", "-p", clean_hash],
							capture_output=True,
							timeout=5
						)

						if cat_proc.stdout:
							found_hashes = re.findall(rb'[a-f0-9]{40}', cat_proc.stdout)
							hashes.extend([h.decode('ascii') for h in found_hashes])
					else:
						# Invalid git object, delete file
						if os.path.exists(target):
							os.remove(target)
						os.chdir(cwd)
						return
				except subprocess.CalledProcessError:
					if os.path.exists(target):
						os.remove(target)
					os.chdir(cwd)
					return
				except subprocess.TimeoutExpired:
					pass
				except Exception:
					pass

			finally:
				os.chdir(cwd)

		# Parse file for other objects (hashes)
		try:
			text_content = target_content.decode('utf-8', errors='ignore')
			raw_hashes = re.findall(r'[a-f0-9]{40}', text_content)
			hashes.extend(raw_hashes)
		except Exception:
			pass

		# Parse file for packs
		try:
			text_content = target_content.decode('utf-8', errors='ignore')
			raw_packs = re.findall(r'(pack\-[a-f0-9]{40})', text_content)
			packs.extend(raw_packs)
		except Exception:
			pass

		# Update QUEUE for hashes
		for h in set(hashes):
			new_item = f"objects/{h[:2]}/{h[2:]}"
			self.queue.append(new_item)

		# Update QUEUE for packs
		for p in set(packs):
			self.queue.append(f"objects/pack/{p}.pack")
			self.queue.append(f"objects/pack/{p}.idx")

	def dump(self):
		# Populate initial queue
		initial_files = [
			'HEAD', 'objects/info/packs', 'description', 'config', 'COMMIT_EDITMSG',
			'index', 'packed-refs', 'refs/heads/master', 'refs/remotes/origin/HEAD',
			'refs/stash', 'logs/HEAD', 'logs/refs/heads/master',
			'logs/refs/remotes/origin/HEAD', 'info/refs', 'info/exclude',
			'refs/wip/index/refs/heads/master', 'refs/wip/wtree/refs/heads/master'
		]

		print(f"{Colors.DIM}[*] Initializing download queue with {len(initial_files)} bootstrap files...{Colors.END}")
		for f in initial_files:
			self.queue.append(f)

		count = 0
		print(f"{Colors.YELLOW}[*] Starting recursive download...{Colors.END}")
		while self.queue:
			self._download_item(self.queue.popleft())
			count += 1
			# Print progress every 100 files
			if count % 100 == 0:
				print(f"{Colors.DIM}[*] Downloaded {count} objects...{Colors.END}")

		print(f"{Colors.GREEN}[+] Download finished. Total items processed: {count}{Colors.END}")


# --- GitExtractor Integration Class ---
class GitExtractor:
	"""
	Integrates logic to extract commits and their content from a broken Git repository.
	Adapted from Extractor (https://github.com/internetwache/GitTools)
	"""
	def __init__(self, git_repo_path: str, extract_dest: str):
		self.git_repo = os.path.abspath(git_repo_path)
		self.dest_dir = os.path.abspath(extract_dest)
		self.objects_path = os.path.join(self.git_repo, ".git", "objects")

		# Create destination folder
		os.makedirs(self.dest_dir, exist_ok=True)

	def _run_git_command(self, args, capture_output=False, text=False, binary=False):
		"""
		Helper to run git commands safely with timeout.
		Returns subprocess.CompletedProcess object or None on failure.
		"""
		try:
			result = subprocess.run(
				['git'] + args, 
				cwd=self.git_repo, 
				capture_output=capture_output, 
				text=text if not binary else False,
				timeout=10 
			)
			return result
		except subprocess.TimeoutExpired:
			return None
		except FileNotFoundError:
			print(f"{Colors.RED}[!] Error: git command not found. Ensure Git is installed.{Colors.END}")
			return None
		except Exception:
			return None

	def _traverse_tree(self, tree_hash, path):
		"""
		Recursively traverses a git tree object and extracts files/folders.
		"""
		# Read blobs/tree information from root tree
		cmd = ['ls-tree', tree_hash]
		result = self._run_git_command(cmd, capture_output=True, text=True)

		if not result or result.returncode != 0:
			return

		lines = result.stdout.splitlines()

		for line in lines:
			# git ls-tree format: mode type hash\tfilename
			# Splitting by whitespace with maxsplit=3 ensures filenames with spaces are handled correctly
			parts = line.split(None, 3)
			if len(parts) < 4:
				continue

			obj_type = parts[1]
			obj_hash = parts[2]
			# The filename usually starts with a tab character in raw output, strip() handles it
			name = parts[3].strip()

			# Get the blob data / Check if object exists
			check_cmd = ['cat-file', '-e', obj_hash]
			check_res = self._run_git_command(check_cmd)

			# Ignore invalid git objects (e.g. ones that are missing)
			if not check_res or check_res.returncode != 0:
				continue

			full_path = os.path.join(path, name)

			if obj_type == "blob":
				print(f"{Colors.GREEN}[+] Found file: {full_path}{Colors.END}")
				cat_cmd = ['cat-file', '-p', obj_hash]
				file_res = self._run_git_command(cat_cmd, capture_output=True, text=False, binary=True)

				if file_res and file_res.returncode == 0:
					# Ensure parent directory exists
					os.makedirs(os.path.dirname(full_path), exist_ok=True)

					with open(full_path, 'wb') as f:
						f.write(file_res.stdout)

			else: # It's a tree
				print(f"{Colors.GREEN}[+] Found folder: {full_path}{Colors.END}")
				os.makedirs(full_path, exist_ok=True)
				# Recursively traverse sub trees
				self._traverse_tree(obj_hash, full_path)

	def _traverse_commit(self, commit, count):
		"""
		Extracts metadata and content for a specific commit.
		"""
		print(f"{Colors.GREEN}[+] Found commit: {commit}{Colors.END}")

		path = os.path.join(self.dest_dir, f"{count}-{commit}")
		os.makedirs(path, exist_ok=True)

		# Add meta information
		cat_cmd = ['cat-file', '-p', commit]
		meta_res = self._run_git_command(cat_cmd, capture_output=True, text=True)

		if meta_res and meta_res.returncode == 0:
			with open(os.path.join(path, "commit-meta.txt"), 'w') as f:
				f.write(meta_res.stdout)

		# Try to extract contents of root tree
		# Note: git ls-tree works on commit hashes as they are treeishes
		self._traverse_tree(commit, path)

	def extract(self):
		commit_count = 0
		print(f"{Colors.CYAN}[*] Extracting commits from {self.git_repo}...{Colors.END}")

		# We need to find all loose objects to inspect them
		if not os.path.exists(self.objects_path):
			print(f"{Colors.YELLOW}[!] No .git/objects directory found. Skipping extraction.{Colors.END}")
			return

		# Walk through .git/objects to find loose object files
		for root, dirs, files in os.walk(self.objects_path):
			for filename in files:
				# Construct the hash from the path structure: .git/objects/ab/cdef... -> abcdef...
				# The parent directory name is the first 2 chars of the hash
				parent_dir = os.path.basename(root)

				# Simple validation to ensure we are looking at loose object structure (2 char folder, 38 char file)
				if len(parent_dir) != 2 or len(filename) != 38:
					continue

				obj_hash = parent_dir + filename

				# Determine object type
				cmd = ['cat-file', '-t', obj_hash]
				result = self._run_git_command(cmd, capture_output=True, text=True)

				if result and result.returncode == 0:
					obj_type = result.stdout.strip()

					# Only analyse commit objects
					if obj_type == "commit":
						self._traverse_commit(obj_hash, commit_count)
						commit_count += 1

		print(f"{Colors.GREEN}[+] Extraction complete. Total commits extracted: {commit_count}{Colors.END}")


# Enums and Data Classes
class Severity(Enum):
	CRITICAL = "Critical"
	HIGH = "High"
	MEDIUM = "Medium"
	LOW = "Low"
	INFO = "Info"

@dataclass
class Dependency:
	name: str
	version: str
	ecosystem: str

@dataclass
class Finding:
	file_path: str
	line_number: Optional[int]
	finding_type: str
	pattern: str
	description: str
	impact: str
	severity: Severity
	cve: Optional[str] = None

class SASTAnalyzer:
	def __init__(self, targets: List[str], exclude_dirs: List[str] = None, severity_threshold: Severity = Severity.INFO, cache_dir: str = ".sast_cache"):
		# Update to accept a list of targets (files or directories)
		self.targets = [Path(t) for t in targets]
		# Expanded default exclude list to reduce false positives from test files and dependencies
		default_excludes = ["node_modules", "vendor", "__pycache__", ".venv", "dist", "build", "test", "tests", "spec", "fixtures", "docs", "examples", "samples"]
		self.exclude_dirs = exclude_dirs if exclude_dirs is not None else default_excludes
		self.severity_threshold = severity_threshold
		self.findings: List[Finding] = []
		self.dependencies: List[Dependency] = []
		self.cache_dir = Path(cache_dir)
		self.cache_dir.mkdir(exist_ok=True)
		self.start_time = time.time() # Track start time for professional report
		self._init_patterns()
		self._load_cve_cache()

		# Regex to strip ANSI codes for length calculation
		self._ansi_escape = re.compile(r'\033\[[0-9;]*m')

	# --- Helper: Get Full Line ---
	def _get_full_line(self, content_lines: List[str], line_number: int) -> str:
		"""Safely retrieve the full line content at a given line number (1-based)."""
		if 0 < line_number <= len(content_lines):
			return content_lines[line_number - 1].strip()
		return ""

	# --- Helper: Visual Length (for padding) ---
	def _get_visual_length(self, text: str) -> int:
		"""Calculate the visual length of a string by removing ANSI escape codes."""
		return len(self._ansi_escape.sub('', text))

	# --- Random Banner Generator ---
	def _get_random_banner(self, width: int = 80) -> List[str]:
		banners = [
			[
				f"{Colors.CYAN}      ____  ____  ____  ________     ",
				f"     / __ \\/ __ \\/ __ \\/  _/ __ \\    ",
				f"    / / / / / / / /_/ // / / / /    ",
				f"   / /_/ / /_/ / _, _// // /_/ /     ",
				f"   \\____/\\____/_/ |_|/___/\\____/     ",
				f"   {Colors.BOLD}S   A   S   T   S   C   A   N{Colors.END}"
			],
			[
				f"{Colors.RED}   __________                 ",
				f"   \\______   \\ ____ _____    ",
				f"    |     ___// __ \\\\__  \\   ",
				f"    |    |   \\  ___/ / __ \\_ ",
				f"    |____|    \\___  >____  / ",
				f"                   \\/     \\/  ",
				f"   {Colors.BOLD}V  U  L  N  E  R  A  B  I  L  I  T  Y{Colors.END}"
			],
			[
				f"{Colors.GREEN}   _______  _______  _______  ______  ",
				f"  (  ____ \\(  ___  )(  ___  )(  __  \\ ",
				f"  | (    \\/| (   ) || (   ) || (  \\  )",
				f"  | |      | |   | || |   | || |   ) |",
				f"  | | ____ | |   | || |   | || |   | |",
				f"  | | \\_  )| |   | || |   | || |   ) |",
				f"  | (___) || (___) || (___) || (__/  )",
				f"  (_______)(_______)(_______)(______/ ",
				f"   {Colors.BOLD}C   O   D   E   S   E   C   U   R   I   T   Y{Colors.END}"
			]
		]

		selected = random.choice(banners)
		# Center the banner lines based on width
		centered_lines = []
		for line in selected:
			# Remove non-printable chars for length calculation
			visible_len = len(re.sub(r'\033\[[0-9;]*m', '', line))
			padding = max(0, (width - visible_len) // 2)
			centered_lines.append(" " * padding + line)

		return centered_lines

	# --- 1. Entropy-Based Secret Validation ---
	@staticmethod
	def _calculate_entropy(data: str) -> float:
		if not data:
			return 0.0
		entropy = 0
		for x in range(256):
			p_x = data.count(chr(x)) / len(data)
			if p_x > 0:
				entropy += -p_x * math.log(p_x, 2)
		return entropy

	def _is_high_entropy(self, match: str) -> bool:
		# Threshold for high entropy (usually secrets)
		return self._calculate_entropy(match) > 3.5

	# --- 2. AST-Based Semantic Analysis (Python) ---
	def _analyze_ast_python(self, content_lines: List[str], file_path: str) -> List[Finding]:
		findings = []
		content = "\n".join(content_lines)
		try:
			tree = ast.parse(content)
		except SyntaxError:
			return findings

		class SecurityVisitor(ast.NodeVisitor):
			def __init__(self, analyzer, file_path, content_lines):
				self.analyzer = analyzer
				self.file_path = file_path
				self.content_lines = content_lines
				self.tainted_vars: Set[str] = set()
				# Framework aware: Django settings
				self.is_django_settings = "settings.py" in file_path
				self.django_secret_key_found = False

			def visit_Call(self, node):
				# Check for dangerous functions (eval, exec, os.system)
				if isinstance(node.func, ast.Name):
					func_name = node.func.id
					line_content = self.analyzer._get_full_line(self.content_lines, node.lineno)

					# Simple heuristic: ignore if function is called with a literal string constant (no injection risk)
					# Updated to use ast.Constant only (Fix for DeprecationWarning)
					has_non_literal_args = any(not isinstance(arg, (ast.Constant, ast.List, ast.Dict, ast.Set, ast.Tuple)) for arg in node.args)

					if func_name in ['eval', 'exec', 'open'] and has_non_literal_args:
						# Check if arguments are tainted (Simple Taint Tracking)
						for arg in node.args:
							if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
								findings.append(Finding(
									file_path=self.file_path,
									line_number=node.lineno,
									finding_type=f"Potential Injection ({func_name})",
									pattern=line_content,
									description=f"Use of {func_name} with potentially untrusted input.",
									impact="Remote Code Execution",
									severity=Severity.CRITICAL
								))
					# Check for execute with tainted vars
					if func_name == 'execute' and has_non_literal_args:
						for arg in node.args:
							if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
								findings.append(Finding(
									file_path=self.file_path,
									line_number=node.lineno,
									finding_type="SQL Injection",
									pattern=line_content,
									description="SQL query execution with user input.",
									impact="Database Compromise",
									severity=Severity.CRITICAL
								))

					# CWE-134 / CWE-117: Format String in Logging
					# In Python < 3.2, logging with % args. In general, passing user data directly to logger 
					# can be risky if the logger interprets format specifiers.
					if func_name in ['info', 'warning', 'error', 'debug', 'critical', 'exception']:
						# If there is only one argument and it's not a literal, it might be a format string issue if it contains %
						# However, standard python logging requires the format string as the first arg. 
						# If user input is passed as the first arg, it's a CWE-134 issue if it contains %s.
						if len(node.args) > 0:
							first_arg = node.args[0]
							# If the first argument is a variable (Name), it's suspicious.
							if isinstance(first_arg, ast.Name):
								# Check if the line actually contains % or {} for formatting, 
								# but since it's a variable we can't know. 
								# We flag suspicious direct logging of variables.
								pass 
						# Detect logger.info("Data: " + user_input) vs logger.info("Data: %s", user_input)
						# The latter is safe. The former might be unsafe if the logger implementation treats it differently, 
						# but standard python logger treats the first arg as msg. 
						# The real risk is logger.info(user_input) where user_input = "Bad %s data".
						
						# We will add a general check for direct variable usage in loggers
						if len(node.args) == 1 and isinstance(node.args[0], ast.Name):
							# Check if the attribute access corresponds to a logger
							if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
								if node.func.value.id.endswith('log') or node.func.attr in ['info', 'warning', 'error', 'debug']:
									# This is a heuristic: logging a single variable directly can be a format string vuln
									if '%' in line_content or '{' in line_content:
										# We can't see the value of the var at AST time, so we rely on regex for the pattern "%s"
										pass

				self.generic_visit(node)

			def visit_Assign(self, node):
				line_content = self.analyzer._get_full_line(self.content_lines, node.lineno)
				# Taint Sources: request.GET, input(), etc.
				if isinstance(node.value, ast.Call):
					if isinstance(node.value.func, ast.Attribute):
						if node.value.func.attr in ['GET', 'POST', 'cookies', 'headers']:
							if isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == 'request':
								for target in node.targets:
									if isinstance(target, ast.Name):
										self.tainted_vars.add(target.id)

				# Framework Config: Django Hardcoded Secret
				if self.is_django_settings:
					if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
						for target in node.targets:
							if isinstance(target, ast.Name) and target.id == 'SECRET_KEY':
								if self.analyzer._is_high_entropy(node.value.value):
									findings.append(Finding(
										file_path=self.file_path,
										line_number=node.lineno,
										finding_type="Hardcoded Django Secret",
										pattern=line_content,
										description="Django SECRET_KEY found hardcoded in settings.",
										impact="Session Forgery, RCE",
										severity=Severity.CRITICAL
									))

				self.generic_visit(node)

		visitor = SecurityVisitor(self, file_path, content_lines)
		visitor.visit(tree)
		return findings

	# --- 3. Real CVE API Integration (OSV) ---
	def _load_cve_cache(self):
		self.cve_cache_path = self.cache_dir / "cve_cache.json"
		try:
			if self.cve_cache_path.exists():
				self.cve_cache = json.loads(self.cve_cache_path.read_text())
			else:
				self.cve_cache = {}
		except:
			self.cve_cache = {}

	def _save_cve_cache(self):
		try:
			self.cve_cache_path.write_text(json.dumps(self.cve_cache))
		except:
			pass

	def _check_osv_api(self, pkg_name: str, version: str, ecosystem: str) -> List[str]:
		cache_key = f"{ecosystem}:{pkg_name}:{version}"
		if cache_key in self.cve_cache:
			return self.cve_cache[cache_key]

		cves = []
		try:
			url = "https://api.osv.dev/v1/query"
			payload = {
				"package": {"name": pkg_name, "ecosystem": ecosystem},
				"version": version
			}
			data = json.dumps(payload).encode('utf-8')
			req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

			with urllib.request.urlopen(req, timeout=5) as response:
				result = json.loads(response.read().decode('utf-8'))
				if result.get("vulns"):
					for vuln in result["vulns"]:
						for alias in vuln.get("aliases", []):
							if alias.startswith("CVE"):
								cves.append(alias)
							elif alias.startswith("GHSA"):
								cves.append(alias)
		except Exception:
			pass # Fail silently on network errors to keep scanning fast

		self.cve_cache[cache_key] = cves
		return cves

	# --- 5. Framework-Aware Config Validation ---
	def _validate_framework_config(self, content: str, content_lines: List[str], path: str) -> List[Finding]:
		findings = []
		filename = Path(path).name.lower()

		# Java Spring (application.properties / yml)
		if filename.startswith("application"):
			# Example DB Password check - ignore if commented out or placeholder
			pattern = r'spring\.datasource\.password\s*=\s*(?!<encrypted>).+'
			for match in re.finditer(pattern, content):
				line_num = content[:match.start()].count('\n') + 1
				line_content = self._get_full_line(content_lines, line_num)
				# Check for comments or common placeholders
				if not self._is_likely_false_positive(match.group(0), line_content, "Database Password"):
					findings.append(Finding(
						file_path=path, line_number=line_num, finding_type="Plaintext DB Password",
						pattern=line_content,
						description="Plaintext database password in Spring config.",
						impact="Credential Theft", severity=Severity.HIGH
					))

			# Check for Actuator exposure
			pattern = r'management\.endpoints\.web\.exposure\.include\s*=\s*\*'
			for match in re.finditer(pattern, content):
				line_num = content[:match.start()].count('\n') + 1
				line_content = self._get_full_line(content_lines, line_num)
				if not self._is_likely_false_positive(match.group(0), line_content, "Actuator Exposure"):
					findings.append(Finding(
						file_path=path, line_number=line_num, finding_type="Spring Actuator Exposure",
						pattern=line_content,
						description="Spring Boot Actuator endpoints are exposed to all.",
						impact="Information Disclosure, RCE", severity=Severity.HIGH
					))

		# Django settings
		if filename == "settings.py":
			# Debug check
			pattern = r'DEBUG\s*=\s*True'
			for match in re.finditer(pattern, content):
				line_num = content[:match.start()].count('\n') + 1
				line_content = self._get_full_line(content_lines, line_num)
				# Skip if it's clearly commented
				if not line_content.startswith('#'):
					findings.append(Finding(
						file_path=path, line_number=line_num, finding_type="Django Debug Enabled",
						pattern=line_content,
						description="Django debug mode is enabled.",
						impact="Information Disclosure", severity=Severity.MEDIUM
					))

			# Allowed hosts check
			pattern = r'ALLOWED_HOSTS\s*=\s*\[?\s*["\']?\*["\']?\s*\]?'
			for match in re.finditer(pattern, content):
				line_num = content[:match.start()].count('\n') + 1
				line_content = self._get_full_line(content_lines, line_num)
				if not line_content.startswith('#'):
					findings.append(Finding(
						file_path=path, line_number=line_num, finding_type="Permissive Allowed Hosts",
						pattern=line_content,
						description="Django ALLOWED_HOSTS is wildcard.",
						impact="Host Header Injection", severity=Severity.HIGH
					))

		# Flask specific checks (usually in app.py or run.py)
		if filename in ["app.py", "run.py", "main.py"]:
			# Flask Debug Mode
			pattern = r'app\.run\s*\(\s*debug\s*=\s*True'
			for match in re.finditer(pattern, content):
				line_num = content[:match.start()].count('\n') + 1
				line_content = self._get_full_line(content_lines, line_num)
				if not line_content.startswith('#'):
					findings.append(Finding(
						file_path=path, line_number=line_num, finding_type="Flask Debug Enabled",
						pattern=line_content,
						description="Flask debug mode is enabled in code.",
						impact="Information Disclosure, RCE", severity=Severity.HIGH
					))

		return findings

	def _init_patterns(self):
		# --- 1. Secret Patterns (Expanded) ---
		self.secret_patterns = {
			"API Key": [
				(r'(?i)(api[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9_-]{20,}["\']?)', Severity.CRITICAL),
				(r'(?i)(api[_-]?secret\s*[=:]\s*["\']?[a-zA-Z0-9_-]{20,}["\']?)', Severity.CRITICAL),
			],
			"Access Token": [
				(r'(?i)(access[_-]?token\s*[=:]\s*["\']?[a-zA-Z0-9_.-]{20,}["\']?)', Severity.CRITICAL),
				(r'(?i)(bearer\s+[a-zA-Z0-9_.-]{20,})', Severity.CRITICAL), # Found in headers/docs
			],
			"Database Password": [
				(r'(?i)(db[_-]?password\s*[=:]\s*["\'][^"\']{8,}["\'])', Severity.CRITICAL),
				(r'(?i)(dbname\s*=\s*[^;]+;.*password\s*=\s*[^;]+)', Severity.CRITICAL), # Connection strings
			],
			"JWT Secret": [
				(r'(?i)(jwt[_-]?secret\s*[=:]\s*["\'][^"\']{8,}["\'])', Severity.CRITICAL),
			],
			"Cloud Credentials": [
				(r'(AKIA[0-9A-Z]{16})', Severity.CRITICAL),
				(r'(?i)(aws[_-]?secret[_-]?key\s*[=:]\s*["\'][^"\']{20,}["\'])', Severity.CRITICAL),
				(r'(?i)(azure[_-]?storage[_-]?key\s*[=:]\s*["\'][^"\']{20,}["\'])', Severity.CRITICAL),
				(r'(?i)(google[_-]?api[_-]?key\s*[=:]\s*["\'][A-Za-z0-9_-]{35}["\'])', Severity.CRITICAL), # Google API Key
			],
			# SSH Key Pattern: Matches standard PEM headers
			"SSH Key": [
				(r'-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----', Severity.CRITICAL),
			],
			"Generic Secret": [
				(r'(?i)(secret\s*[=:]\s*["\'][^"\']{8,}["\'])', Severity.HIGH),
				(r'(?i)(password\s*[=:]\s*["\'][^"\']{8,}["\'])', Severity.HIGH),
			],
			# Service Specific Tokens
			"Stripe Key": [
				(r'(sk_live_[0-9a-zA-Z]{24,})', Severity.CRITICAL),
				(r'(pk_live_[0-9a-zA-Z]{24,})', Severity.HIGH),
			],
			"Slack Token": [
				(r'xox[baprs]-[a-zA-Z0-9-]{10,}', Severity.HIGH),
				(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}', Severity.HIGH),
			],
			"GitHub Token": [
				(r'(ghp_[a-zA-Z0-9]{36})', Severity.CRITICAL), # Personal Access Token
				(r'(gho_[a-zA-Z0-9]{36})', Severity.CRITICAL), # OAuth Access Token
				(r'(ghu_[a-zA-Z0-9]{36})', Severity.CRITICAL), # User token
				(r'(ghs_[a-zA-Z0-9]{36})', Severity.CRITICAL), # Server-to-Server token
				(r'(ghr_[a-zA-Z0-9]{36})', Severity.CRITICAL), # Refresh token
			],
			"GitLab Token": [
				(r'(glpat-[a-zA-Z0-9_-]{20})', Severity.CRITICAL),
			],
			"Atlassian Token": [
				(r'(Bearer\s+[a-zA-Z0-9]{24})', Severity.HIGH), # Often used for Jira/Confluence
				(r'(?i)(atlassian[_-]?api[_-]?token\s*[=:]\s*["\'][^"\']{20}["\'])', Severity.HIGH),
			],
			"Twilio Key": [
				(r'(SK[a-fA-F0-9]{32})', Severity.HIGH),
				(r'(AC[a-fA-F0-9]{32})', Severity.HIGH),
			],
			"SendGrid Key": [
				(r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})', Severity.HIGH),
			],
			"Datadog Key": [
				(r'(pub[a-fA-F0-9]{32})', Severity.HIGH), # Public key (not usually secret, but tracked)
				(r'(priv[a-fA-F0-9]{32})', Severity.CRITICAL), # Private key
				(r'(api[a-fA-F0-9]{32})', Severity.CRITICAL), # API key
			],
			"Postman Token": [
				(r'(PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34})', Severity.MEDIUM),
			],
			"NuGet Token": [
				(r'(oy2[a-zA-Z0-9]{43})', Severity.HIGH),
			],
			"Generic High Entropy String": [
				(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']', Severity.HIGH), # Base64 looking strings
			],
		}

		self.crypto_patterns = {
			"Weak Hash (MD5)": [(r'(?i)\bmd5\s*\(|hashlib\.md5', Severity.HIGH)],
			"Weak Hash (SHA1)": [(r'(?i)\bsha1\s*\(|hashlib\.sha1', Severity.MEDIUM)],
			"Weak Encryption (DES)": [(r'(?i)\bDES\s*\(|from\s+Crypto\.Cipher\s+import\s+DES', Severity.HIGH)],
			"Weak Encryption (RC4)": [(r'(?i)\bRC4\s*\(|ARC4\s*\(', Severity.HIGH)],
			"ECB Mode": [(r'(?i)AES\.MODE_ECB|MODE_ECB', Severity.HIGH)],
			"Hardcoded IV": [(r'(?i)iv\s*=\s*["\'][0-9a-fA-F]{16,}["\']', Severity.HIGH)],
			"Weak Random": [(r'(?i)random\.random\s*\(|Math\.random\s*\(', Severity.MEDIUM)],
			"Missing Salt": [(r'(?i)hash\s*\(\s*password\s*\)', Severity.HIGH)],
			# New: Weak SSL/TLS Protocols
			"Weak SSL Protocol": [
				(r'(?i)(SSLv3|TLSv1[_\s]?(?!0|1[12]))', Severity.HIGH), # Catches SSLv3, TLSv1 but not TLSv1.2 or 1.3
				(r'(?i)(PROTOCOL_SSLv3|PROTOCOL_TLSv1)', Severity.HIGH)
			],
		}

		self.config_patterns = {
			"Debug Mode Enabled": [(r'(?i)debug\s*[=:]\s*true|DEBUG\s*=\s*True', Severity.MEDIUM)],
			"Default Credentials": [(r'(?i)(admin\s*[=:]\s*["\']?admin["\']?)', Severity.HIGH)],
			"Test Keys": [(r'(?i)test[_-]?key\s*[=:]\s*["\'][^"\']+', Severity.MEDIUM)],
			"Unrestricted CORS": [(r'(?i)access-control-allow-origin\s*[:=]\s*\*', Severity.MEDIUM)],
			"Permissive Access": [(r'(?i)(allow\s*=\s*["\']\*["\'])', Severity.MEDIUM)],
			# New: Strict Transport Security missing or low age (heuristic)
			"Missing HSTS": [
				(r'(?i)Strict-Transport-Security\s*[:=]\s*max-age\s*=\s*[0-9]{1,6}', Severity.INFO), # Detected if present, but we might want 'missing'. 
				# Since we scan for patterns, detecting 'missing' is hard without context. 
				# We will detect 'weak HSTS' instead.
				(r'(?i)Strict-Transport-Security\s*[:=]\s*max-age\s*=\s*[0-9]{1,5}', Severity.LOW) # Less than 100000 seconds
			]
		}

		self.logging_patterns = {
			"Logging Password": [(r'(?i)log(?:ger|ging)?\.\w+\(.*password|print\(.*password', Severity.HIGH)],
			"Logging Token": [(r'(?i)log(?:ger|ging)?\.\w+\(.*token|print\(.*token', Severity.HIGH)],
			"Logging Session ID": [(r'(?i)log(?:ger|ging)?\.\w+\(.*session[_-]?id', Severity.MEDIUM)],
			"Logging Payment Data": [(r'(?i)log(?:ger|ging)?\.\w+\(.*card[_-]?(?:number|cvv)', Severity.CRITICAL)],
			"Logging Personal Info": [(r'(?i)log(?:ger|ging)?\.\w+\(.*ssn', Severity.HIGH)],
		}

		self.env_patterns = {
			"Plaintext Env Secret": [(r'(?i)^[A-Z_]+(?:SECRET|KEY|TOKEN|PASSWORD)\s*=\s*["\']?[^"\'\s]+', Severity.HIGH)],
			"Fallback Secret": [(r'(?i)(?:fallback|default)_[a-z]+_secret', Severity.MEDIUM)],
		}

		# --- NEW PATTERNS FOR WIDER SCOPE ---

		# 1. Injection (SQL, Command, LDAP, SSTI)
		self.injection_patterns = {
			"SQL Injection (Concatenation)": [
				(r'["\'].*WHERE.*["\']\s*\+.*\(|["\'].*SELECT.*["\']\s*\+.*\(', Severity.HIGH),
				(r'execute\s*\(\s*["\'].*%.*["\']\s*%\s*\(?\w', Severity.HIGH), # Python f-string style or %
				(r'\.query\s*\(\s*["\'].*\$\{', Severity.HIGH), # JS/Node interpolation
				(r'query\s*\(\s*["\'].*\+\s*\w+', Severity.HIGH)
			],
			"Command Injection": [
				(r'os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(\s*.*shell\s*=\s*True', Severity.HIGH),
				(r'exec\s*\(|system\s*\(|popen\s*\(|passthru\s*\(', Severity.HIGH),
				(r'\.exec\s*\(|Runtime\.getRuntime\(\)\.exec', Severity.HIGH), # Java/JS
			],
			"LDAP Injection": [
				(r'(?i)(ldap_search|ldap_bind)\s*\([^)]*\+[^)]*\)', Severity.HIGH),
			],
			# New: Server-Side Template Injection (SSTI)
			"Template Injection (SSTI)": [
				(r'\{\{.*request\.\w+.*\}\}', Severity.HIGH), # Jinja2/Django
				(r'<%=.*request\.\w+.*%>', Severity.HIGH),     # ERB (Ruby)
				(r'\$\{.*request\.\w+.*\}', Severity.HIGH),     # Freemarker/Velocity
			]
		}

		# --- UPDATED FOR DOCUMENT REQUIREMENTS ---

		# CWE-643: XPath Injection
		self.xpath_patterns = {
			"XPath Injection": [
				(r'(?i)(xpath|selectNodes|selectSingleNode)\s*\(\s*["\'].*\+.*["\']', Severity.HIGH), # Concatenation
				(r'(?i)evaluate\s*\(\s*["\'].*\$.*["\']', Severity.HIGH), # Variable interpolation
				(r'(?i)find\s*\(\s*["\'].*\$\w', Severity.HIGH), # PHP SimpleXML
			]
		}

		# CWE-295: Improper Certificate Validation
		# CWE-319: Cleartext Transmission
		self.cert_crypto_patterns = {
			"Insecure Certificate Validation": [
				(r'(?i)verify\s*=\s*False', Severity.HIGH), # Python requests
				(r'(?i)ssl\.create_default_context\(\s*\)', Severity.MEDIUM), # Often used without check_hostname
				(r'(?i)check_hostname\s*=\s*False', Severity.HIGH),
				(r'(?i)TrustManager\[\]', Severity.HIGH), # Java trust-all
				(r'(?i)X509TrustManager', Severity.MEDIUM), # Usage of custom TrustManager
				(r'(?i)setHostnameVerifier\s*\(\s*ALLOW_ALL', Severity.HIGH), # Java
				(r'(?i)ALLOW_ALL_HOSTNAME_VERIFIER', Severity.HIGH),
			],
			"Weak RSA Padding (CWE-780)": [
				(r'RSA/ECB/PKCS1Padding', Severity.MEDIUM), # Java
				(r'(?i)Cipher\.getInstance\(["\']RSA', Severity.MEDIUM), # Generic RSA check (context dependent)
			],
			"Cleartext HTTP Protocol": [
				(r'["\']http://', Severity.LOW) # Generally low, but relevant for sensitive data
			]
		}

		# CWE-15: External Control of System/Config
		# CWE-470: Unsafe Reflection
		self.reflection_patterns = {
			"Unsafe Reflection / Dynamic Import": [
				(r'__import__\(\s*\w+\s*\)', Severity.HIGH), # Python
				(r'importlib\.import_module\(', Severity.HIGH), # Python
				(r'Class\.forName\s*\(', Severity.HIGH), # Java
				(r'ClassLoader\.loadClass', Severity.HIGH), # Java
				(r'getattr\s*\([^,]+,\s*[^)]+\)', Severity.MEDIUM), # Python dynamic attribute access
			]
		}

		# CWE-134: Format String
		# CWE-113: CRLF Injection
		self.input_neutralization_patterns = {
			"Format String Injection": [
				(r'printf\s*\(\s*\w+\s*\)', Severity.HIGH), # C/PHP
				(r'System\.out\.printf\s*\(\s*\w+\s*\)', Severity.HIGH), # Java
				(r'fprintf\s*\(\s*\w+\s*,\s*\w+\s*\)', Severity.HIGH),
				# Python logging where variable is the format string
				(r'logger\.(debug|info|warning|error|critical)\s*\(\s*\w+\s*\)', Severity.MEDIUM),
			],
			"CRLF Injection (HTTP Response Splitting)": [
				(r'\r\n', Severity.LOW), # Literal in string
				(r'%0d%0a', Severity.LOW), # URL encoded
				(r'\\r\\n', Severity.LOW), # Escaped
			]
		}

		# CWE-377: Insecure Temporary File
		# CWE-732: Incorrect Permission Assignment
		self.file_system_patterns = {
			"Insecure Temporary File": [
				(r'os\.tmpnam\(\)', Severity.HIGH), # Python
				(r'tempfile\.mktemp\(\)', Severity.HIGH), # Python
				(r'tmpfile\(\)', Severity.MEDIUM), # C
				(r'mkstemp\s*\(\s*["\']?', Severity.MEDIUM),
			],
			"Weak File Permissions": [
				(r'chmod\s*\(\s*["\']?777', Severity.MEDIUM), # Unix
				(r'chmod\s*\(\s*["\']?a\+rwx', Severity.MEDIUM),
				(r'File\.setReadable\s*\(\s*true,\s*false\s*\)', Severity.HIGH), # Java (readable by all)
				(r'SetWorldReadable\s*\(\s*true', Severity.HIGH), # C#
				(r'cacls|icacls\s.*grant.*everyone', Severity.MEDIUM), # Windows
			]
		}

		# CWE-352: CSRF
		# CWE-614: Sensitive Cookie without Secure
		# CWE-1004: Sensitive Cookie without HttpOnly
		self.web_config_patterns = {
			"CSRF Protection Disabled": [
				(r'@csrf_exempt', Severity.MEDIUM), # Django
				(r'csrf\.disable\(\)', Severity.HIGH), # Express/Node
				(r'VerifyCsrfToken\s*=\s*false', Severity.MEDIUM), # Laravel/PHP
			],
			"Cookie Missing Secure Flag": [
				(r'response\.set_cookie\([^)]*\)(?!.*secure\s*=\s*True)', Severity.LOW), # Python (negative lookahead is tricky in multiline, simplified here)
				(r'Set-Cookie:.*;(?!.*Secure)', Severity.LOW), # Header
				(r'cookie\.setSecure\(false\)', Severity.HIGH), # Java/Explicit False
			],
			"Cookie Missing HttpOnly Flag": [
				(r'httponly\s*=\s*False', Severity.MEDIUM),
				(r'httpOnly\s*=\s*false', Severity.MEDIUM),
				(r'Set-Cookie:.*;(?!.*HttpOnly)', Severity.LOW),
			]
		}

		# 2. Network (SSRF, Open Redirect, XXE)
		self.network_patterns = {
			"SSRF Risk": [
				(r'requests\.(get|post|put|delete|request)\s*\(', Severity.MEDIUM),
				(r'urllib\.(request|urlopen)\s*\(|urllib2\.urlopen\s*\(', Severity.MEDIUM),
				(r'fetch\s*\(|axios\.(get|post)\s*\(|http\.get\(|http\.request\(', Severity.MEDIUM),
				(r'open\s*\(\s*["\']https?://', Severity.LOW),
			],
			"Open Redirect": [
				(r'redirect\s*\(|response\.redirect|header\s*\(\s*["\']Location', Severity.MEDIUM),
			],
			"XXE (XML External Entity)": [
				(r'DocumentBuilder\s*\.|XMLReader\s*\(|SAXParser\s*\(', Severity.HIGH),
			],
			# New: File Protocol Access (potential LFI)
			"File URL Scheme": [
				(r'["\']file://', Severity.MEDIUM),
			]
		}

		# 3. Deserialization
		self.deserialization_patterns = {
			"Unsafe Deserialization": [
				(r'pickle\.(load|loads)\s*\(', Severity.CRITICAL),
				(r'shelve\.open\s*\(', Severity.CRITICAL),
				(r'yaml\.load\s*\(|yaml\.unsafe_load\s*\(', Severity.CRITICAL),
				(r'marshal\.(load|loads)\s*\(', Severity.CRITICAL),
				(r'ObjectInputStream\s*\(|XMLDecoder\s*\(', Severity.CRITICAL), # Java
				(r'node-serialize|unserialize\s*\(', Severity.HIGH), # Node/PHP
			]
		}

		# 4. Cross-Site Scripting (XSS)
		self.xss_patterns = {
			"Potential XSS": [
				(r'innerHTML\s*=\s*.*\+|outerHTML\s*=\s*.*\+', Severity.HIGH),
				(r'document\.write\s*\(|document\.writeln\s*\(', Severity.HIGH),
				(r'eval\s*\(|setTimeout\s*\(\s*["\']?\w+\["\']?\)|setInterval\s*\(\s*["\']?\w+\["\']?\)', Severity.HIGH),
				(r'\$\(["\'].*html\s*\(', Severity.HIGH), # jQuery .html()
			]
		}

		# 5. Infrastructure (Hardcoded IPs, etc)
		self.infrastructure_patterns = {
			"Hardcoded Private IP": [
				(r'\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b', Severity.LOW),
				(r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', Severity.LOW),
			],
			"Localhost Reference": [
				(r'(localhost|0\.0\.0\.0|::1)', Severity.INFO),
			],
			# New: AWS Metadata IP (Cloud Metadata Attack)
			"AWS Metadata IP": [
				(r'169\.254\.169\.254', Severity.CRITICAL),
			],
			"Hardcoded URL (Potential Internal)": [
				(r'(?i)(http|https)://(localhost|127\.0\.0\.1|internal|staging|dev)\.', Severity.INFO),
			],
			# New: S3 Bucket Detection
			"Hardcoded S3 Bucket": [
				(r'[a-z0-9.-]{3,63}\.s3\.amazonaws\.com', Severity.INFO),
			]
		}

		# Fallback local DB (used only if API fails or for speed)
		self.vulnerable_packages = {
			"python": {"pycrypto": [("*", Severity.CRITICAL)], "django": [("<2.2", Severity.HIGH)], "flask": [("<0.12.5", Severity.HIGH)]},
			"javascript": {"lodash": [("<4.17.15", Severity.HIGH)], "minimist": [("<1.2.2", Severity.HIGH)], "express": [("<4.16.0", Severity.HIGH)]},
			"java": {"log4j": [("<2.17.0", Severity.CRITICAL)]},
		}

		self.dependency_parsers = {
			"requirements.txt": self._parse_requirements,
			"package.json": self._parse_package_json,
			"pom.xml": self._parse_pom,
			"build.gradle": self._parse_gradle,
		}

		self.config_extensions = {".env", ".yaml", ".yml", ".json", ".properties", ".xml", ".conf", ".ini"}
		self.code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".h"}
		self.doc_extensions = {".md", ".rst", ".txt", ".adoc"} # Added to skip certain checks in docs

		# --- Updated Impact Map ---
		self.impact_map = {
			"API Key": "Unauthorized access, credential compromise",
			"Access Token": "Unauthorized access, token forgery",
			"Database Password": "Database breach, data exfiltration",
			"JWT Secret": "Token forgery, authentication bypass",
			"Cloud Credentials": "Cloud account compromise, resource abuse",
			"SSH Key": "Server compromise, lateral movement",
			"Generic Secret": "Credential exposure, unauthorized access",
			"Stripe Key": "Payment processing fraud, data theft",
			"Slack Token": "Workspace takeover, data leakage",
			"Google Cloud Key": "Cloud resource compromise",
			"Firebase Token": "Database read/write access, billing abuse",
			"GitHub Token": "Repository access, supply chain attack, CI/CD compromise",
			"GitLab Token": "Repository access, pipeline manipulation",
			"Atlassian Token": "Jira/Confluence data theft, account takeover",
			"Twilio Key": "SMS fraud, data interception",
			"SendGrid Key": "Email spam, phishing campaigns",
			"Datadog Key": "Monitoring manipulation, infrastructure blindness",
			"Postman Token": "API collection exposure, automated attack vectors",
			"NuGet Token": "Package feed poisoning",
			"Generic High Entropy String": "Potential secret exposure",
			"Weak Hash (MD5)": "Password cracking, collision attacks",
			"Weak Hash (SHA1)": "Collision attacks, data integrity issues",
			"Weak Encryption (DES)": "Data disclosure, brute force attacks",
			"Weak Encryption (RC4)": "Data disclosure, stream cipher attacks",
			"ECB Mode": "Pattern disclosure, data leakage",
			"Hardcoded IV": "Reduced encryption security",
			"Weak Random": "Predictable values, session hijacking",
			"Missing Salt": "Rainbow table attacks, password cracking",
			"Weak SSL Protocol": "Man-in-the-middle attacks, data interception",
			"Debug Mode Enabled": "Information leakage, stack trace exposure",
			"Default Credentials": "Unauthorized access, privilege escalation",
			"Test Keys": "Production access with test credentials",
			"Unrestricted CORS": "Cross-site request forgery, data theft",
			"Permissive Access": "Unauthorized access, privilege escalation",
			"Missing HSTS": "Downgrade attacks, cookie interception",
			"Logging Password": "Log-based data leaks, credential exposure",
			"Logging Token": "Token theft, session hijacking",
			"Logging Session ID": "Session hijacking, unauthorized access",
			"Logging Payment Data": "PCI-DSS violations, financial data theft",
			"Logging Personal Info": "Privacy violations, compliance issues",
			"Plaintext Env Secret": "Secret exposure in environment files",
			"Fallback Secret": "Insecure secret rotation, fallback exposure",
			"Vulnerable Dependency": "Supply chain attack, known exploits",
			"SQL Injection (Concatenation)": "Database compromise, data theft",
			"Command Injection": "Remote code execution, server takeover",
			"LDAP Injection": "Authentication bypass, information disclosure",
			"Template Injection (SSTI)": "Remote code execution via template engine",
			"SSRF Risk": "Internal port scanning, data exfiltration from cloud metadata",
			"Open Redirect": "Phishing attacks, credential theft",
			"XXE (XML External Entity)": "Server-side request forgery, local file disclosure",
			"File URL Scheme": "Local file inclusion, sensitive file access",
			"Unsafe Deserialization": "Remote code execution via object injection",
			"Potential XSS": "Session hijacking, defacement, credential theft",
			"Hardcoded Private IP": "Information disclosure of internal network topology",
			"Localhost Reference": "Hardcoded configuration reduces deployment flexibility",
			"AWS Metadata IP": "Cloud credential theft via metadata service",
			"Hardcoded S3 Bucket": "Information disclosure, potential bucket misaccess",
			"Spring Actuator Exposure": "Full system control via management endpoints",
			"Flask Debug Enabled": "Code execution via interactive debugger",
			# New Map Entries
			"XPath Injection": "XPath query manipulation, unauthorized data access",
			"Insecure Certificate Validation": "Man-in-the-middle attacks, data interception",
			"Weak RSA Padding (CWE-780)": "Cryptographic attacks, data disclosure",
			"Cleartext HTTP Protocol": "Data interception, credential theft",
			"Unsafe Reflection / Dynamic Import": "Remote code execution, application instability",
			"Format String Injection": "Code execution, information disclosure, crashes",
			"CRLF Injection (HTTP Response Splitting)": "Cache poisoning, XSS",
			"Insecure Temporary File": "Race conditions, data leakage",
			"Weak File Permissions": "Unauthorized data access/modification by local users",
			"CSRF Protection Disabled": "Unauthorized actions performed on behalf of user",
			"Cookie Missing Secure Flag": "Cookie interception over unencrypted connections",
			"Cookie Missing HttpOnly Flag": "Session hijacking via XSS",
		}

	def _get_remediation(self, finding_type: str) -> str:
		remediation_map = {
			"API Key": "Remove the hardcoded API key and use environment variables or a secret management service.",
			"Access Token": "Revoke the exposed token and implement secure token storage.",
			"Database Password": "Remove hardcoded password and use secrets management.",
			"JWT Secret": "Rotate the secret key immediately and store it securely.",
			"Cloud Credentials": "Revoke the exposed credentials and generate new ones using IAM roles.",
			"SSH Key": "Remove the private key from the repository and add it to .gitignore.",
			"Generic Secret": "Remove the secret and use a secure configuration mechanism.",
			"Stripe Key": "Revoke the key immediately, rotate to a restricted key, and store in env vars.",
			"Slack Token": "Revoke the token from Slack admin settings and rotate.",
			"Google Cloud Key": "Revoke the key in GCP Console and use Workload Identity Federation.",
			"Firebase Token": "Restrict database rules and rotate the token.",
			"GitHub Token": "Revoke the token in GitHub Developer Settings and rotate.",
			"GitLab Token": "Revoke the token in GitLab User Settings.",
			"Atlassian Token": "Revoke the token in Atlassian Account Settings.",
			"Twilio Key": "Rotate keys in the Twilio Console.",
			"SendGrid Key": "Rotate keys in SendGrid settings.",
			"Datadog Key": "Rotate keys in Datadog organization settings.",
			"Postman Token": "Revoke the token in Postman account settings.",
			"NuGet Token": "Rotate the API key.",
			"Generic High Entropy String": "Investigate if string is a secret. If so, rotate and remove from code.",
			"Weak Hash (MD5)": "Replace MD5 with a strong hashing algorithm like SHA-256 or bcrypt.",
			"Weak Hash (SHA1)": "Replace SHA1 with a strong hashing algorithm like SHA-256.",
			"Weak Encryption (DES)": "Replace DES with AES-256.",
			"Weak Encryption (RC4)": "Replace RC4 with a secure stream cipher like AES-GCM.",
			"ECB Mode": "Switch to a more secure mode like CBC or GCM.",
			"Hardcoded IV": "Use a random, unique IV for each encryption operation.",
			"Weak Random": "Use a cryptographically secure random number generator.",
			"Missing Salt": "Use a unique salt for each password hash.",
			"Weak SSL Protocol": "Disable SSLv3 and TLSv1.0/1.1. Enforce TLSv1.2 or higher.",
			"Debug Mode Enabled": "Disable debug mode in production environments.",
			"Default Credentials": "Change default credentials before deployment.",
			"Test Keys": "Remove test keys from production code.",
			"Unrestricted CORS": "Restrict CORS to specific trusted domains.",
			"Permissive Access": "Implement strict access controls and least privilege.",
			"Missing HSTS": "Implement HTTP Strict Transport Security with a long max-age (e.g., 31536000).",
			"Logging Password": "Remove password logging from code.",
			"Logging Token": "Remove token logging from code.",
			"Logging Session ID": "Stop logging sensitive session identifiers.",
			"Logging Payment Data": "Cease logging payment card data to comply with PCI-DSS.",
			"Logging Personal Info": "Stop logging PII.",
			"Plaintext Env Secret": "Use encrypted secrets or a secure vault.",
			"Fallback Secret": "Implement proper secret rotation without fallbacks.",
			"Vulnerable Dependency": "Update the dependency to the latest secure version.",
			"SQL Injection (Concatenation)": "Use parameterized queries or prepared statements.",
			"Command Injection": "Avoid passing user input to shell commands. Use native APIs.",
			"LDAP Injection": "Use proper LDAP escaping libraries.",
			"Template Injection (SSTI)": "Avoid rendering user input in templates. Use auto-escaping.",
			"SSRF Risk": "Validate and whitelist allowed URLs. Disable redirects to internal IPs.",
			"Open Redirect": "Do not redirect based solely on user input. Use whitelists.",
			"XXE (XML External Entity)": "Disable XML external entities in the parser configuration.",
			"File URL Scheme": "Restrict file access paths. Avoid user input in file paths.",
			"Unsafe Deserialization": "Do not deserialize untrusted data. Use safe formats like JSON.",
			"Potential XSS": "Sanitize output and encode data contextually. Avoid unsafe DOM methods.",
			"Hardcoded Private IP": "Move configuration to environment variables.",
			"Localhost Reference": "Move configuration to environment variables.",
			"AWS Metadata IP": "Block access to 169.254.169.254 via firewall/iptables or IMDSv2.",
			"Hardcoded S3 Bucket": "Move bucket names to configuration. Check bucket ACLs.",
			"Spring Actuator Exposure": "Restrict management endpoints to specific IPs or disable them externally.",
			"Flask Debug Enabled": "Remove debug=True from app.run. Use environment variables for config.",
			# New Remediation Entries
			"XPath Injection": "Use parameterized XPath queries or escape user input.",
			"Insecure Certificate Validation": "Enable certificate verification. Do not bypass it in production.",
			"Weak RSA Padding (CWE-780)": "Use RSA with OAEP padding (RSA/ECB/OAEPWithSHA-256AndMGF1Padding).",
			"Cleartext HTTP Protocol": "Enforce HTTPS. Redirect all HTTP traffic to HTTPS.",
			"Unsafe Reflection / Dynamic Import": "Avoid dynamic code execution. Whitelist allowed modules/classes.",
			"Format String Injection": "Use format strings with placeholders (%s, {}) instead of direct string formatting.",
			"CRLF Injection (HTTP Response Splitting)": "Encode CRLF sequences in output before using in HTTP headers.",
			"Insecure Temporary File": "Use secure file creation functions that enforce permissions (e.g., tempfile.mkstemp).",
			"Weak File Permissions": "Restrict file permissions to owner-only (e.g., 600 or 0o600).",
			"CSRF Protection Disabled": "Enable CSRF tokens for all state-changing requests.",
			"Cookie Missing Secure Flag": "Set the 'Secure' attribute on all cookies containing sensitive data.",
			"Cookie Missing HttpOnly Flag": "Set the 'HttpOnly' attribute on cookies to prevent JavaScript access.",
		}
		return remediation_map.get(finding_type, "Review and fix the security issue according to best practices.")

	def _read_file(self, path: Path) -> str:
		try:
			return path.read_text(encoding='utf-8', errors='ignore')
		except Exception:
			return ""

	# --- False Positive Reduction Logic ---
	def _is_likely_false_positive(self, matched_text: str, line_content: str, ftype: str) -> bool:
		"""
		Determines if a matched pattern is likely a false positive based on context.
		"""
		line_stripped = line_content.strip()

		# 1. Check for comments (Common false positive source)
		# Updated: Explicitly exclude PEM headers ('-----') to allow SSH/RSA keys detection.
		# Otherwise lines starting with '-' are incorrectly flagged as SQL/XML comments.
		if line_stripped.startswith(('#', '//', '/*', '*', '<!--')):
			return True
		# Check for SQL style comments '--', but exclude PEM headers '-----'
		if line_stripped.startswith('--') and not line_stripped.startswith('-----'):
			return True

		# 2. Extract the value from the match to analyze it specifically
		# Look for values inside quotes or after '='
		val_match = re.search(r'["\']([^"\']+)["\']', matched_text)
		if val_match:
			val = val_match.group(1).lower()
		else:
			# Fallback if no quotes (e.g. env vars or specific keywords)
			val = matched_text.split('=')[-1].split(':')[-1].strip().lower()
			# Remove common punctuation for checking
			val = re.sub(r'[;,\s\)\}\]]', '', val)

		# 3. Check against common placeholders and non-secret strings
		placeholders = {
			'test', 'example', 'dummy', 'sample', 'changeme', 'replace',
			'your_key_here', 'your_api_key', 'your_token', 'none', 'null',
			'false', 'true', 'get', 'post', 'delete', 'put', '12345', '123456',
			'abcde', 'xxxxx', 'secret', 'password', 'admin', 'user', 'dev',
			'staging', 'local', 'localhost', '127.0.0.1', '0.0.0.0', 'demo'
		}

		if val in placeholders:
			# Be stricter for secrets (High/Critical), but maybe allow 'localhost' for infrastructure info
			if "Secret" in ftype or "Key" in ftype or "Password" in ftype or "Token" in ftype:
				return True
			if ftype == "Localhost Reference" and val in ['localhost', '127.0.0.1', '0.0.0.0']:
				return True # Explicitly skipping localhost references as they are often valid defaults

		# 4. Check for URLs in secrets (often false positives like "https://api.example.com")
		if val.startswith("http") and ("Key" in ftype or "Secret" in ftype):
			return True

		# 5. Short value check
		# If it's called a 'Key' or 'Secret' but is very short, it's likely a placeholder
		if len(val) < 8 and ("Key" in ftype or "Secret" in ftype or "Password" in ftype):
			return True

		return False

	def _scan_patterns(self, content: str, content_lines: List[str], file_path: str, patterns: Dict) -> List[Finding]:
		findings = []
		for ftype, plist in patterns.items():
			for pattern, severity in plist:
				for match in re.finditer(pattern, content):
					line_num = content[:match.start()].count('\n') + 1
					line_content = self._get_full_line(content_lines, line_num)
					matched_text = match.group(0)

					# --- FALSE POSITIVE FILTER ---
					if self._is_likely_false_positive(matched_text, line_content, ftype):
						continue

					# Feature 1: Entropy Validation for Generic Secrets
					# Re-validate entropy if we haven't already filtered it out via keywords
					if "Secret" in ftype or "Token" in ftype or ("Key" in ftype and "SSH" not in ftype and "Private" not in ftype):
						# Extract value again for entropy check if not done
						val_match = re.search(r'["\']([^"\']+)["\']', matched_text)
						val = val_match.group(1) if val_match else matched_text.split('=')[-1]

						# Only check entropy if we have a string long enough
						if len(val) > 10 and not self._is_high_entropy(val):
							# Skip secrets that don't look random enough (False Positive reduction)
							continue

					# Feature: Multi-line extraction for SSH Keys
					if "SSH Key" in ftype:
						start_idx = line_num - 1
						end_idx = start_idx
						found_end_tag = False
						search_limit = min(len(content_lines), start_idx + 100)
						for i in range(start_idx + 1, search_limit):
							if "-----END" in content_lines[i]:
								end_idx = i
								found_end_tag = True
								break

						# FIX: Only flag as vulnerability if an end tag is found within range
						if not found_end_tag:
							continue

						if end_idx > start_idx:
							line_content = "\n".join(content_lines[start_idx:end_idx+1])
						else:
							line_content = self._get_full_line(content_lines, line_num)
					else:
						# Standard single line extraction
						line_content = self._get_full_line(content_lines, line_num)
					findings.append(Finding(
						file_path=file_path,
						line_number=line_num,
						finding_type=ftype,
						pattern=line_content,
						description=f"Detected {ftype.lower()}",
						impact=self.impact_map.get(ftype, "Security vulnerability"),
						severity=severity
					))
		return findings

	# --- Dependency Parsing with SBOM & CVE Support ---
	def _parse_requirements(self, content: str, path: str) -> List[Finding]:
		findings = []
		ecosystem = "PyPI"
		for i, line in enumerate(content.splitlines(), 1):
			# Skip comments and empty lines
			if line.strip().startswith('#') or not line.strip():
				continue

			match = re.match(r'^([a-zA-Z0-9_-]+)(?:[>=<]+([0-9.]+))?', line.strip())
			if match:
				pkg = match.group(1).lower()
				ver = match.group(2) or "*"
				self.dependencies.append(Dependency(pkg, ver, ecosystem))

				cves = self._check_osv_api(pkg, ver, ecosystem)
				severity = Severity.HIGH
				if cves:
					findings.append(Finding(path, i, "Vulnerable Dependency", line.strip(),
						f"Package '{pkg}' has known CVEs: {cves}", "Known CVEs, supply chain risks",
						severity, cve=cves[0] if cves else None))
				elif pkg in self.vulnerable_packages.get("python", {}):
					findings.append(Finding(path, i, "Vulnerable Dependency", line.strip(),
						f"Package '{pkg}' has known vulnerabilities", "Known CVEs, supply chain risks",
						self.vulnerable_packages["python"][pkg][0][1]))
		return findings

	def _parse_package_json(self, content: str, path: str) -> List[Finding]:
		findings = []
		ecosystem = "npm"
		try:
			data = json.loads(content)
			deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
			for pkg, ver in deps.items():
				self.dependencies.append(Dependency(pkg, ver, ecosystem))
				cves = self._check_osv_api(pkg, ver, ecosystem)
				severity = Severity.HIGH
				dep_str = f'"{pkg}": "{ver}"'
				if cves:
					findings.append(Finding(path, None, "Vulnerable Dependency", dep_str,
						f"Package '{pkg}' has known CVEs", "Known CVEs, supply chain risks",
						severity, cve=cves[0] if cves else None))
				elif pkg.lower() in self.vulnerable_packages.get("javascript", {}):
					findings.append(Finding(path, None, "Vulnerable Dependency", dep_str,
						f"Package '{pkg}' has known vulnerabilities", "Known CVEs, supply chain risks",
						self.vulnerable_packages["javascript"][pkg.lower()][0][1]))
		except json.JSONDecodeError:
			pass
		return findings

	def _parse_pom(self, content: str, path: str) -> List[Finding]:
		findings = []
		ecosystem = "Maven"
		deps = re.findall(r'<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>', content)
		for art, ver in deps:
			self.dependencies.append(Dependency(art, ver, ecosystem))
			cves = self._check_osv_api(art, ver, ecosystem)
			severity = Severity.CRITICAL
			dep_str = f'<artifactId>{art}</artifactId><version>{ver}</version>'
			if cves:
				findings.append(Finding(path, None, "Vulnerable Dependency", dep_str,
					f"Package '{art}' has known CVEs", "Known CVEs, remote code execution",
					severity, cve=cves[0] if cves else None))
			elif art.lower() in self.vulnerable_packages.get("java", {}):
				findings.append(Finding(path, None, "Vulnerable Dependency", dep_str,
					f"Package '{art}' has known vulnerabilities", "Known CVEs, remote code execution",
					self.vulnerable_packages["java"][art.lower()][0][1]))
		return findings

	def _parse_gradle(self, content: str, path: str) -> List[Finding]:
		findings = []
		ecosystem = "Maven"
		deps = re.findall(r'implementation\s+[\'"]([^:]+):([^:]+):([^:\']+)[\'"]', content)
		for grp, art, ver in deps:
			pkg = f"{grp}:{art}"
			self.dependencies.append(Dependency(pkg, ver, ecosystem))
			cves = self._check_osv_api(pkg, ver, ecosystem)
			dep_str = f'implementation "{grp}:{art}:{ver}"'
			if cves:
				findings.append(Finding(path, None, "Vulnerable Dependency", dep_str,
					f"Package '{pkg}' has known CVEs", "Known CVEs",
					Severity.HIGH, cve=cves[0]))
		return findings

	def _should_skip(self, path: Path, check_exclusion_dirs: bool = True) -> bool:
		if path.suffix.lower() in {'.pyc', '.class', '.o', '.so', '.dll', '.exe', '.png', '.jpg', '.zip', '.gif', '.svg', '.pdf'}:
			return True
		if check_exclusion_dirs and any(ex in path.parts for ex in self.exclude_dirs):
			return True
		return False

	def _deduplicate(self) -> List[Finding]:
		seen = set()
		return [f for f in self.findings if (f.file_path, f.line_number, f.finding_type, f.pattern) not in seen and not seen.add((f.file_path, f.line_number, f.finding_type, f.pattern))]

	def _filter_severity(self) -> List[Finding]:
		order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
		threshold = order.index(self.severity_threshold)
		return [f for f in self.findings if order.index(f.severity) <= threshold]

	# --- 6. Parallel Scanning ---
	def _process_file(self, path: Path) -> List[Finding]:
		file_findings = []
		content = self._read_file(path)
		if not content:
			return []

		content_lines = content.splitlines()
		str_path = str(path)

		is_doc_file = path.suffix in self.doc_extensions
		is_code_file = path.suffix in self.code_extensions

		# Standard Regex Scans
		file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.secret_patterns))
		file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.crypto_patterns))

		if path.suffix in self.config_extensions or path.name.startswith(".env"):
			file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.config_patterns))

		if is_code_file:
			file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.logging_patterns))

			# New Scopes - Skip logic patterns in documentation files to reduce noise
			if not is_doc_file:
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.injection_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.network_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.deserialization_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.xss_patterns))

				# --- NEW SCANS FOR DOCUMENT ---
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.xpath_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.cert_crypto_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.reflection_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.input_neutralization_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.file_system_patterns))
				file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.web_config_patterns))
				# -------------------------------

			file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.infrastructure_patterns))

		if path.name.startswith(".env"):
			file_findings.extend(self._scan_patterns(content, content_lines, str_path, self.env_patterns))

		# Feature 5: Framework Config
		file_findings.extend(self._validate_framework_config(content, content_lines, str_path))

		# Feature 2: AST Analysis (Python only)
		if path.suffix == ".py":
			file_findings.extend(self._analyze_ast_python(content_lines, str_path))

		# Dependency Parsing
		if path.name in self.dependency_parsers:
			file_findings.extend(self.dependency_parsers[path.name](content, str_path))

		return file_findings

	def analyze(self) -> List[Finding]:
		self.findings = []
		files_to_scan = []

		for target in self.targets:
			if not target.exists():
				print(f"{Colors.YELLOW}[!] Warning: Target does not exist: {target}{Colors.END}")
				continue

			if target.is_file():
				if not self._should_skip(target, check_exclusion_dirs=False):
					files_to_scan.append(target)
			elif target.is_dir():
				for root, dirs, files in os.walk(target):
					dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
					for file in files:
						path = Path(root) / file
						if not self._should_skip(path, check_exclusion_dirs=True):
							files_to_scan.append(path)

		# Execute parallel scanning
		with concurrent.futures.ThreadPoolExecutor() as executor:
			future_to_file = {executor.submit(self._process_file, f): f for f in files_to_scan}
			for future in concurrent.futures.as_completed(future_to_file):
				try:
					findings = future.result()
					self.findings.extend(findings)
				except Exception as e:
					print(f"Error scanning file: {e}")

		# Save CVE cache
		self._save_cve_cache()

		self.findings = self._deduplicate()
		self.findings = self._filter_severity()
		return self.findings

	# --- 7. SBOM Generation ---
	def generate_sbom(self, output_path: str = "sbom.json"):
		sbom = {
			"bomFormat": "CycloneDX",
			"specVersion": "1.4",
			"version": 1,
			"metadata": {
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"tools": [{"name": "SASTAnalyzer", "version": "1.0"}]
			},
			"components": []
		}

		seen_deps = set()
		for dep in self.dependencies:
			dep_id = (dep.name, dep.ecosystem)
			if dep_id in seen_deps:
				continue
			seen_deps.add(dep_id)

			sbom["components"].append({
				"type": "library",
				"name": dep.name,
				"version": dep.version,
				"purl": f"pkg:{dep.ecosystem.lower()}/{dep.name}@{dep.version}",
				"supplier": "Unknown"
			})

		with open(output_path, "w") as f:
			json.dump(sbom, f, indent=2)
		return output_path

	def generate_report(self, fmt: str = "json") -> str:
		if fmt == "json":
			findings_list = []

			# Updated Category Map
			category_map = {
				"Secret Management": self.secret_patterns,
				"Cryptography": self.crypto_patterns,
				"Configuration": self.config_patterns,
				"Logging": self.logging_patterns,
				"Environment": self.env_patterns,
				"Injection": self.injection_patterns,
				"Network": self.network_patterns,
				"Deserialization": self.deserialization_patterns,
				"XSS": self.xss_patterns,
				"Infrastructure": self.infrastructure_patterns,
			}

			for f in self.findings:
				category = "General"
				sub_agent = "SAST"

				for cat, patterns in category_map.items():
					if f.finding_type in patterns:
						category = cat
						sub_agent = f"{cat}Scanner"
						break

				# Handle new categories for JSON report
				if f.finding_type in self.xpath_patterns:
					category = "Injection"
					sub_agent = "XPathScanner"
				elif f.finding_type in self.cert_crypto_patterns:
					category = "Cryptography"
					sub_agent = "CryptoScanner"
				elif f.finding_type in self.reflection_patterns:
					category = "Injection"
					sub_agent = "ReflectionScanner"
				elif f.finding_type in self.input_neutralization_patterns:
					category = "Injection"
					sub_agent = "InputValidationScanner"
				elif f.finding_type in self.file_system_patterns:
					category = "File System"
					sub_agent = "FileScanner"
				elif f.finding_type in self.web_config_patterns:
					category = "Configuration"
					sub_agent = "WebConfigScanner"

				if "Vulnerable Dependency" in f.finding_type:
					category = "Dependency"
					sub_agent = "DependencyScanner"
				elif "Injection" in f.finding_type and "Potential" not in f.finding_type:
					# Specific check for AST detected injection
					category = "Injection"
					sub_agent = "ASTScanner"
				elif "Django" in f.finding_type or "Flask" in f.finding_type or "Spring" in f.finding_type:
					category = "Configuration"
					sub_agent = "FrameworkScanner"

				finding_entry = {
					"id": str(uuid.uuid4()),
					"agent_group": "SAST",
					"sub_agent": sub_agent,
					"vulnerability_type": f.finding_type,
					"category": category,
					"severity": f.severity.value,
					"confidence": "High",
					"target_url": None,
					"affected_parameter": f.pattern,
					"description": f.description,
					"impact": f.impact,
					"observation": f"Pattern matched in source code or configuration.",
					"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
					"proof_of_concept": None,
					"remediation": self._get_remediation(f.finding_type),
					"cve_reference": f.cve,
					"details": {
						"method": "Static File Analysis",
						"param_location": "Source Code / Config",
						"payload": f.pattern,
						"detection_method": "Regex Match / AST / API",
						"shell_context": None,
						"privilege_context": None,
						"baseline_time": None,
						"response_time": None,
						"extracted_data": {
							"type": "String Match",
							"file_path": f.file_path,
							"strategy": "StaticAnalysis",
							"line_number": f.line_number,
							"preview": f.pattern,
							"full_content_saved": False,
							"saved_path": None
						},
						"raw_request": None,
						"raw_response": None
					}
				}
				findings_list.append(finding_entry)

			report_data = {
				"status": "Success",
				"errors": [],
				"gap_reason": None,
				"findings": findings_list
			}
			return json.dumps(report_data, indent=2)

		# --- Fancy Text Report Generation (Fixed) ---
		order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
		width = 80

		# Color mapping
		sev_colors = {
			Severity.CRITICAL: f"{Colors.RED}{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}",
			Severity.HIGH: f"{Colors.RED}{Colors.BOLD}",
			Severity.MEDIUM: f"{Colors.YELLOW}{Colors.BOLD}",
			Severity.LOW: f"{Colors.BLUE}{Colors.BOLD}",
			Severity.INFO: f"{Colors.CYAN}{Colors.BOLD}"
		}
		sev_reset = Colors.END

		lines = []

		# 1. Random Banner
		banner_lines = self._get_random_banner(width)
		lines.append("")
		for line in banner_lines:
			lines.append(line)
		lines.append("")

		# 2. Scan Metadata
		scan_duration = time.time() - self.start_time

		meta_h = f" SCAN SUMMARY "
		lines.append(f"{Colors.CYAN}{'─' * width}{Colors.END}")
		lines.append(f"{Colors.BOLD}{meta_h.center(width)}{Colors.END}")
		lines.append(f"{Colors.CYAN}{'─' * width}{Colors.END}")

		targets_str = ', '.join([str(t) for t in self.targets])
		if len(targets_str) > 50:
			targets_str = targets_str[:47] + "..."

		lines.append(f"  {Colors.GREEN}Status:{Colors.END}         {Colors.BOLD}Completed{Colors.END}")
		lines.append(f"  {Colors.GREEN}Duration:{Colors.END}       {scan_duration:.2f}s")
		lines.append(f"  {Colors.GREEN}Targets:{Colors.END}        {targets_str}")
		lines.append(f"  {Colors.GREEN}Total Findings:{Colors.END} {len(self.findings)}")
		lines.append("")

		# 3. Findings Loop
		if not self.findings:
			lines.append(f"{Colors.GREEN}{Colors.BOLD}    [+] No vulnerabilities found. Great job!{Colors.END}")
			lines.append("")
		else:
			for sev in order:
				sev_findings = [f for f in self.findings if f.severity == sev]
				if sev_findings:
					# Severity Header
					color_code = sev_colors.get(sev, "")
					header_text = f" {sev.value.upper()} ({len(sev_findings)} FOUND) "

					# Top border of severity box
					lines.append(f"{color_code}┌{'─' * (width - 2)}┐{sev_reset}")

					# Calculate visual length of header text without ANSI codes for centering
					header_visual_len = self._get_visual_length(header_text)
					header_padding = (width - 2 - header_visual_len) // 2
					header_line = f"{color_code}│{' ' * header_padding}{header_text}{' ' * ((width - 2) - header_visual_len - header_padding)}│{sev_reset}"
					lines.append(header_line)

					# Separator
					lines.append(f"{color_code}├{'─' * (width - 2)}┤{sev_reset}")

					for idx, f in enumerate(sev_findings):
						# Finding Card

						# Title Line
						text_segment = f" [{idx+1}/{len(sev_findings)}] {f.finding_type}"
						visual_len = self._get_visual_length(text_segment)
						padding = max(0, (width - 2) - visual_len)

						lines.append(f"{color_code}│{sev_reset}{Colors.BOLD}{text_segment}{sev_reset}{' ' * padding}{color_code}│{sev_reset}")

						# File Line
						text_segment = f" File:       {f.file_path}"
						visual_len = self._get_visual_length(text_segment)
						padding = max(0, (width - 2) - visual_len)
						lines.append(f"{color_code}│{sev_reset}{Colors.DIM}{text_segment}{sev_reset}{' ' * padding}{color_code}│{sev_reset}")

						# Line Number Line
						text_segment = f" Line:       {f.line_number or 'N/A'}"
						visual_len = self._get_visual_length(text_segment)
						padding = max(0, (width - 2) - visual_len)
						lines.append(f"{color_code}│{sev_reset}{Colors.DIM}{text_segment}{sev_reset}{' ' * padding}{color_code}│{sev_reset}")

						# Impact Line
						text_segment = f" Impact:      {f.impact}"
						visual_len = self._get_visual_length(text_segment)
						padding = max(0, (width - 2) - visual_len)
						lines.append(f"{color_code}│{sev_reset}{Colors.DIM}{text_segment}{sev_reset}{' ' * padding}{color_code}│{sev_reset}")

						# Pattern Line (Full Length, Wrapped)
						pattern_label = " Pattern:    "
						# Calculate visual length of label to determine padding for wrapped lines
						label_visual_len = self._get_visual_length(pattern_label)
						# Available space for text inside the box is (width - 2) - label_visual_len
						text_width = (width - 2) - label_visual_len

						# Clean pattern for display (replace newlines with space to avoid vertical mess inside the box)
						# Note: We print the entire pattern as requested.
						pattern_clean = f.pattern.replace('\n', ' ')

						# Use textwrap to split the pattern text into chunks that fit the width
						# initial_indent handles the first line, subsequent_indent handles the rest
						wrapped_lines = textwrap.wrap(
							pattern_clean,
							width=width - 2,
							initial_indent=pattern_label,
							subsequent_indent=" " * label_visual_len,
							break_long_words=True, # Ensure we fit in the box even if it cuts a token
							break_on_hyphens=False
						)

						# If textwrap fails to wrap (rare edge case), just print the raw line
						if not wrapped_lines and pattern_clean:
							wrapped_lines = [pattern_label + pattern_clean]

						for line_content in wrapped_lines:
							visual_len = self._get_visual_length(line_content)
							padding = max(0, (width - 2) - visual_len)
							lines.append(f"{color_code}│{sev_reset}{Colors.DIM}{line_content}{sev_reset}{' ' * padding}{color_code}│{sev_reset}")

						if idx < len(sev_findings) - 1:
							# Internal separator
							lines.append(f"{color_code}│{sev_reset} {' ' * (width - 4)} {color_code}│{sev_reset}")

					# Bottom border
					lines.append(f"{color_code}└{'─' * (width - 2)}┘{sev_reset}")
					lines.append("")

		# Footer
		lines.append(f"{Colors.DIM}Generated by SASTAnalyzer v1.0 // Static Analysis Module{Colors.END}")

		return "\n".join(lines)

	# --- 8. CI/CD Annotations Support ---
	def print_ci_annotations(self):
		if "GITHUB_ACTIONS" in os.environ or "GITLAB_CI" in os.environ:
			for f in self.findings:
				level = "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "warning"
				msg = f"{f.finding_type}: {f.description}"
				if "GITHUB_ACTIONS" in os.environ:
					print(f"::{level} file={f.file_path},line={f.line_number},title={f.finding_type}::{msg}")
				elif "GITLAB_CI" in os.environ:
					print(f"{f.file_path}:{f.line_number} {level} {f.finding_type}: {msg}")

def clone_repository(git_url: str) -> Tuple[str, str]:
	temp_root = tempfile.mkdtemp(prefix="sast_scan_")
	repo_dir = os.path.join(temp_root, "repo")

	try:
		print(f"{Colors.CYAN}[*] Cloning repository {git_url} into {repo_dir}...{Colors.END}")
		subprocess.check_call(
			["git", "clone", "--depth", "1", git_url, repo_dir],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL
		)
		print(f"{Colors.GREEN}[+] Clone successful.{Colors.END}")
		return repo_dir, temp_root
	except subprocess.CalledProcessError as e:
		shutil.rmtree(temp_root)
		raise RuntimeError(f"Failed to clone repository: {git_url}. Ensure git is installed and the URL is correct.")
	except FileNotFoundError:
		shutil.rmtree(temp_root)
		raise RuntimeError("Git is not installed or not found in PATH. Please install Git to use remote URL scanning.")

def main():
	import argparse

	# Custom formatter to maintain newlines in help text
	class SmartFormatter(argparse.HelpFormatter):
		def _split_lines(self, text, width):
			if text.startswith('R|'):
				return text[2:].splitlines()
			return argparse.HelpFormatter._split_lines(self, text, width)

	parser = argparse.ArgumentParser(
		prog="SASTScanner",
		formatter_class=SmartFormatter,
		description="Professional Static Application Security Testing (SAST) tool.\n\n"
																								"Scans source code, dependencies, and configurations for security vulnerabilities, "
																								"secrets, and compliance issues using static analysis, regex patterns, and AST parsing.",
		epilog="Examples:\n"
																				 "  Scan a local directory:\n"
																				 "    python scanner.py ./src\n\n"
																				 "  Scan a remote Git repository:\n"
																				 "    python scanner.py https://github.com/user/repo.git\n\n"
																				 "  Scan a website for exposed .git repositories:\n"
																				 "    python scanner.py https://example.com\n\n"
																				 "  Scan and save a JSON report:\n"
																				 "    python scanner.py ./project --output json --output-file report.json"
	)

	# --- Target Specification ---
	target_group = parser.add_argument_group("Target Specification")
	target_group.add_argument(
		"targets",
		metavar="TARGET",
		nargs="+",
		help="Specify one or more target paths. Can be local files/directories, remote Git URLs "
																				 "(supports http/https/git@ protocols), or websites (checks for exposed .git)."
	)

	# --- Analysis Configuration ---
	config_group = parser.add_argument_group("Analysis Configuration")
	config_group.add_argument(
		"--exclude",
		metavar="DIR",
		nargs="*",
		default=[],
		help="List of directory names to exclude from the scan (e.g., node_modules, tests, vendor). "
																				 "Default excludes already apply."
	)
	config_group.add_argument(
		"--severity",
		choices=["critical", "high", "medium", "low", "info"],
		default="info",
		help="Minimum severity level to report. Findings below this threshold will be ignored. "
																				 "(default: %(default)s)"
	)

	# --- Reporting & Output ---
	report_group = parser.add_argument_group("Reporting & Output")
	report_group.add_argument(
		"--output",
		choices=["json", "text"],
		default="json",
		help="Specify the output format for the scan results. (default: %(default)s)"
	)
	report_group.add_argument(
		"--output-file",
		metavar="PATH",
		help="Path to save the report file. If omitted, the report will be printed to STDOUT."
	)
	report_group.add_argument(
		"--sbom",
		action="store_true",
		help="Generate a Software Bill of Materials (SBOM) in CycloneDX format (saved as sbom.json)."
	)
	report_group.add_argument(
		"--fail-on",
		choices=["critical", "high", "medium", "low", "info", "none"],
		default="high",
		help="Minimum severity level to trigger a non-zero exit code. Useful for failing CI/CD pipelines. "
																				 "Set to 'none' to always return 0. (default: %(default)s)"
	)

	args = parser.parse_args()

	sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}

	resolved_targets = []
	temp_cleanup_dirs = []

	for target_str in args.targets:
		# 1. Check if it's a local path
		p = Path(target_str)
		if p.exists():
			resolved_targets.append(target_str)
			continue

		# 2. Check if it's a URL
		is_url = target_str.startswith("http://") or target_str.startswith("https://") or target_str.startswith("git@")
		is_git_url = target_str.endswith(".git")

		if is_url:
			if not is_git_url:
				# --- NEW FEATURE: Check for exposed .git directory on websites ---
				print(f"{Colors.CYAN}[*] Checking {target_str} for exposed .git directory...{Colors.END}")
				exposed = False
				try:
					# We look for .git/HEAD. Standard HEAD content looks like: "ref: refs/heads/master"
					head_url = target_str.rstrip('/') + '/.git/HEAD'
					req = urllib.request.Request(head_url)
					# Add User-Agent to avoid some WAFs blocking python-urllib
					req.add_header('User-Agent', 'Mozilla/5.0')

					with urllib.request.urlopen(req, timeout=10) as response:
						content = response.read().decode('utf-8', errors='ignore')
						# Check if it contains references to heads
						if 'refs/heads' in content:
							exposed = True
				except Exception as e:
					# Not exposed, or connection error
					pass

				if exposed:
					print(f"{Colors.GREEN}[+] Exposed .git repository found at {target_str}!{Colors.END}")
					print(f"{Colors.YELLOW}[*] Attempting to dump repository contents...{Colors.END}")

					# Create a temporary directory for the dump
					dump_temp_root = tempfile.mkdtemp(prefix="sast_dump_")
					dump_repo_path = os.path.join(dump_temp_root, "repo")

					try:
						# Initialize and run GitDumper
						# The base URL must point to the .git folder
						git_base_url = target_str.rstrip('/') + '/.git/'
						dumper = GitDumper(git_base_url, dump_repo_path)
						dumper.dump()

						# --- NEW INTEGRATION: Extract Commits ---
						# After dumping, use GitExtractor to recover commits and content
						print(f"{Colors.CYAN}[*] Extracting commits and content from dumped repository...{Colors.END}")
						extract_path = os.path.join(dump_temp_root, "extracted_commits")

						extractor = GitExtractor(dump_repo_path, extract_path)
						extractor.extract()

						# Add both the raw dump and the extracted commits to targets
						resolved_targets.append(dump_repo_path)
						resolved_targets.append(extract_path)
						temp_cleanup_dirs.append(dump_temp_root)
						print(f"{Colors.GREEN}[+] Dump and extraction successful. Ready to scan.{Colors.END}")
						continue
					except Exception as e:
						print(f"{Colors.RED}[!] Failed to dump or extract repository: {e}{Colors.END}")
						shutil.rmtree(dump_temp_root)
				else:
					print(f"{Colors.DIM}[-] No exposed .git/HEAD found at {target_str}.{Colors.END}")

			# If not an exposed web git (or dumper failed), try standard git clone logic
			# This handles standard github/gitlab URLs ending in .git
			try:
				repo_path, temp_root = clone_repository(target_str)
				resolved_targets.append(repo_path)
				temp_cleanup_dirs.append(temp_root)
			except RuntimeError as e:
				print(f"{Colors.RED}Error: {e}{Colors.END}")
		else:
			print(f"{Colors.YELLOW}[!] Warning: Input path not found and not a valid URL: {target_str}{Colors.END}")

	if not resolved_targets:
		print(f"{Colors.RED}[!] No valid targets found to scan.{Colors.END}")
		sys.exit(1)

	analyzer = None
	try:
		analyzer = SASTAnalyzer(resolved_targets, args.exclude, sev_map[args.severity])
		analyzer.analyze()

		if args.sbom:
			sbom_path = analyzer.generate_sbom()
			print(f"{Colors.GREEN}[+] SBOM generated at {sbom_path}{Colors.END}")

		analyzer.print_ci_annotations()

		report = analyzer.generate_report(args.output)
		if args.output_file:
			Path(args.output_file).write_text(report)
			print(f"{Colors.GREEN}[+] Report written to {args.output_file}{Colors.END}")
		else:
			print(report)

		if args.fail_on != "none":
			fail_threshold = sev_map[args.fail_on]
			order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
			for f in analyzer.findings:
				if order.index(f.severity) <= order.index(fail_threshold):
					sys.exit(1)
		sys.exit(0)

	except FileNotFoundError as e:
		print(f"{Colors.RED}Error: {e}{Colors.END}")
		sys.exit(1)
	finally:
		for temp_dir in temp_cleanup_dirs:
			try:
				print(f"{Colors.DIM}[*] Cleaning up temporary directory {temp_dir}...{Colors.END}")
				shutil.rmtree(temp_dir)
			except Exception as e:
				print(f"{Colors.YELLOW}[!] Warning: Could not remove temporary directory {temp_dir}: {e}{Colors.END}")

if __name__ == "__main__":
	main()