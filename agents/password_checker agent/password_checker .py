"""
Password Policy Checker Agent — Fixed Version
==============================================
Fixes applied:
  1. _selenium_success() — no longer returns True on "no error" (false positive)
  2. Probe accounts use totally separate email domain to avoid collision
  3. Main account credentials printed clearly and saved immediately after creation
  4. Form filler: security answer filled BEFORE submit in all paths
  5. After each probe, page is fully reloaded to clear state
  6. created_accounts.json saved right after account creation (not just at end)
  7. Manual-login-friendly: credentials printed with copy-paste formatting
  8. _register() no longer silently swallows Selenium false-positives
  9. API probe now always tries a fresh unique email
  10. Improved error scraping covers more UI frameworks
"""

import json
import time
import uuid
import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager


# ─────────────────────────────────────────────────────────────────────────────
# Severity scoring
# ─────────────────────────────────────────────────────────────────────────────

def score_policy(policy):
    score    = 0
    findings = []
    min_len  = policy.get("minimum_length")

    if min_len is None:
        findings.append("CRITICAL  — No minimum length enforced: any password accepted")
    elif isinstance(min_len, int):
        if min_len >= 12:
            score += 30
            findings.append(f"GOOD      — Minimum length is {min_len} characters (>=12)")
        elif min_len >= 8:
            score += 15
            findings.append(f"MODERATE  — Minimum length is {min_len} characters (8-11)")
        else:
            score += 5
            findings.append(f"WEAK      — Minimum length is only {min_len} characters (<8)")
    else:
        score += 10
        findings.append(f"INFO      — Minimum length: {min_len}")

    for key, label, pts in [
        ("requires_uppercase", "Uppercase letter required", 15),
        ("requires_lowercase", "Lowercase letter required", 15),
        ("requires_number",    "Number required",           15),
        ("requires_symbol",    "Symbol required",           20),
    ]:
        if policy.get(key):
            score += pts
            findings.append(f"GOOD      — {label}")
        else:
            findings.append(f"MISSING   — {label} not enforced")

    if policy.get("password_history_enforced"):
        score += 5
        findings.append("GOOD      — Password history enforced")
    else:
        findings.append("UNKNOWN   — Password history: not tested / not enforced")

    if   score >= 80: lbl, tag = "STRONG",   "green"
    elif score >= 50: lbl, tag = "MODERATE", "yellow"
    elif score >= 20: lbl, tag = "WEAK",     "red"
    else:             lbl, tag = "CRITICAL",  "red"

    return score, lbl, tag, findings


# ─────────────────────────────────────────────────────────────────────────────
# Universal App API Client
# ─────────────────────────────────────────────────────────────────────────────

class AppAPIClient:
    REGISTER_CANDIDATES = [
        "/api/Users",
        "/api/register",
        "/api/v1/users",
        "/api/v1/register",
        "/api/auth/register",
        "/register",
        "/signup",
        "/WebGoat/register.mvc",
        "/bWAPP/user_new.php",
        "/mutillidae/index.php",
    ]

    LOGIN_CANDIDATES = [
        "/rest/user/login",
        "/api/login",
        "/api/v1/login",
        "/api/auth/login",
        "/api/v1/auth/login",
        "/login",
        "/WebGoat/login",
        "/bWAPP/login.php",
        "/mutillidae/index.php",
    ]

    def __init__(self, base_url):
        self.base    = base_url.split("#")[0].rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "PasswordPolicyChecker/1.0"})

        self._register_url    = None
        self._login_url       = None
        self._register_method = None
        self._login_method    = None
        self._extra_fields    = {}
        self._csrf_token      = None
        self._working         = False
        self._security_questions = []

    def discover(self):
        print("    [API] Probing registration endpoints...")
        self._fetch_security_questions()

        for suffix in self.REGISTER_CANDIDATES:
            url = self.base + suffix
            result = self._probe_register_endpoint(url)
            if result:
                self._register_url    = url
                self._register_method = result
                print(f"    [API] Found register endpoint: {url} ({result})")
                self._working = True
                break

        if not self._working:
            print("    [API] No API endpoint found — will use Selenium form")
            return False

        for suffix in self.LOGIN_CANDIDATES:
            url = self.base + suffix
            if self._probe_login_endpoint(url):
                self._login_url = url
                print(f"    [API] Found login endpoint: {url}")
                break

        return True

    def _fetch_security_questions(self):
        candidates = [
            "/api/SecurityQuestions",
            "/api/v1/security-questions",
            "/api/security_questions",
        ]
        for suffix in candidates:
            try:
                r = self.session.get(self.base + suffix, timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    qs   = data.get("data", data if isinstance(data, list) else [])
                    if qs and isinstance(qs, list) and len(qs) > 0:
                        self._security_questions = qs
                        print(f"    [API] Fetched {len(qs)} security questions from {suffix}")
                        print(f"    [API] Using: \"{qs[0].get('question','?')}\"")
                        self._extra_fields["securityQuestion"] = qs[0]
                        return
            except Exception:
                pass

    def _probe_register_endpoint(self, url):
        uid   = uuid.uuid4().hex[:8]
        email = f"canary{uid}@canary.com"
        pw    = "CanaryPass1!"

        try:
            payload = self._build_json_payload(email, pw)
            r = self.session.post(
                url, json=payload, timeout=8,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            if r.status_code in (200, 201, 400, 409, 422):
                try:
                    body = r.json()
                    if isinstance(body, dict):
                        has_api_keys = any(k in body for k in (
                            "status", "data", "user", "id", "email",
                            "message", "error", "token", "success",
                        ))
                        if has_api_keys:
                            return "json"
                except Exception:
                    pass
        except Exception:
            pass

        try:
            payload = self._build_form_payload(email, pw)
            r = self.session.post(url, data=payload, timeout=8, allow_redirects=True)
            if r.status_code in (200, 302) and len(r.text) > 200:
                text_lower = r.text.lower()
                if any(k in text_lower for k in (
                    "register", "login", "password", "username",
                    "successfully", "already", "invalid",
                )):
                    return "form"
        except Exception:
            pass

        return None

    def _probe_login_endpoint(self, url):
        try:
            r = self.session.post(
                url, json={"email": "test@test.com", "password": "test"}, timeout=5
            )
            return r.status_code in (200, 400, 401, 403, 422)
        except Exception:
            try:
                r = self.session.post(
                    url,
                    data={"username": "test", "password": "test", "Login": "Login"},
                    timeout=5, allow_redirects=False
                )
                return r.status_code in (200, 302, 400, 401, 403)
            except Exception:
                return False

    def _build_json_payload(self, email, password, answer="MyAnswer123"):
        payload = {
            "email":          email,
            "username":       email.split("@")[0],
            "password":       password,
            "passwordRepeat": password,
            "password2":      password,
            "securityAnswer": answer,
        }
        if self._security_questions:
            payload["securityQuestion"] = self._security_questions[0]
        return payload

    def _build_form_payload(self, email, password, answer="MyAnswer123"):
        uid = email.split("@")[0]
        payload = {
            "email":            email,
            "username":         uid,
            "user":             uid,
            "login":            uid,
            "password":         password,
            "password_confirm": password,
            "password2":        password,
            "confirm_password": password,
            "cpassword":        password,
            "pass":             password,
            "pass2":            password,
            "secret_q_a":       answer,
            "my-answer":        answer,
            "security_answer":  answer,
            "securityAnswer":   answer,
            "hint":             answer,
            "firstname":        "Agent",
            "lastname":         "Tester",
            "first_name":       "Agent",
            "last_name":        "Tester",
            "agree":            "1",
            "terms":            "1",
        }
        if self._csrf_token:
            payload["csrf_token"]  = self._csrf_token
            payload["user_token"]  = self._csrf_token
            payload["_token"]      = self._csrf_token
        return payload

    def _get_csrf_token(self, page_url):
        try:
            r    = self.session.get(page_url, timeout=8)
            soup = BeautifulSoup(r.text, "html.parser")

            for name in ("csrf_token", "user_token", "_token",
                         "authenticity_token", "csrfmiddlewaretoken"):
                el = soup.find("input", {"name": name})
                if el:
                    self._csrf_token = el.get("value", "")
                    print(f"    [API] CSRF token captured ({name})")
                    return self._csrf_token

            meta = soup.find("meta", {"name": "csrf-token"})
            if meta:
                self._csrf_token = meta.get("content", "")
                return self._csrf_token
        except Exception:
            pass
        return None

    def register(self, email, password, answer="MyAnswer123"):
        if not self._working:
            return False, "No API endpoint"

        self._get_csrf_token(self._register_url)

        try:
            if self._register_method == "json":
                payload = self._build_json_payload(email, password, answer)
                r = self.session.post(self._register_url, json=payload, timeout=10)
                try:
                    body = r.json()
                    if r.status_code in (200, 201):
                        if body.get("status") == "success":
                            return True, f"Created (id={body.get('data',{}).get('id','?')})"
                        if body.get("success") or body.get("created"):
                            return True, "Account created"
                        if "token" in body or "user" in body:
                            return True, "Account created"
                    err = (body.get("message") or body.get("error")
                           or body.get("detail") or str(body))
                    return False, str(err)[:150]
                except Exception:
                    if r.status_code in (200, 201, 302):
                        return True, "Account likely created (non-JSON response)"
                    return False, f"HTTP {r.status_code}"

            else:
                payload = self._build_form_payload(email, password, answer)
                r = self.session.post(
                    self._register_url, data=payload,
                    timeout=10, allow_redirects=True
                )
                body_lower = r.text.lower()
                if any(k in body_lower for k in (
                    "successfully", "account created", "registered",
                    "thank you", "welcome", "login", "sign in",
                    "created successfully"
                )):
                    return True, "Account created (form)"
                if any(k in body_lower for k in (
                    "already exists", "already registered", "taken",
                    "duplicate", "error", "invalid", "failed"
                )):
                    soup = BeautifulSoup(r.text, "html.parser")
                    for sel in (".alert", ".error", ".danger",
                                "[class*=error]", "[class*=alert]"):
                        el = soup.select_one(sel)
                        if el:
                            return False, el.get_text(strip=True)[:150]
                    return False, "Registration failed (form)"

                if r.status_code == 302 or len(r.history) > 0:
                    return True, "Account created (redirect)"

                return False, f"Ambiguous response (HTTP {r.status_code})"

        except Exception as e:
            return False, str(e)[:100]

    def login(self, email, password):
        if not self._login_url:
            return False, None, "No login endpoint"

        uid = email.split("@")[0]

        json_payloads = [
            {"email": email,    "password": password},
            {"username": uid,   "password": password},
            {"login": uid,      "password": password},
            {"user": uid,       "password": password},
        ]

        for json_payload in json_payloads:
            try:
                r = self.session.post(
                    self._login_url, json=json_payload, timeout=10,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )
                if r.status_code == 401:
                    try:
                        body = r.json()
                        err  = (body.get("error") or body.get("message")
                                or "Invalid email or password")
                        return False, None, str(err)
                    except Exception:
                        return False, None, "Invalid credentials (HTTP 401)"

                if r.status_code == 200:
                    try:
                        body  = r.json()
                        token = (body.get("authentication", {}).get("token")
                                 or body.get("token")
                                 or body.get("access_token")
                                 or body.get("jwt"))
                        if token:
                            return True, token, "Login successful"
                        if (body.get("success") is True
                                or body.get("status") == "success"
                                or body.get("user")):
                            return True, None, "Login successful (no token)"
                        err = (body.get("error") or body.get("message"))
                        if err:
                            return False, None, str(err)
                    except Exception:
                        return True, None, "Login successful (non-JSON)"

            except Exception as e:
                print(f"    [API] JSON login attempt failed: {e}")
                continue

        self._get_csrf_token(self._login_url)
        form_payloads = [
            {"username": uid,   "password": password,
             "Login": "Login",  "user_token": self._csrf_token or ""},
            {"email": email,    "password": password},
            {"user": uid,       "password": password,  "Login": "Login"},
        ]

        for form_payload in form_payloads:
            try:
                r = self.session.post(
                    self._login_url, data=form_payload,
                    timeout=10, allow_redirects=True,
                )
                body_lower = r.text.lower()
                if any(k in body_lower for k in (
                    "logout", "sign out", "welcome", "dashboard",
                    "logged in", "your profile", "my account",
                )):
                    return True, None, "Login successful (form)"
                if any(k in body_lower for k in (
                    "invalid", "incorrect", "wrong", "failed", "error",
                    "bad credentials",
                )):
                    return False, None, "Invalid credentials (form)"
            except Exception as e:
                print(f"    [API] Form login attempt failed: {e}")
                continue

        return False, None, "Login failed — all methods exhausted"

    def probe_password(self, password):
        if not self._working:
            return None, "no_api"

        # FIX: use truly unique domain per probe to avoid any collision
        uid   = uuid.uuid4().hex[:12]
        email = f"probe{uid}@probedomain{uid[:6]}.com"
        ok, msg = self.register(email, password)
        if ok:
            return "accepted", ""
        if any(k in msg.lower() for k in (
            "password", "length", "character", "uppercase", "lowercase",
            "digit", "number", "symbol", "special", "weak", "policy",
            "must contain", "at least", "too short", "invalid password"
        )):
            return "rejected", msg
        if any(k in msg.lower() for k in (
            "already", "exists", "duplicate", "taken", "registered"
        )):
            return "accepted", ""
        return "rejected", msg


# ─────────────────────────────────────────────────────────────────────────────
# Universal Form Handler (Selenium — works on ANY app)
# ─────────────────────────────────────────────────────────────────────────────

class UniversalFormHandler:
    SECURITY_ANSWERS = {
        "mother":    "Jane",       "pet":       "Fluffy",
        "school":    "Greenwood",  "city":      "Springfield",
        "born":      "Springfield","friend":    "Alex",
        "car":       "Toyota",     "color":     "Blue",
        "colour":    "Blue",       "food":      "Pizza",
        "teacher":   "MrSmith",   "maiden":    "Johnson",
        "sibling":   "Alex",       "brother":   "Alex",
        "sister":    "Alex",       "sport":     "Football",
        "movie":     "Inception",  "book":      "HarryPotter",
        "childhood": "Fluffy",     "street":    "MainStreet",
        "company":   "TechCorp",   "work":      "TechCorp",
        "default":   "MyAnswer123",
    }

    def __init__(self, driver):
        self.driver  = driver
        self._filled = []

    def _set(self, el, value):
        try:    el.clear()
        except: pass
        try:
            el.send_keys(Keys.CONTROL + "a")
            el.send_keys(Keys.DELETE)
        except: pass
        el.send_keys(str(value))

    def _attrs(self, el):
        return " ".join(filter(None, [
            el.get_attribute("name")            or "",
            el.get_attribute("id")              or "",
            el.get_attribute("formcontrolname") or "",
            el.get_attribute("placeholder")     or "",
            el.get_attribute("autocomplete")    or "",
            el.get_attribute("aria-label")      or "",
            el.get_attribute("class")           or "",
            el.get_attribute("type")            or "",
        ])).lower()

    def _classify(self, el):
        typ = (el.get_attribute("type") or "text").lower()
        a   = self._attrs(el)

        if typ == "hidden":   return "hidden"
        if typ == "radio":    return "skip"
        if typ in ("submit", "button", "reset", "image"): return "skip"

        if typ == "checkbox":
            if any(k in a for k in ("agree","accept","terms","condition",
                                    "privacy","gdpr","toc","tos")):
                return "terms"
            return "skip"

        if "captcha" in a:    return "captcha"

        if typ == "password":
            if any(k in a for k in ("confirm","repeat","retype","verify",
                                    "again","second","re_","_2","2nd",
                                    "match","reenter","re-enter")):
                return "confirm_password"
            return "password"

        if "email" in a:      return "email"

        if any(k in a for k in ("securityanswer","security_answer",
                                "securityanswercontrol","secret_q_a",
                                "my-answer","hint_answer","sec_answer",
                                "secret_answer")):
            return "security_answer"

        if any(k in a for k in ("answer",)) and "security" not in a:
            return "security_answer"

        if any(k in a for k in ("confirm","repeat","retype","verify")):
            return "confirm_password"

        if any(k in a for k in ("username","user_name","uname","userid",
                                "login_name","loginname","screen_name",
                                "account_name","nickname","nick",
                                "login","user")):
            return "username"

        if any(k in a for k in ("firstname","first_name","fname",
                                "given_name","givenname","forename")):
            return "firstname"

        if any(k in a for k in ("lastname","last_name","lname","surname",
                                "family_name","familyname")):
            return "lastname"

        if any(k in a for k in ("fullname","full_name","realname",
                                "displayname","display_name")):
            return "fullname"

        if "name" in a and not any(k in a for k in ("user","last","first",
                                                     "full","display")):
            return "fullname"

        if any(k in a for k in ("phone","mobile","tel","cell","contact_no",
                                "phonenumber","phone_number","cellphone")):
            return "phone"

        if any(k in a for k in ("dob","date_of_birth","birthdate","birthday",
                                "birth_date","dateofbirth","bday")):
            return "dob"

        if any(k in a for k in ("ssn","socialsecurity","social_security",
                                "sin","taxid","tax_id")):
            return "ssn"

        if any(k in a for k in ("zip","postal","postcode","post_code")):
            return "zip"

        if any(k in a for k in ("address","street")):
            return "address"

        if any(k in a for k in (" age ",)):
            return "age"

        if any(k in a for k in ("website","url","homepage","blog")):
            return "website"

        if any(k in a for k in ("city",)):
            return "city"

        if any(k in a for k in ("state","province","region")):
            return "state"

        if any(k in a for k in ("country","nation")):
            return "country"

        return "unknown"

    def _best_answer(self, question_text):
        q = (question_text or "").lower()
        for kw, ans in self.SECURITY_ANSWERS.items():
            if kw in q:
                return ans
        return self.SECURITY_ANSWERS["default"]

    def _handle_native_selects(self):
        chosen = []
        for sel_el in self.driver.find_elements(By.TAG_NAME, "select"):
            if not sel_el.is_displayed():
                continue
            try:
                sel  = Select(sel_el)
                opts = [o for o in sel.options
                        if (o.get_attribute("value") or "").strip()]
                if not opts:
                    continue

                texts = [o.text.lower() for o in opts]
                is_sec = any(any(k in t for k in (
                    "mother","pet","school","city","friend","born","car",
                    "color","colour","sibling","teacher","maiden","sport",
                    "book","street","childhood","company","movie","work",
                    "first","childhood","memorable"
                )) for t in texts)

                sel.select_by_index(1)
                chosen_text = opts[0].text
                time.sleep(0.5)

                if is_sec:
                    print(f"    [Form] Security question (select): \"{chosen_text[:70]}\"")
                    chosen.append(chosen_text)
                else:
                    print(f"    [Form] Dropdown selected: \"{chosen_text[:50]}\"")

            except Exception as e:
                print(f"    [Form] Select error: {e}")
        return chosen

    def _handle_mat_selects(self):
        chosen = []
        try:
            triggers = self.driver.find_elements(
                By.CSS_SELECTOR,
                "mat-select, [role='combobox'], .mat-select-trigger, "
                "[class*='mat-select']"
            )
            for trigger in triggers:
                if not trigger.is_displayed():
                    continue
                try:
                    trigger.click()
                    time.sleep(1.2)

                    WebDriverWait(self.driver, 6).until(
                        EC.presence_of_element_located(
                            (By.CSS_SELECTOR, "mat-option, .mat-option")
                        )
                    )
                    options = self.driver.find_elements(
                        By.CSS_SELECTOR, "mat-option, .mat-option"
                    )
                    real = [o for o in options
                            if o.is_displayed() and len((o.text or "").strip()) > 2]
                    if real:
                        txt = real[0].text.strip()
                        real[0].click()
                        time.sleep(0.5)
                        chosen.append(txt)
                        print(f"    [Form] mat-select chosen: \"{txt[:70]}\"")

                except Exception:
                    try:
                        self.driver.find_element(By.TAG_NAME, "body").send_keys(Keys.ESCAPE)
                    except: pass
        except Exception as e:
            print(f"    [Form] mat-select error: {e}")
        return chosen

    def _fill_security_answer(self, question_texts):
        answer = self._best_answer(question_texts[0] if question_texts else "")

        selectors = [
            "//input[@name='secret_q_a']",
            "//input[@name='my-answer']",
            "//input[@formcontrolname='securityAnswerControl']",
            "//input[contains(@name,'answer')]",
            "//input[contains(@id,'answer')]",
            "//input[contains(@placeholder,'answer')]",
            "//input[contains(@placeholder,'Answer')]",
            "//input[contains(@formcontrolname,'answer')]",
            "//input[contains(@aria-label,'answer')]",
            "//input[contains(@aria-label,'Answer')]",
            "//input[contains(@class,'answer')]",
            "//input[contains(@name,'secret')]",
            "//input[contains(@name,'hint')]",
        ]
        for sel in selectors:
            try:
                el = self.driver.find_element(By.XPATH, sel)
                if el.is_displayed() and el.get_attribute("type") != "hidden":
                    self._set(el, answer)
                    self._filled.append(("security_answer", answer))
                    print(f"    [Form] Security answer filled: \"{answer}\"")
                    return True
            except Exception:
                pass
        return False

    def fill(self, password, account):
        self._filled = []

        try:
            WebDriverWait(self.driver, 12).until(
                EC.presence_of_element_located((By.XPATH, "//input"))
            )
        except Exception:
            pass
        time.sleep(2)

        if self.driver.find_elements(By.CSS_SELECTOR,
            "iframe[src*='recaptcha'], .g-recaptcha, "
            "[class*='captcha'], [id*='captcha']"):
            print("    [Form] WARNING: CAPTCHA detected — may need manual help")

        pw_fields      = []
        confirm_fields = []
        sec_ans_filled = False

        # ── Pass 1: all visible inputs ─────────────────────────────────────────
        for inp in self.driver.find_elements(By.TAG_NAME, "input"):
            try:
                if not inp.is_displayed():
                    continue
                ft = self._classify(inp)

                if ft in ("skip", "hidden", "captcha"):
                    continue

                elif ft == "terms":
                    if not inp.is_selected():
                        try:
                            inp.click()
                        except Exception:
                            try:
                                self.driver.execute_script("arguments[0].click();", inp)
                            except: pass
                        self._filled.append(("terms", "checked"))
                        print("    [Form] Terms checkbox checked")

                elif ft == "email":
                    self._set(inp, account["email"])
                    self._filled.append(("email", account["email"]))

                elif ft == "username":
                    self._set(inp, account["username"])
                    self._filled.append(("username", account["username"]))

                elif ft == "password":
                    pw_fields.append(inp)

                elif ft == "confirm_password":
                    confirm_fields.append(inp)

                elif ft == "security_answer":
                    ans = self._best_answer(account.get("security_answer",""))
                    self._set(inp, ans)
                    self._filled.append(("security_answer", ans))
                    sec_ans_filled = True
                    print(f"    [Form] Security answer (input): \"{ans}\"")

                elif ft == "firstname":
                    self._set(inp, "Agent")
                    self._filled.append(("firstname", "Agent"))

                elif ft == "lastname":
                    self._set(inp, "Tester")
                    self._filled.append(("lastname", "Tester"))

                elif ft == "fullname":
                    self._set(inp, "Agent Tester")
                    self._filled.append(("fullname", "Agent Tester"))

                elif ft == "phone":
                    self._set(inp, "9999999999")
                    self._filled.append(("phone", "9999999999"))

                elif ft == "dob":
                    for fmt in ("01/01/1990", "1990-01-01", "01-01-1990"):
                        try:
                            self._set(inp, fmt)
                            break
                        except: pass
                    self._filled.append(("dob", "01/01/1990"))

                elif ft == "ssn":
                    self._set(inp, "123-45-6789")
                    self._filled.append(("ssn", "123-45-6789"))
                    print("    [Form] SSN filled: 123-45-6789")

                elif ft == "zip":
                    self._set(inp, "12345")
                    self._filled.append(("zip", "12345"))

                elif ft == "address":
                    self._set(inp, "123 Test Street")
                    self._filled.append(("address", "123 Test St"))

                elif ft == "city":
                    self._set(inp, "Springfield")
                    self._filled.append(("city", "Springfield"))

                elif ft == "state":
                    self._set(inp, "NY")
                    self._filled.append(("state", "NY"))

                elif ft == "country":
                    self._set(inp, "US")
                    self._filled.append(("country", "US"))

                elif ft == "age":
                    self._set(inp, "25")
                    self._filled.append(("age", "25"))

                elif ft == "website":
                    self._set(inp, "https://example.com")
                    self._filled.append(("website", "https://example.com"))

                elif ft == "unknown":
                    if not (inp.get_attribute("value") or "").strip():
                        self._set(inp, account["username"])
                        self._filled.append(("unknown->username", account["username"]))

            except Exception:
                pass

        # ── Pass 2: fill passwords ─────────────────────────────────────────────
        if pw_fields:
            self._set(pw_fields[0], password)
            self._filled.append(("password", "***"))
        if confirm_fields:
            self._set(confirm_fields[0], password)
            self._filled.append(("confirm_password", "***"))
        elif len(pw_fields) > 1:
            self._set(pw_fields[1], password)
            self._filled.append(("confirm_password_2nd", "***"))

        # ── Pass 3: dropdowns ──────────────────────────────────────────────────
        time.sleep(0.5)
        chosen_q  = self._handle_native_selects()
        chosen_q += self._handle_mat_selects()
        time.sleep(1)

        # ── Pass 4: security answer (ALWAYS run after dropdowns) ───────────────
        # FIX: always attempt to fill security answer after dropdown selection,
        # even if sec_ans_filled=True, because dropdown changes the visible answer field
        self._fill_security_answer(chosen_q)

        # ── Pass 5: visible textareas ──────────────────────────────────────────
        for ta in self.driver.find_elements(By.TAG_NAME, "textarea"):
            try:
                if ta.is_displayed():
                    a = self._attrs(ta)
                    if any(k in a for k in ("bio","about","description","comment")):
                        self._set(ta, "Test account")
                        self._filled.append(("textarea", "Test account"))
            except Exception:
                pass

        # ── Pass 6: second pass for dynamically loaded fields ──────────────────
        time.sleep(1.5)
        for inp in self.driver.find_elements(By.TAG_NAME, "input"):
            try:
                if not inp.is_displayed():
                    continue

                val = inp.get_attribute("value") or ""
                if val.strip():
                    continue  # already filled

                ft = self._classify(inp)

                if ft == "unknown":
                    self._set(inp, account["username"])
                    self._filled.append(("secondpass_unknown", account["username"]))
                    print(f"    [Form] 2nd pass unknown field filled")

                elif ft == "zip":
                    self._set(inp, "12345")
                    self._filled.append(("secondpass_zip", "12345"))

                elif ft == "ssn":
                    self._set(inp, "123-45-6789")
                    self._filled.append(("secondpass_ssn", "123-45-6789"))
                    print("    [Form] 2nd pass SSN filled")

                elif ft == "phone":
                    self._set(inp, "9999999999")
                    self._filled.append(("secondpass_phone", "9999999999"))

                elif ft == "security_answer":
                    ans = self._best_answer("")
                    self._set(inp, ans)
                    self._filled.append(("secondpass_security_answer", ans))
                    print(f"    [Form] 2nd pass security answer filled: \"{ans}\"")

            except:
                pass

        print(f"    [Form] Fields handled: {[f[0] for f in self._filled]}")

    def submit(self):
        """
        FIX: Try submit buttons in priority order.
        Prefer buttons with submit-like text, fall back to first visible button.
        """
        submit_keywords = ["register","sign up","signup","create","submit","continue","next"]

        # Priority 1: input[type=submit]
        for el in self.driver.find_elements(By.XPATH, "//input[@type='submit']"):
            if el.is_displayed() and el.is_enabled():
                self.driver.execute_script("arguments[0].scrollIntoView(true);", el)
                time.sleep(0.3)
                el.click()
                return True

        # Priority 2: button with submit-like text
        all_buttons = self.driver.find_elements(By.TAG_NAME, "button")
        for btn in all_buttons:
            if btn.is_displayed() and btn.is_enabled():
                txt = (btn.text or btn.get_attribute("value") or "").lower()
                if any(k in txt for k in submit_keywords):
                    self.driver.execute_script("arguments[0].scrollIntoView(true);", btn)
                    time.sleep(0.3)
                    btn.click()
                    return True

        # Priority 3: any visible enabled button
        for btn in all_buttons:
            if btn.is_displayed() and btn.is_enabled():
                self.driver.execute_script("arguments[0].scrollIntoView(true);", btn)
                time.sleep(0.3)
                btn.click()
                return True

        return False


# ─────────────────────────────────────────────────────────────────────────────
# Main Agent
# ─────────────────────────────────────────────────────────────────────────────

class PasswordPolicyCheckerAgent:

    def __init__(self, target):
        self.target  = target.rstrip("/")
        self.base    = self.target.split("#")[0].rstrip("/")
        self.session = requests.Session()

        self.pages             = set()
        self.register_pages    = []
        self.login_pages       = []
        self.password_forms    = []
        self.created_accounts  = []
        self._probe_results    = []

        self.policy = {
            "minimum_length":            None,
            "requires_uppercase":        False,
            "requires_lowercase":        False,
            "requires_number":           False,
            "requires_symbol":           False,
            "password_history_enforced": None,
        }

        self.app_type = self._detect_app_type()
        print(f"[i] App type  : {self.app_type}")

        self.setup_browser()
        self.form = UniversalFormHandler(self.driver)

        print(f"[i] Probing API endpoints for {self.base} ...")
        self.api = AppAPIClient(self.base)
        self.api_available = self.api.discover()
        print(f"[i] API mode  : {'enabled' if self.api_available else 'disabled (Selenium only)'}")

    def _detect_app_type(self):
        t = self.target.lower()
        if "juice" in t or ":3000" in t:       return "juiceshop"
        if "webgoat" in t or ":9090" in t:     return "webgoat"
        if "bwapp" in t or ":8888" in t:       return "bwapp"
        if "mutillidae" in t or ":8181" in t:  return "mutillidae"
        if "dvwa" in t or ":8080" in t:        return "dvwa"
        return "generic"

    def setup_browser(self):
        opts = webdriver.ChromeOptions()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--window-size=1400,900")
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=opts)
        self.driver.set_page_load_timeout(30)

    def _wait(self, s=3): time.sleep(s)

    def crawl(self):
        print("\n[+] Crawling site")
        try:
            r    = self.session.get(self.base, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                self.pages.add(urljoin(self.base, link["href"]))
        except Exception as e:
            print("[-] Crawl warning:", e)

        self.pages.add(self.target)

        route_map = {
            "juiceshop":  ["/#/register",   "/#/login",    "/#/forgot-password"],
            "webgoat":    ["/WebGoat/login", "/WebGoat/registration"],
            "bwapp":      ["/bWAPP/login.php", "/bWAPP/user_new.php"],
            "mutillidae": ["/mutillidae/index.php?page=register.php",
                           "/mutillidae/index.php?page=login.php"],
            "dvwa":       ["/login.php", "/setup.php"],
            "generic":    ["/login", "/register", "/signup"],
        }
        for path in route_map.get(self.app_type, route_map["generic"]):
            self.pages.add(self.base + path)

        print("[+] Pages discovered:", len(self.pages))

    REGISTER_PRIORITY = ["#/register","page=register","user_new",
                         "/registration","register","signup"]
    LOGIN_PRIORITY    = ["#/login","page=login","/bwapp/login",
                         "/webgoat/login","login","signin"]

    def _rank(self, url, priority):
        u = url.lower()
        for i, p in enumerate(priority):
            if p in u: return i
        return 999

    def detect_auth_pages(self):
        reg_c, log_c = [], []
        for pg in self.pages:
            p = pg.lower()
            if any(k in p for k in ("register","signup","user_new",
                                    "page=register","registration")):
                reg_c.append(pg)
            if any(k in p for k in ("login","signin","page=login")):
                log_c.append(pg)

        self.register_pages = sorted(set(reg_c), key=lambda u: self._rank(u, self.REGISTER_PRIORITY))
        self.login_pages    = sorted(set(log_c), key=lambda u: self._rank(u, self.LOGIN_PRIORITY))

        print("\nRegister pages:", self.register_pages)
        print("Login pages:",    self.login_pages)
        print(f"[i] Using register: {self.register_pages[0] if self.register_pages else 'NONE'}")
        print(f"[i] Using login:    {self.login_pages[0]    if self.login_pages    else 'NONE'}")

    def detect_password_forms(self):
        print("\n[+] Detecting password forms")
        for pg in self.pages:
            try:
                self.driver.get(pg)
                self._wait(4)
                if self.driver.find_elements(
                    By.XPATH,
                    "//input[@type='password' or "
                    "contains(@formcontrolname,'password')]"
                ):
                    print("[+] Password form detected:", pg)
                    self.password_forms.append(pg)
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # FIX: _selenium_success() — removed the "no error = success" branch.
    # Now requires POSITIVE evidence of success (URL change OR explicit keyword).
    # ─────────────────────────────────────────────────────────────────────────
    def _selenium_success(self, original_url):
        current = self.driver.current_url.lower()
        source  = self.driver.page_source.lower()

        # Positive signal 1: URL changed away from registration page
        if current != original_url.lower():
            # But NOT if we just got redirected back to the same page with an error
            if not any(k in current for k in ("register","signup","error")):
                return True

        # Positive signal 2: explicit success keywords in page
        if any(k in source for k in [
            "logout", "sign out",
            "account created", "registration successful",
            "successfully registered", "successfully created",
            "welcome back",
        ]):
            return True

        # Positive signal 3: dashboard/profile page indicators
        if any(k in current for k in ["dashboard","profile","account","welcome"]):
            return True

        # Everything else = failure (do NOT default to success)
        return False

    def _get_error(self):
        sels = [
            "mat-snack-bar-container","simple-snack-bar",
            ".cdk-overlay-container","mat-error",
            ".alert-danger",".alert-error",".alert",
            ".error-message",".validation-message",
            "[role='alert']","[class*='error']",
            "[class*='snack']","[class*='toast']",
            "[class*='invalid']",".help-block",".invalid-feedback",
            # Additional selectors for common frameworks
            ".form-error", ".field-error", ".input-error",
            "p.error", "span.error", "div.error",
            "[data-error]", ".ng-invalid ~ .error",
        ]
        msgs = []
        for s in sels:
            try:
                for el in self.driver.find_elements(By.CSS_SELECTOR, s):
                    t = el.text.strip()
                    if t and t not in msgs and len(t) > 2:
                        msgs.append(t)
            except Exception: pass
        return " | ".join(msgs)

    def _gen_account(self, prefix="agent"):
        """FIX: Generate account with clearly printable credentials for manual testing."""
        uid = uuid.uuid4().hex[:10]
        u   = prefix + uid
        pw  = "ValidPass1!"
        return {
            "username": u,
            "email":    u + "@test.com",
            "password": pw,
            "security_answer": "MyAnswer123",
        }

    def _register(self, email, password, answer, page):
        if self.api_available:
            ok, msg = self.api.register(email, password, answer)
            if ok:
                return True, "API"
            # FIX: only treat as definitive rejection if clearly password-related
            if any(k in msg.lower() for k in (
                "password","length","character","weak","policy","invalid password"
            )):
                return False, f"API-rejected: {msg}"
            # For other API errors (network, server), fall through to Selenium
            print(f"    [API] Non-password error: {msg} — trying Selenium")

        try:
            self.driver.get(page)
            self._wait(6)
            original_url = self.driver.current_url

            account = {"username": email.split("@")[0],
                       "email": email,
                       "password": password,
                       "security_answer": answer}

            self.form.fill(password, account)

            # Allow JS validation to settle before submitting
            time.sleep(2)
            self.form.submit()
            time.sleep(5)

            if self._selenium_success(original_url):
                return True, "Selenium"

            err = self._get_error()
            if not err:
                # Take a screenshot hint from page title
                title = self.driver.title
                err = f"No error message captured (page title: {title})"
            return False, f"Selenium-rejected: {err[:150]}"

        except Exception as e:
            return False, f"Selenium-error: {e}"

    def create_account(self, page):
        account = self._gen_account()
        print(f"\n[+] Creating account")
        print(f"    Email   : {account['email']}")
        print(f"    Password: {account['password']}")
        print(f"    Page    : {page}")
        print(f"    API URL : {self.api._register_url if self.api_available else 'N/A'}")
        print(f"    API mode: {self.api._register_method if self.api_available else 'Selenium only'}")

        ok, method = self._register(
            account["email"], account["password"],
            account["security_answer"], page
        )

        if ok:
            print(f"[+] Account created successfully ({method})")
            print(f"\n{'='*55}")
            print(f"  MANUAL LOGIN CREDENTIALS (copy-paste ready)")
            print(f"  Email    : {account['email']}")
            print(f"  Password : {account['password']}")
            print(f"{'='*55}\n")
            self.created_accounts.append(account)
            # FIX: save immediately so credentials are never lost
            self._save_accounts_now()
        else:
            print(f"[-] Account creation FAILED")
            print(f"    Reason  : {method}")
            print(f"    The agent will still attempt probing,")
            print(f"    but results may be unreliable if registration failed.")

    def _save_accounts_now(self):
        """FIX: Save accounts to disk immediately after creation."""
        try:
            with open("created_accounts.json", "w") as f:
                json.dump(self.created_accounts, f, indent=4)
            print(f"    [i] Credentials saved → created_accounts.json")
        except Exception as e:
            print(f"    [!] Could not save accounts: {e}")

    def verify_login(self):
        if not self.created_accounts:
            print("\n[-] No accounts to verify — registration may have failed")
            return
        if not self.login_pages:
            print("\n[-] No login page found")
            return

        acct = self.created_accounts[0]
        page = self.login_pages[0]

        print(f"\n[+] Verifying login")
        print(f"    Email   : {acct['email']}")
        print(f"    Password: {acct['password']}")
        print(f"    Login URL: {self.api._login_url if self.api_available else 'N/A (Selenium)'}")

        if self.api_available and self.api._login_url:
            ok, token, msg = self.api.login(acct["email"], acct["password"])
            if ok:
                tok_preview = (str(token)[:30] + "...") if token else "none"
                print(f"[+] Login verified via API | Token: {tok_preview}")
                return
            print(f"[-] API login failed: {msg}")

        print(f"\n    Trying Selenium login on: {page}")
        try:
            self.driver.get(page)
            self._wait(5)
            orig = self.driver.current_url
            self.form.fill(acct["password"], acct)
            time.sleep(2)
            self.form.submit()
            time.sleep(5)

            after = self.driver.current_url
            print(f"    After submit URL: {after}")

            if self._selenium_success(orig):
                print("[+] Login verification successful (Selenium)")
            else:
                print("[-] Login verification failed (Selenium)")
                err = self._get_error()
                if err:
                    print(f"    Error message: {err[:300]}")
                else:
                    print("    No error message shown — account may not exist.")
                    print(f"    Try logging in manually at: {page}")
                    print(f"    Email: {acct['email']}  Password: {acct['password']}")
        except Exception as e:
            print(f"Login error: {e}")

    def _probe(self, page, password):
        """
        FIX: After each probe, fully reload the page to clear form state.
        This prevents previous probe's data from bleeding into the next.
        """
        if self.api_available:
            outcome, msg = self.api.probe_password(password)
            if outcome is not None:
                if msg and len(msg) > 120: msg = msg[:120] + "..."
                return outcome, msg

        uid     = uuid.uuid4().hex[:10]
        # FIX: use unique domain per probe, not shared @probe.com
        account = {"username":  "probe" + uid,
                   "email":     f"probe{uid}@probedomain{uid[:6]}.net",
                   "password":  password,
                   "security_answer": "ProbAns99"}

        self.driver.get(page)
        self._wait(5)
        orig = self.driver.current_url

        self.form.fill(password, account)
        time.sleep(2)
        try:
            self.driver.switch_to.active_element.send_keys(Keys.TAB)
        except: pass
        self._wait(1)

        inline = self._get_error()
        self.form.submit()
        self._wait(4)

        if self._selenium_success(orig):
            # FIX: reload page cleanly before returning, so next probe starts fresh
            self.driver.get(page)
            self._wait(2)
            return "accepted", ""

        post     = self._get_error()
        combined = (inline + " | " + post).strip(" |")
        boilerplate = ["welcome to owasp", "juice shop is"]
        if any(b in combined.lower() for b in boilerplate):
            combined = "(registration failed — no error message shown)"

        # FIX: reload page after rejection too
        try:
            self.driver.get(page)
            self._wait(2)
        except: pass

        return "rejected", combined

    def detect_password_policy(self, page):
        mode = "API + Selenium fallback" if self.api_available else "Selenium only"
        print(f"\n[+] Detecting password policy ({mode})\n")

        probes = [
            ("a",           "1 char",             "length > 1"),
            ("abcde",       "5 chars",            "length > 5"),
            ("abcdefg",     "7 chars",            "length > 7"),
            ("abcdefgh",    "8 chars lowercase",  "length > 8 or complexity"),
            ("abcdefgh12",  "8c lower+num",       "uppercase or symbol"),
            ("ABCDEFGH12",  "8c upper+num",       "lowercase or symbol"),
            ("abcdEFGH12",  "8c mixed+num",       "symbol required"),
            ("abcdEFGH!@",  "8c mixed+sym",       "number required"),
            ("abcdEFGH1!",  "9c full complexity", "should accept"),
            ("password",    "common word",        "dictionary check"),
            ("password1",   "common+number",      "dictionary check"),
            ("Password1",   "common capitalised", "dictionary check"),
        ]

        accepted, rejected = [], []

        for pwd, label, hint in probes:
            outcome, msg = self._probe(page, pwd)
            short  = (msg[:100]+"...") if len(msg)>100 else (msg or "(no message)")
            status = "ACCEPTED" if outcome == "accepted" else "REJECTED"
            print(f"  [{status:8}] {label:26} | {short}")
            self._probe_results.append({
                "password": pwd, "label": label,
                "outcome":  outcome, "message": msg,
            })
            if outcome == "accepted": accepted.append(pwd)
            else:                     rejected.append((pwd, msg))

        self._infer_policy(accepted, rejected)

    def _infer_policy(self, accepted, rejected_pairs):
        rej_pwds = [p for p, _ in rejected_pairs]
        rej_msgs = " ".join(m for _, m in rejected_pairs).lower()

        if accepted:
            self.policy["minimum_length"] = min(len(p) for p in accepted)
        elif rejected_pairs:
            self.policy["minimum_length"] = \
                f">={max(len(p) for p,_ in rejected_pairs)}"

        nums = re.findall(r'\b(\d{1,2})\s*(?:characters?|chars?|digits?)',
                          rej_msgs)
        if nums:
            self.policy["minimum_length"] = max(int(n) for n in nums)

        def _chk(reject_pwd, compare_accepted, key, keywords):
            if reject_pwd in rej_pwds:
                if any(p in accepted for p in compare_accepted):
                    self.policy[key] = True
            if any(k in rej_msgs for k in keywords):
                self.policy[key] = True

        _chk("abcdefgh12", ["ABCDEFGH12","abcdEFGH12","abcdEFGH1!"],
             "requires_uppercase", ["uppercase","capital","upper"])
        _chk("ABCDEFGH12", ["abcdefgh12","abcdEFGH12","abcdEFGH1!"],
             "requires_lowercase", ["lowercase","lower case","lower-case"])
        _chk("abcdEFGH!@", ["abcdEFGH1!","abcdefgh12"],
             "requires_number",    ["digit","number","numeric"])
        _chk("abcdEFGH12", ["abcdEFGH1!","abcdEFGH!@"],
             "requires_symbol",    ["special","symbol","non-alphanumeric"])

    def save_accounts(self):
        with open("created_accounts.json", "w") as f:
            json.dump(self.created_accounts, f, indent=4)
        print("\n[+] Accounts saved → created_accounts.json")

    def generate_report(self):
        score, label, tag, findings = score_policy(self.policy)
        report = {
            "target":                  self.target,
            "app_type":                self.app_type,
            "api_mode":                self.api_available,
            "pages_discovered":        list(self.pages),
            "register_pages":          self.register_pages,
            "login_pages":             self.login_pages,
            "password_forms_detected": self.password_forms,
            "accounts_created":        self.created_accounts,
            "password_policy":         self.policy,
            "probe_log":               self._probe_results,
            "severity": {"score": score, "label": label, "findings": findings},
        }
        output_path = getattr(self, "_report_output_path", "password_policy_report.json")
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)

        sep = "=" * 60
        print(f"\n{sep}")
        print(f"  PASSWORD POLICY REPORT")
        print(f"  Target   : {self.target}")
        print(f"  App type : {self.app_type}")
        print(f"  API mode : {'enabled' if self.api_available else 'disabled'}")
        print(sep)
        print(f"\n  SEVERITY : {label}  (score {score}/100)\n")
        print("  POLICY SETTINGS:")
        for k, v in self.policy.items():
            icon = "✔" if v and v is not False else "✘"
            val  = str(v) if v is not None else "None (not enforced)"
            print(f"    {icon}  {k:<42} {val}")
        print("\n  FINDINGS:")
        for f in findings:
            print(f"    • {f}")
        print(f"\n{sep}")
        print("  Full report → password_policy_report.json")
        print(f"  Accounts   → created_accounts.json")
        print(sep + "\n")

        # FIX: always print credentials at the end for easy manual testing
        if self.created_accounts:
            acct = self.created_accounts[0]
            print(f"\n{'='*55}")
            print(f"  MANUAL LOGIN CREDENTIALS")
            print(f"  Email    : {acct['email']}")
            print(f"  Password : {acct['password']}")
            if self.login_pages:
                print(f"  Login at : {self.login_pages[0]}")
            print(f"{'='*55}\n")

    def teardown(self):
        try:    self.driver.quit()
        except: pass

    def run(self):
        try:
            self.crawl()
            self.detect_auth_pages()
            self.detect_password_forms()

            if not self.register_pages and not self.api_available:
                print("\n[-] No register page and no API — cannot probe")
                return

            page = self.register_pages[0] if self.register_pages else self.target

            self.create_account(page)
            self.verify_login()
            self.detect_password_policy(page)
            self.save_accounts()
            self.generate_report()
        finally:
            self.teardown()


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Agent 22 - Password Policy Checker"
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Target base URL. If omitted, falls back to an interactive prompt.",
    )
    parser.add_argument(
        "--output",
        default="password_policy_report.json",
        help="Where to write the JSON report (default: password_policy_report.json).",
    )
    args = parser.parse_args()

    target = args.url or input("Enter target URL: ").strip()

    agent = PasswordPolicyCheckerAgent(target)
    agent._report_output_path = args.output
    agent.run()