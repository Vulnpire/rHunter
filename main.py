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
from urllib import quote
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
        self._callbacks.setExtensionName("Open Redirect Hunter Pro")

        self.last_request_time = 0
        self.lock = threading.Lock()
        self.max_threads = 5
        self.active_threads = []
        self.scanned_requests = set()
        
        # Initialize whitelisted domains (domains we trust for redirects)
        self.whitelisted_domains = self.load_setting("whitelisted_domains", [])
        
        # Enhanced payloads with markers
        self.payloads = self.load_setting("payloads", [
            "https://evil.com",
            "http://evil.com", 
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "\\\evil.com",
            "\\\\evil.com",
            "/\\evil.com",
            "https://evil.com%2f",
            "https://evil.com%2f%2e%2e",
            "https://evil.com#@target",
            "https://evil.com?@target",
            "https://evil.com@target",
            "https://target@evil.com",
            "https://evil.com%00",
            "https://evil.com%0d%0a",
            "//evil.com/%2f..",
            "//evil.com/%2e%2e",
            "https:evil.com",
            "http:evil.com",
            "evil.com",
            "@evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ])
        
        self.keywords = self.load_setting("keywords", ["url", "redirect", "next", "target", "return", "dest", "goto", "link"])
        self.delay = float(self._callbacks.loadExtensionSetting("delay") or "2.0")
        self.extension_enabled = (self._callbacks.loadExtensionSetting("enabled") != "false")
        self.scan_post_enabled = (self._callbacks.loadExtensionSetting("scan_post") == "true")
        self.strict_mode = (self._callbacks.loadExtensionSetting("strict_mode") != "false")

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

        menu_item = JMenuItem("Scan with Open Redirect Hunter Pro", 
                            actionPerformed=lambda e: self.manual_scan(request_responses[0]))
        menu.add(menu_item)
        return menu

    def manual_scan(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            method = request_info.getMethod()
            param_source = "query" if method == "GET" else "body"
            self.start_scan_thread(url, messageInfo, param_source)
            self.update_status("Manual scan started for: %s" % url.getPath())
        except Exception as e:
            self._stderr.println("[!] Error in manual scan: %s" % str(e))
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

            self._callbacks.saveExtensionSetting("payloads", "\n".join(self.payloads))
            self._callbacks.saveExtensionSetting("keywords", ",".join(self.keywords))
            self._callbacks.saveExtensionSetting("whitelisted_domains", "\n".join(self.whitelisted_domains))
            self._callbacks.saveExtensionSetting("delay", str(self.delay))
            self._callbacks.saveExtensionSetting("enabled", "true" if self.extension_enabled else "false")
            self._callbacks.saveExtensionSetting("scan_post", "true" if self.scan_post_enabled else "false")
            self._callbacks.saveExtensionSetting("strict_mode", "true" if self.strict_mode else "false")

            self.update_status("Settings saved successfully.")
        except Exception as e:
            self._stderr.println("[!] Error updating settings: %s" % str(e))
            self.update_status("Error saving settings.")

    def init_gui(self):
        self.panel = JPanel(BorderLayout(10, 10))
        self.panel.setBorder(EmptyBorder(10, 10, 10, 10))

        ## --- Settings Panel ---
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))

        # === General Options ===
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

        main_panel.add(general_panel)

        # === Payloads Section ===
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
        
        # === Whitelist Section ===
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

        # === Keywords and Rate Limit ===
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

        # === Save Button ===
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.save_button = JButton("Save Settings", actionPerformed=self.save_settings)
        button_panel.add(self.save_button)
        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(button_panel)

        # === Status Label ===
        self.status_label = JLabel("Status: Ready", SwingConstants.LEFT)
        self.status_label.setBorder(EmptyBorder(5, 5, 5, 5))
        self.status_label.setFont(self.status_label.getFont().deriveFont(Font.BOLD))

        self.panel.add(main_panel, BorderLayout.CENTER)
        self.panel.add(self.status_label, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "Open Redirect Hunter Pro"

    def getUiComponent(self):
        return self.panel

    def update_status(self, message):
        self.status_label.setText("Status: " + message)
        self._stdout.println("[*] " + message)

    def is_valid_open_redirect(self, location_header, payload, original_host):
        """
        Enhanced validation to reduce false positives.
        Returns (is_vulnerable, confidence, reason)
        """
        if not location_header:
            return False, None, None
            
        location_lower = location_header.lower()
        payload_lower = payload.lower()
        
        # Extract the malicious domain from our payload
        evil_domain = None
        if "evil.com" in payload_lower:
            evil_domain = "evil.com"
        elif "javascript:" in payload_lower:
            evil_domain = "javascript"
        elif "data:" in payload_lower:
            evil_domain = "data"
            
        if not evil_domain:
            return False, None, None
            
        # Parse the location header
        try:
            parsed = urlparse(location_header)
            
            # Check if it's a javascript or data URI
            if parsed.scheme in ['javascript', 'data']:
                return True, "High", "XSS via %s URI scheme" % parsed.scheme
                
            # Get the redirect domain
            redirect_host = parsed.hostname if parsed.hostname else ""
            
            # Direct redirect to evil domain
            if redirect_host and evil_domain in redirect_host.lower():
                # Check if it's actually redirecting to evil.com or just contains it as parameter
                if redirect_host.lower() == evil_domain or redirect_host.lower().endswith('.' + evil_domain):
                    return True, "High", "Direct redirect to malicious domain: %s" % redirect_host
                    
            # Protocol-relative redirect
            if location_header.startswith("//") and evil_domain in location_header:
                parts = location_header[2:].split('/', 1)
                if parts and evil_domain in parts[0].lower():
                    return True, "High", "Protocol-relative redirect to: %s" % parts[0]
                    
            # Check for bypass techniques
            if location_header.startswith("///") or location_header.startswith("\\\\"):
                if evil_domain in location_header:
                    return True, "Medium", "Multiple slash bypass technique"
                    
            # Check if the payload appears at the beginning (potential open redirect)
            if location_header.startswith(payload) or location_header.startswith("//" + evil_domain):
                return True, "High", "Location starts with malicious payload"
                
            # Check for @ bypass technique  
            if "@" in location_header and evil_domain in location_header:
                # Check if evil domain comes after @ (which would make it the real destination)
                at_index = location_header.find("@")
                evil_index = location_header.find(evil_domain)
                if evil_index > at_index:
                    return True, "High", "@ bypass technique detected"
                    
            # In strict mode, require the evil domain to be the primary destination
            if self.strict_mode:
                # If evil.com only appears as a parameter value, it's likely false positive
                if "?" in location_header or "&" in location_header:
                    # Parse query parameters
                    if "?" in location_header:
                        query_part = location_header.split("?", 1)[1]
                        if evil_domain in query_part and redirect_host != evil_domain:
                            # Evil domain is just in parameters, not the main destination
                            return False, None, None
                            
        except Exception as e:
            self._stderr.println("[!] Error parsing location: %s" % str(e))
            
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

    def start_scan_thread(self, url, messageInfo, param_source):
        with self.lock:
            if len(self.active_threads) >= self.max_threads:
                return

            def runner():
                try:
                    self.scan_with_rate_limit(url, messageInfo, param_source)
                except Exception as e:
                    self._stderr.println("[!] Thread error: %s" % str(e))
                finally:
                    with self.lock:
                        self.active_threads.remove(thread)

            thread = threading.Thread(target=runner)
            self.active_threads.append(thread)
            thread.start()

    def scan_with_rate_limit(self, url, messageInfo, param_source):
        with self.lock:
            now = time.time()
            wait = self.delay - (now - self.last_request_time)
            if wait > 0:
                time.sleep(wait)
            self.last_request_time = time.time()
            self.scan_for_redirects(url, messageInfo, param_source)

    def scan_for_redirects(self, base_url, messageInfo, param_source):
        try:
            parsed = self._helpers.analyzeRequest(messageInfo)
            headers = list(parsed.getHeaders())
            orig_url = base_url.toString()
            original_host = base_url.getHost()

            if param_source == "query":
                query = base_url.getQuery()
            else:
                request_bytes = messageInfo.getRequest()
                body_offset = parsed.getBodyOffset()
                body = request_bytes[body_offset:]
                query = body.decode('utf-8', errors='ignore')

            self.update_status("Scanning: %s" % base_url.getPath())

            # Extract parameters
            params = {}
            if query:
                for param in query.split('&'):
                    key, sep, val = param.partition('=')
                    if key:
                        params[key] = val

            # Track findings
            vulnerabilities_found = []

            # Scan parameters
            for key in params:
                if not self.scan_all_checkbox.isSelected():
                    if not any(word in key.lower() for word in self.keywords):
                        continue

                self._stdout.println("[*] Testing parameter: %s" % key)
                
                for payload in self.payloads:
                    new_params = params.copy()
                    new_params[key] = quote(payload)
                    new_query = "&".join("%s=%s" % (k, v) for k, v in new_params.items())
                    url_base = orig_url.split('?')[0]
                    new_url_str = url_base + "?" + new_query if param_source == "query" else url_base

                    if param_source == "body":
                        request = self._helpers.buildHttpMessage(headers, new_query)
                    else:
                        request = self._helpers.buildHttpRequest(URL(new_url_str))

                    http_service = messageInfo.getHttpService()
                    response = self._callbacks.makeHttpRequest(http_service, request)
                    analyzed_resp = self._helpers.analyzeResponse(response.getResponse())

                    # Check for Location header
                    location_header = None
                    for header in analyzed_resp.getHeaders():
                        if header.lower().startswith("location:"):
                            location_header = header.split(":", 1)[1].strip()
                            break

                    if location_header:
                        # Enhanced validation
                        is_vuln, confidence, reason = self.is_valid_open_redirect(
                            location_header, payload, original_host
                        )
                        
                        if is_vuln:
                            # Check if redirect domain is whitelisted
                            is_whitelisted = False
                            for domain in self.whitelisted_domains:
                                if domain and domain in location_header.lower():
                                    is_whitelisted = True
                                    self._stdout.println("[-] Skipping whitelisted domain: %s" % domain)
                                    break
                                    
                            if not is_whitelisted:
                                vulnerabilities_found.append({
                                    'param': key,
                                    'payload': payload,
                                    'location': location_header,
                                    'confidence': confidence,
                                    'reason': reason,
                                    'url': new_url_str,
                                    'response': response
                                })
                                
                                self._stdout.println("[+] VALID Open Redirect found!")
                                self._stdout.println("    Parameter: %s" % key)
                                self._stdout.println("    Payload: %s" % payload)
                                self._stdout.println("    Redirects to: %s" % location_header)
                                self._stdout.println("    Confidence: %s" % confidence)
                                self._stdout.println("    Reason: %s" % reason)
                                
                                # Report the issue
                                self.report_redirect(http_service, new_url_str, response, 
                                                  payload, location_header, confidence, reason)
                                
                                # Stop testing this parameter after first valid finding
                                break
                        else:
                            # Log false positive that was filtered
                            if "evil.com" in location_header.lower():
                                self._stdout.println("[-] Filtered potential false positive:")
                                self._stdout.println("    Location: %s" % location_header)
                                self._stdout.println("    Reason: evil.com appears only as parameter value")

            if vulnerabilities_found:
                self.update_status("Found %d open redirect(s)!" % len(vulnerabilities_found))
            else:
                self.update_status("Scan complete: no open redirects found.")

        except Exception as e:
            self._stderr.println("[!] Scan error: %s" % str(e))
            self.update_status("Error during scan.")

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
