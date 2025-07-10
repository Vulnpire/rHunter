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

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.setExtensionName("Open Redirect Hunter")

        self.last_request_time = 0
        self.lock = threading.Lock()
        self.max_threads = 5
        self.active_threads = []
        self.scanned_requests = set()

        self.payloads = self.load_setting("payloads", [
            "//evil.com", "///evil.com", "https://evil.com", "http://evil.com",
            "\\\\evil.com\\@good.com", "/\\evil.com/%2f..", "/\\evil.com/%2e%2e",
            "https://evil.com#@target", "https://evil.com%2f%2e%2e"
        ])
        self.keywords = self.load_setting("keywords", ["url", "redirect", "next", "target"])
        self.delay = float(self._callbacks.loadExtensionSetting("delay") or "2.0")
        self.extension_enabled = (self._callbacks.loadExtensionSetting("enabled") != "false")
        self.scan_post_enabled = (self._callbacks.loadExtensionSetting("scan_post") == "true")

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

        menu_item = JMenuItem("Scan this request", actionPerformed=lambda e: self.manual_scan(request_responses[0]))
        submenu = JMenuItem("Extensions > Open Redirect Hunter > Scan this request")
        submenu.add(menu_item)
        menu.add(menu_item)
        return menu

    def manual_scan(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            method = request_info.getMethod()
            param_source = "query" if method == "GET" else "body"
            self.start_scan_thread(url, messageInfo, param_source)
            self.update_status("Manual scan started.")
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
            self.delay = float(self.rate_field.getText().strip())
            self.extension_enabled = self.toggle_checkbox.isSelected()
            self.scan_post_enabled = self.scan_post_checkbox.isSelected()

            self._callbacks.saveExtensionSetting("payloads", "\n".join(self.payloads))
            self._callbacks.saveExtensionSetting("keywords", ",".join(self.keywords))
            self._callbacks.saveExtensionSetting("delay", str(self.delay))
            self._callbacks.saveExtensionSetting("enabled", "true" if self.extension_enabled else "false")
            self._callbacks.saveExtensionSetting("scan_post", "true" if self.scan_post_enabled else "false")

            self.update_status("Settings saved and persisted.")
        except Exception as e:
            self._stderr.println("[!] Error updating settings: %s" % str(e))
            self.update_status("Error saving settings.")

    def toggle_extension(self, event):
        self.extension_enabled = self.toggle_checkbox.isSelected()
        self._callbacks.saveExtensionSetting("enabled", "true" if self.extension_enabled else "false")
        status = "enabled" if self.extension_enabled else "disabled"
        self.update_status("Extension is now %s." % status)

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

        main_panel.add(general_panel)

        # === Payloads Section (Collapsible) ===
        payload_toggle_panel = JPanel(BorderLayout())
        payload_toggle_panel.setBorder(TitledBorder("Payloads (click to expand/collapse)"))

        # Toggle button to show/hide payload area
        self.payload_toggle = JToggleButton("Show Payloads")
        payload_toggle_panel.add(self.payload_toggle, BorderLayout.NORTH)

        # Payload text area (initially hidden)
        self.payload_area = JTextArea("\n".join(self.payloads), 8, 50)
        self.payload_area.setLineWrap(True)
        self.payload_area.setWrapStyleWord(True)
        scroll_payload = JScrollPane(self.payload_area)
        scroll_payload.setPreferredSize(Dimension(500, 120))
        scroll_payload.setVisible(False)  # Start collapsed

        payload_toggle_panel.add(scroll_payload, BorderLayout.CENTER)

        # Toggle behavior
        def toggle_payload_visibility(event):
            visible = self.payload_toggle.isSelected()
            scroll_payload.setVisible(visible)
            self.payload_toggle.setText("Hide Payloads" if visible else "Show Payloads")
            payload_toggle_panel.revalidate()
            payload_toggle_panel.repaint()

        self.payload_toggle.addActionListener(toggle_payload_visibility)

        # Add to main panel
        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(payload_toggle_panel)

        # === Keywords and Rate Limit ===
        keyword_panel = JPanel(GridLayout(0, 2, 5, 5))
        keyword_panel.setBorder(TitledBorder("Filtering and Timing"))

        keyword_panel.add(JLabel("Keywords to watch (comma-separated):"))
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
        self.status_label.setForeground(Color(180, 200, 220))

        self.panel.add(main_panel, BorderLayout.CENTER)
        self.panel.add(self.status_label, BorderLayout.SOUTH)

        
    def getTabCaption(self):
        return "Open Redirect Hunter"

    def getUiComponent(self):
        return self.panel

    def update_status(self, message):
        self.status_label.setText("Status: " + message)
        self._stdout.println("[*] " + message)

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
                if any(word in key.lower() for word in self.keywords):
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

            if param_source == "query":
                query = base_url.getQuery()
            else:
                request_bytes = messageInfo.getRequest()
                body_offset = parsed.getBodyOffset()
                body = request_bytes[body_offset:]
                query = body.decode('utf-8', errors='ignore')

            self.update_status("Scanning: %s" % base_url)

            # Extract parameters
            params = {}
            if query:
                for param in query.split('&'):
                    key, sep, val = param.partition('=')
                    if key:
                        params[key] = val

            # If no params and "Scan all" is enabled, fuzz the root URL
            if not params and self.scan_all_checkbox.isSelected():
                for payload in self.payloads:
                    new_url_str = base_url.getProtocol() + "://" + base_url.getHost() + base_url.getPath()
                    if not new_url_str.endswith("/"):
                        new_url_str += "/"
                    new_url_str += quote(payload)

                    new_request = self._helpers.buildHttpRequest(URL(new_url_str))
                    http_service = messageInfo.getHttpService()
                    response = self._callbacks.makeHttpRequest(http_service, new_request)
                    analyzed_resp = self._helpers.analyzeResponse(response.getResponse())

                    for header in analyzed_resp.getHeaders():
                        if header.lower().startswith("location:"):
                            location = header.split(":", 1)[1].strip()
                            if any(p in location for p in self.payloads):
                                self.report_redirect(http_service, new_url_str, response, payload)
                                self.update_status("Open Redirect found at root! Stopping scanning early.")
                                return  # exit early

            # Scan parameters
            for key in params:
                if not self.scan_all_checkbox.isSelected():
                    if not any(word in key.lower() for word in self.keywords):
                        continue

                attempt = 0
                for payload in self.payloads:
                    new_params = params.copy()
                    new_params[key] = quote(payload)
                    new_query = "&".join("%s=%s" % (k, v) for k, v in new_params.items())
                    url_base = orig_url.split('?')[0]
                    new_url_str = url_base + "?" + new_query if param_source == "query" else url_base

                    if param_source == "body":
                        # Rebuild POST request
                        request = self._helpers.buildHttpMessage(headers, new_query)
                    else:
                        # Rebuild GET request
                        request = self._helpers.buildHttpRequest(URL(new_url_str))

                    http_service = messageInfo.getHttpService()
                    response = self._callbacks.makeHttpRequest(http_service, request)
                    analyzed_resp = self._helpers.analyzeResponse(response.getResponse())

                    location_header = None
                    for header in analyzed_resp.getHeaders():
                        if header.lower().startswith("location:"):
                            location_header = header.split(":", 1)[1].strip()
                            break

                    if location_header and any(p in location_header for p in self.payloads):
                        self.report_redirect(http_service, new_url_str, response, payload)
                        self.update_status("Open Redirect found! Stopping scanning early.")
                        return  # exit early after detection

                    attempt += 1
                    if attempt >= 3:
                        break

            self.update_status("Finished scan: no open redirect found.")

        except Exception as e:
            self._stderr.println("[!] Scan error: %s" % str(e))
            self.update_status("Error during scan.")


    def report_redirect(self, http_service, url_str, response_info, payload):
        issue = CustomScanIssue(
            http_service,
            URL(url_str),
            [response_info],
            "Open Redirect",
            "The application redirects to: <b>{}</b>".format(payload),
            "Medium"
        )
        self._callbacks.addScanIssue(issue)
        self._stdout.println("[+] Open Redirect found: %s -> %s" % (url_str, payload))

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
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
