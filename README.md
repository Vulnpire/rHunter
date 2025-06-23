# Open Redirect Hunter - Burp Suite Extension

Open Redirect Hunter is a Burp Suite extension designed to automatically detect open redirect vulnerabilities in web applications. It scans HTTP requests for redirect parameters and tests them with custom payloads to identify insecure redirects that can lead to phishing or other attacks.

---

## Features

- Scans **GET** requests by default.
- Optional scanning of **POST** requests with configurable toggle.
- Customizable payloads to test redirect parameters.
- Customizable keywords to identify parameters of interest.
- Rate limiting to control scan speed and avoid detection.
- Multi-threaded scanning with configurable concurrency.
- Clear status updates in the Burp Suite UI.
- Adds custom scan issues directly in Burp's Scanner tab upon detection.
- Saves and loads extension settings persistently.

---

## Installation

1. Download the `.py` file for the extension.
2. Open Burp Suite, go to the **Extender** tab.
3. Select **Extensions** and click **Add**.
4. Choose **Extension Type**: Python.
5. Load the `.py` script.
6. The **Open Redirect Hunter** tab will appear in Burp's UI.

---

## Usage

1. Navigate to the **Open Redirect Hunter** tab.
2. Configure:
    - Payloads: one per line (default payloads included).
    - Keywords: comma-separated list of parameter names to target (default: `url, redirect, next, target`).
    - Rate limit: delay in seconds between scans.
    - Enable or disable scanning POST requests via checkbox.
    - Enable or disable the extension.
3. Click **Save Settings** to persist your preferences.
4. The extension will automatically scan HTTP requests as you browse or proxy traffic through Burp Suite.
5. Found open redirects will be reported as custom scan issues.

---

## Configuration Options

| Option                | Description                                   | Default Value                      |
| --------------------- | --------------------------------------------- | --------------------------------- |
| Payloads              | List of payloads used to test redirects      | `//evil.com`, `https://evil.com`  |
| Keywords              | Parameter keywords to target                  | `url, redirect, next, target`     |
| Rate Limit            | Delay (seconds) between individual scans     | `2.0` seconds                     |
| Scan POST Requests    | Enable scanning of POST request parameters   | Disabled (unchecked by default)   |
| Enable Extension      | Enable or disable scanning                    | Enabled                          |

---

## Notes

- The extension respects Burp's scope settings and only scans requests within scope.
- Scanning POST requests can increase scan time and resource usage.
- Maximum 3 payloads tested per request parameter to limit traffic and speed.

---

## Contributing

Contributions, suggestions, and improvements are welcome!
Feel free to submit issues or pull requests.

---

## License

This project is licensed under the MIT License.

---

## Author

v1xtron
[GitHub Profile](https://github.com/Vulnpire)  
Contact: ones.and.zeroes.1@pm.me

---

## Disclaimer

Use this extension responsibly and only on applications for which you have permission to test.

