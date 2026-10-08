# PhishGuard Browser Protection

This Chrome/Edge Manifest V3 extension checks the current page URL against a running PhishGuard API.

## Local setup

1. Start PhishGuard on `http://127.0.0.1:8080`.
2. Open Chrome/Edge extensions.
3. Enable Developer mode.
4. Choose **Load unpacked**.
5. Select this `browser-extension` folder.
6. Open a normal website in a new tab.

The extension blocks interaction with a high-risk page using a warning overlay and provides **Go Back** and **Continue Anyway**.

The extension is a demonstration/prototype. It does not claim to provide browser-level protection against every threat.

## Deployed use

Update the API endpoint in `content.js` from the local address to the deployed PhishGuard API URL before publishing the extension.
