# Infostealer exposure response (advice for the user)

Stealers (RedLine/Lumma/Vidar/StealC-style) take saved passwords, cookies, autofill, crypto wallets,
Discord/Telegram sessions, and files, usually in seconds, then exit. Removing the malware does **not**
undo the theft.

1. **Contain first**, isolate, then remove the malware (incident-response, opt-in).
2. **From a different, clean device**: change passwords for email first, then banking, then everything saved in the browser.
3. **Kill sessions**, "sign out of all devices" for Google/Microsoft/Facebook/Discord/Steam/GitHub etc.
   (stolen cookies bypass passwords and MFA).
4. **Rotate MFA** secrets if authenticator seeds or backup codes were stored on the PC.
5. **Crypto wallets**, move funds to a new wallet created on a clean device.
6. **Developer secrets**, rotate API keys/tokens found in `.env`, `.git-credentials`, cloud CLI configs.
7. Watch for account recovery emails / new-device alerts for weeks.
