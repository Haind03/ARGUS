# Browser artefacts

| Browser | Profile root | History / downloads | Extensions | Credentials (do not read) |
|---|---|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>` | `History` (urls, visits, downloads) | `Extensions\`, `Secure Preferences` | `Login Data`, `Cookies` (Network\), `Local State` key |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>` | same schema | same | same |
| Brave / Vivaldi | `%LOCALAPPDATA%\BraveSoftware\...`, `%LOCALAPPDATA%\Vivaldi\...` | same | same | same |
| Opera | `%APPDATA%\Opera Software\Opera Stable` | same | same | same |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\<x>` | `places.sqlite` (moz_places, moz_historyvisits, moz_annos downloads) | `extensions.json` | `logins.json`, `key4.db`, `cookies.sqlite` |

Timestamps: Chromium = microseconds since 1601-01-01 UTC; Firefox = microseconds since Unix epoch.
ARGUS never opens credential stores, reading them is exactly what stealers do (ARG-CA-003 would flag it).
