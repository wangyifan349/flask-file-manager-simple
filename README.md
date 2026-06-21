# 🍊 Flask File Manager Simple

A lightweight, single-file, self-hosted Flask file manager with localized builds.

**Flask File Manager Simple** is designed for personal LAN usage, small home servers, private VPS deployments, and simple self-hosted workflows. It works like a tiny personal **Nextcloud-style** file browser: upload, browse, download, preview, edit text files, stream media, and share files or folders through public read-only share links.

The default root version is now **English**. Additional pure-language builds are provided in the `localized/` directory.

---

## 🌍 Localized Builds

Each localized build is a complete single-file application with embedded HTML, CSS, and JavaScript.

```text
localized/
├── en/
├── ja/
├── ko/
├── es/
├── de/
└── fr/
```

| Folder | Language |
| --- | --- |
| `localized/en/` | English |
| `localized/ja/` | Japanese |
| `localized/ko/` | Korean |
| `localized/es/` | Spanish |
| `localized/de/` | German |
| `localized/fr/` | French |

You can run any language version directly:

```bash
cd localized/en
pip install -r requirements.txt
python flask_file_manager.py
```

Replace `en` with `ja`, `ko`, `es`, `de`, or `fr` as needed.

---

## ✨ Features

### 📁 File Management

- Hierarchical folder browsing
- Single-click folder navigation
- Single-click file download
- Upload files
- Create folders from the right-click context menu
- Rename files and folders
- Move files and folders
- Delete files and folders
- Multi-select with `Ctrl`, `Cmd`, or `Shift`
- Drag selection in the file grid
- Right-click context menu for advanced actions

### 🔐 Authentication

- HTTP Basic Authentication powered by `Flask-HTTPAuth`
- One private owner account
- No registration system
- No public access to private file APIs
- Username and password configurable through environment variables

### 🔗 Sharing

- Share individual files
- Share folders
- Public share links do not require login
- Shared folders can be browsed online
- Shared files can be downloaded
- Shared text files can be viewed online
- Shared audio and video files can be streamed online
- Share links are stored in `shares.json`
- Share links can be revoked from the share list

### 🎬 Media Streaming

- Online video playback for registered video extensions
- Online audio playback for registered audio extensions
- HTTP Range request support for seeking in media files
- Media playback is available both in the private file manager and public share pages

### 📝 Text Viewing and Editing

- Online text editing for registered text extensions
- Encoding detection with `charset-normalizer`
- Save text files using the detected encoding
- Full-screen modal editor
- Public shared text files are view-only

### 🗜️ 7z Archive Download

- Download folders as `.7z` archives
- Download multiple selected files and folders as one `.7z` archive
- Uses `py7zr`
- Uses high-compression LZMA2 settings
- Temporary archives are stored in `cache/`
- Old archive cache files are cleaned automatically

---

## 🚀 Quick Start

Copy and run:

```bash
git clone https://github.com/wangyifan349/flask-file-manager-simple
cd flask-file-manager-simple
pip install -r requirements.txt
python flask_file_manager.py
```

Open:

```text
http://127.0.0.1:5000
```

For LAN access:

```text
http://YOUR_LAN_IP:5000
```

---

## 🔑 Default Login

```text
Username: admin
Password: admin123
```

You should change these values before real use.

---

## ⚙️ Configuration

### Linux / macOS

```bash
export FM_USERNAME="your_username"
export FM_PASSWORD="your_strong_password"
export FM_MAX_UPLOAD_BYTES="1073741824"
python flask_file_manager.py
```

### Windows PowerShell

```powershell
$env:FM_USERNAME="your_username"
$env:FM_PASSWORD="your_strong_password"
$env:FM_MAX_UPLOAD_BYTES="1073741824"
python flask_file_manager.py
```

---

## 🔒 Security Notes

This project is intended for trusted personal or LAN environments.

HTTP Basic Authentication does not encrypt credentials by itself. If you expose this service outside a trusted network, place it behind HTTPS using a reverse proxy such as Caddy, Nginx, or Traefik.

Share links are bearer links. Anyone with a valid share link can access the shared file or folder until the share is revoked.

---

## 📜 License

This project is licensed under the **GNU Affero General Public License v3.0 only**.

License identifier:

```text
AGPL-3.0-ONLY
```

You must comply with the terms of the GNU Affero General Public License v3.0 only when you use, modify, distribute, deploy, or provide this software over a network.

If you modify this project and make it available to users over a network, you must provide the corresponding source code of your modified version under the same license terms.

See the `LICENSE` file for details.

---

## 🙏 Acknowledgements

Thanks to the open-source libraries and contributors that support this project, including:

- Flask
- Flask-HTTPAuth
- charset-normalizer
- py7zr
- Bootstrap

This project would not be possible without the Python, Flask, and broader open-source communities.


## ☕ Buy Me a Coffee

If this project helps you, please consider buying me a coffee. ☕

I built this project with care, patience, and many late nights. Open-source software may look simple from the outside, but every feature, bug fix, and improvement takes real time and effort. ❤️

Your support is never required, but it would be deeply appreciated. Thank you for your kindness and support. 🙏

### ₿ Bitcoin (BTC)

```text
bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p
```

### ⟠ Ethereum (ETH)

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

### 💵 USDT (ERC-20)

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

### ◎ Solana (SOL)

```text
B7N4e3KG9zWQBwMrtydS1B9wVBp2w62fAdryZdxAMBiz
```
