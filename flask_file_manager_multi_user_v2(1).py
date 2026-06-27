"""
Flask File Manager Simple - Multi-User Release V2.

A single-file LAN file manager for Flask. This file contains the backend API,
embedded HTML, CSS, and JavaScript required to browse, upload, create folders,
rename, delete, move, share, archive, preview media, and edit supported text files.

Release V2 keeps the original file-manager UI behavior while adding multi-user support:
- Session-based login and logout pages.
- User registration page backed by SQLite.
- Per-user isolated storage directories under ./storage/<username>.
- Per-user share ownership and per-user archive cache isolation.
- Original browsing, upload, rename, move, share, archive, media preview, and editor behavior retained.

Run:
    python flask_file_manager.py

Default seeded account:
    username: admin
    password: admin123

Environment variables:
    FM_USERNAME             Default seeded username.
    FM_PASSWORD             Default seeded password.
    FM_SECRET_KEY           Flask session secret. Set this in production.
    FM_ALLOW_REGISTRATION   1/true/yes to enable registration; 0/false/no to disable.
    FM_MAX_UPLOAD_BYTES     Maximum upload size in bytes.
"""

from __future__ import annotations

import json
import mimetypes
import re
import sqlite3
import uuid
import os
import secrets
import shutil
import time
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional

from charset_normalizer import from_bytes
import py7zr
from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent  # Application directory.
STORAGE_ROOT = (BASE_DIR / "storage").resolve()  # Root containing isolated per-user storage folders.
SHARES_FILE = BASE_DIR / "shares.json"  # Persistent share metadata.
CACHE_ROOT = (BASE_DIR / "cache").resolve()  # Root containing isolated per-user archive caches.
USERS_DB = BASE_DIR / "users.sqlite3"  # Persistent user database.

DEFAULT_USERNAME = os.environ.get("FM_USERNAME", "admin")  # Default seeded username.
DEFAULT_PASSWORD = os.environ.get("FM_PASSWORD", "admin123")  # Default seeded password.
SESSION_SECRET = os.environ.get("FM_SECRET_KEY") or secrets.token_hex(32)  # Flask session signing key.
ALLOW_REGISTRATION = os.environ.get("FM_ALLOW_REGISTRATION", "1").lower() not in {"0", "false", "no", "off"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")  # Safe folder-name username rule.

MAX_UPLOAD_BYTES = int(os.environ.get("FM_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))  # Default: 1 GiB.

TEXT_EXTENSIONS = {
    ".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".csv", ".log", ".ini", ".conf",
    ".py", ".js", ".ts", ".css", ".html", ".htm", ".vue", ".java", ".c", ".cpp", ".h",
    ".hpp", ".go", ".rs", ".php", ".rb", ".sh", ".bat", ".ps1", ".sql", ".toml",
    ".env", ".gitignore", ".dockerignore", ".jsonc", ".lock",
}

VIDEO_EXTENSIONS = {".mp4", ".webm", ".ogg", ".ogv", ".m4v", ".mov", ".mkv"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".ogg", ".oga", ".m4a", ".aac", ".flac", ".webm"}

app = Flask(__name__)  # Flask application instance.
app.secret_key = SESSION_SECRET  # Required for signed login sessions.
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES  # Enforce upload limit.

STORAGE_ROOT.mkdir(parents=True, exist_ok=True)  # Ensure storage root exists.
CACHE_ROOT.mkdir(parents=True, exist_ok=True)  # Ensure cache root exists.

def username_is_valid(username: str) -> bool:  # Validate usernames that also map to folder names.
    return bool(USERNAME_RE.fullmatch((username or "").strip()))

def normalize_username(username: str) -> str:  # Normalize user input without changing case.
    return (username or "").strip()

def database_connection() -> sqlite3.Connection:  # Open the user database.
    connection = sqlite3.connect(USERS_DB)
    connection.row_factory = sqlite3.Row
    return connection

def storage_root_for_username(username: str) -> Path:  # Return one user's isolated storage root.
    username = normalize_username(username)
    if not username_is_valid(username):
        abort(400, description="Invalid username")

    root = (STORAGE_ROOT / username).resolve()
    try:
        root.relative_to(STORAGE_ROOT)
    except ValueError:
        abort(400, description="Invalid user storage path")

    return root

def cache_root_for_username(username: str) -> Path:  # Return one user's isolated archive cache root.
    username = normalize_username(username)
    if not username_is_valid(username):
        abort(400, description="Invalid username")

    root = (CACHE_ROOT / username).resolve()
    try:
        root.relative_to(CACHE_ROOT)
    except ValueError:
        abort(400, description="Invalid user cache path")

    return root

def get_user(username: str) -> Optional[sqlite3.Row]:  # Fetch a user row by username.
    username = normalize_username(username)
    with database_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

def create_user(username: str, password: str, is_admin: int = 0) -> tuple[bool, str]:  # Create a new login user.
    username = normalize_username(username)
    password = password or ""

    if not username_is_valid(username):
        return False, "Username must be 3-32 characters and may contain letters, numbers, underscore, dot, and hyphen."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    try:
        with database_connection() as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, created, is_admin) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), int(time.time()), int(is_admin)),
            )
    except sqlite3.IntegrityError:
        return False, "Username already exists."

    storage_root_for_username(username).mkdir(parents=True, exist_ok=True)
    cache_root_for_username(username).mkdir(parents=True, exist_ok=True)
    return True, ""

def init_user_database() -> None:  # Initialize SQLite and seed the default account.
    with database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created INTEGER NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            """
        )

    if not get_user(DEFAULT_USERNAME):
        ok, error = create_user(DEFAULT_USERNAME, DEFAULT_PASSWORD, is_admin=1)
        if not ok:
            raise RuntimeError(f"Could not create default user: {error}")

def verify_user_credentials(username: str, password: str) -> bool:  # Validate form-login credentials.
    user = get_user(username)
    return bool(user and check_password_hash(user["password_hash"], password or ""))

def current_username() -> Optional[str]:  # Return the logged-in username, if any.
    username = session.get("username")
    return normalize_username(username) if username else None

def current_storage_root() -> Path:  # Return the logged-in user's storage root.
    username = current_username()
    if not username:
        abort(401, description="Login required")

    root = storage_root_for_username(username)
    root.mkdir(parents=True, exist_ok=True)
    return root

def current_cache_root() -> Path:  # Return the logged-in user's archive cache root.
    username = current_username()
    if not username:
        abort(401, description="Login required")

    root = cache_root_for_username(username)
    root.mkdir(parents=True, exist_ok=True)
    return root

def require_auth(func):  # Apply session authentication to protected routes.
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_username():
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Login required"}), 401
            return redirect(url_for("login_page", next=request.full_path if request.query_string else request.path))
        return func(*args, **kwargs)
    return wrapper

init_user_database()

def load_shares() -> Dict[str, Any]:  # Read share records from disk.
    if not SHARES_FILE.exists():
        return {}
    try:
        return json.loads(SHARES_FILE.read_text("utf-8"))
    except Exception:
        return {}

def save_shares(data: Dict[str, Any]) -> None:  # Atomically save share records.
    temporary_share_file = SHARES_FILE.with_suffix(".tmp")
    temporary_share_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    temporary_share_file.replace(SHARES_FILE)

def safe_path(rel_path: str | None = "", root: Path | None = None) -> Path:  # Resolve paths inside one user's storage root only.
    root = (root or current_storage_root()).resolve()
    rel_path = (rel_path or "").strip().lstrip("/\\")
    target = (root / rel_path).resolve()

    try:
        target.relative_to(root)
    except ValueError:
        abort(400, description="Invalid path")

    return target

def rel_from_root(path: Path, root: Path | None = None) -> str:  # Convert an absolute path to a user-storage-relative path.
    root = (root or current_storage_root()).resolve()
    return path.resolve().relative_to(root).as_posix()

def is_within(child: Path, parent: Path) -> bool:  # Check path containment.
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False

def get_share_or_404(token: str) -> Dict[str, Any]:  # Load a valid public share or abort.
    shares = load_shares()
    share = shares.get(token)
    if not share:
        abort(404, description="Share does not exist or has been revoked")

    owner = share.get("owner") or DEFAULT_USERNAME  # Backward fallback for old share records.
    root = safe_path(share.get("path", ""), storage_root_for_username(owner))
    if not root.exists():
        abort(404, description="Shared source file does not exist")

    share["owner"] = owner
    share["token"] = token
    share["root_abs"] = root
    return share

def resolve_shared_path(share: Dict[str, Any], rel_path: str | None = "") -> Path:  # Resolve read-only share paths.
    root = share["root_abs"]
    if root.is_file():
        # For file shares, only the shared file itself may be accessed.
        target = root
    else:
        rel_path = (rel_path or "").strip().lstrip("/\\")
        target = (root / rel_path).resolve()

    if not is_within(target, root):
        abort(403, description="Access outside the shared directory is not allowed")

    return target

def entry_to_dict(path: Path) -> Dict[str, Any]:  # Serialize a managed file or folder.
    stat = path.stat()
    is_file = path.is_file()
    return {
        "name": path.name,
        "path": rel_from_root(path),
        "type": "dir" if path.is_dir() else "file",
        "size": stat.st_size if is_file else None,
        "modified": int(stat.st_mtime),
        "media": media_type_for(path),
        "editable": is_text_file(path),
    }

def shared_entry_to_dict(path: Path, root: Path) -> Dict[str, Any]:  # Serialize a shared file or folder.
    stat = path.stat()
    rel = "" if path.resolve() == root.resolve() else path.resolve().relative_to(root.resolve()).as_posix()
    return {
        "name": path.name,
        "path": rel,
        "type": "dir" if path.is_dir() else "file",
        "size": stat.st_size if path.is_file() else None,
        "modified": int(stat.st_mtime),
        "media": media_type_for(path),
        "editable": is_text_file(path),
    }

def media_type_for(path: Path) -> Optional[str]:  # Detect browser-playable media by extension.
    """
    Strictly determine online playback support by file extension.
    Only extensions registered in VIDEO_EXTENSIONS / AUDIO_EXTENSIONS will show playback actions.
    """
    if not path.is_file():
        return None

    suffix = path.suffix.lower()
    if suffix in VIDEO_EXTENSIONS:
        return "video"
    if suffix in AUDIO_EXTENSIONS:
        return "audio"
    return None

def is_text_file(path: Path) -> bool:  # Detect editable text files by extension.
    """
    Strictly determine online editing support by file extension.
    Only extensions registered in TEXT_EXTENSIONS will show editing actions.
    """
    if not path.is_file():
        return False
    return path.suffix.lower() in TEXT_EXTENSIONS

def detect_encoding(raw: bytes) -> str:  # Detect text encoding for the editor.
    if not raw:
        return "utf-8"

    result = from_bytes(raw).best()
    if result and result.encoding:
        return result.encoding

    return "utf-8"

def list_dir_payload(current: Path) -> Dict[str, Any]:  # Build directory listing payload.
    root = current_storage_root()
    if not current.exists():
        return {"ok": False, "error": "Path does not exist"}
    if not current.is_dir():
        return {"ok": False, "error": "Not a directory"}

    dirs = []
    files = []

    for child in current.iterdir():
        if child.name.startswith("."):
            continue
        try:
            item = entry_to_dict(child)
        except OSError:
            continue

        if child.is_dir():
            dirs.append(item)
        else:
            files.append(item)

    dirs.sort(key=lambda x: x["name"].lower())
    files.sort(key=lambda x: x["name"].lower())

    parent = ""
    if current != root:
        parent = rel_from_root(current.parent)

    return {
        "ok": True,
        "cwd": rel_from_root(current, root) if current != root else "",
        "parent": parent,
        "items": dirs + files,
    }

def list_shared_dir_payload(current: Path, root: Path) -> Dict[str, Any]:  # Build shared listing payload.
    if not current.exists():
        return {"ok": False, "error": "Path does not exist"}
    if not current.is_dir():
        return {"ok": False, "error": "Not a directory"}

    dirs = []
    files = []
    for child in current.iterdir():
        if child.name.startswith("."):
            continue
        try:
            item = shared_entry_to_dict(child, root)
        except OSError:
            continue

        if child.is_dir():
            dirs.append(item)
        else:
            files.append(item)

    dirs.sort(key=lambda x: x["name"].lower())
    files.sort(key=lambda x: x["name"].lower())

    cwd = "" if current.resolve() == root.resolve() else current.resolve().relative_to(root.resolve()).as_posix()
    parent = ""
    if current.resolve() != root.resolve():
        parent_path = current.parent.resolve()
        parent = "" if parent_path == root.resolve() else parent_path.relative_to(root.resolve()).as_posix()

    return {
        "ok": True,
        "cwd": cwd,
        "parent": parent,
        "root_name": root.name,
        "items": dirs + files,
    }

def partial_response(path: Path):  # Stream partial file content for media seeking.
    """
    Support Range requests so video/audio elements can seek.
    """
    file_size = path.stat().st_size
    range_header = request.headers.get("Range")

    if not range_header:
        return send_file(path, conditional=True)

    try:
        units, range_spec = range_header.split("=", 1)
        if units != "bytes":
            raise ValueError
        start_s, end_s = range_spec.split("-", 1)
        start = int(start_s) if start_s else 0
        end = int(end_s) if end_s else file_size - 1
        end = min(end, file_size - 1)
        if start > end:
            raise ValueError
    except ValueError:
        return Response(status=416)

    length = end - start + 1
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

    def generate():
        with path.open("rb") as file_handle:
            file_handle.seek(start)
            remaining = length
            chunk_size = 1024 * 1024
            while remaining > 0:
                chunk = file_handle.read(min(chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    partial_content_response = Response(generate(), status=206, mimetype=mime, direct_passthrough=True)
    partial_content_response.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
    partial_content_response.headers["Accept-Ranges"] = "bytes"
    partial_content_response.headers["Content-Length"] = str(length)
    return partial_content_response

def unique_archive_name(prefix: str = "download") -> str:  # Create a unique archive filename.
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in prefix).strip("._")
    if not safe:
        safe = "download"
    return f"{safe}_{int(time.time())}_{uuid.uuid4().hex[:8]}.7z"

def cleanup_old_cache(max_age_seconds: int = 24 * 3600, cache_root: Path | None = None) -> None:  # Remove expired cached archives.
    cache_root = cache_root or current_cache_root()
    now = time.time()
    for cache_file in cache_root.iterdir():
        try:
            if cache_file.is_file() and now - cache_file.stat().st_mtime > max_age_seconds:
                cache_file.unlink()
        except OSError:
            pass

def make_7z_archive(paths: list[Path], base_dir: Path, archive_name: str) -> Path:  # Package selected files as 7z.
    user_cache_root = current_cache_root()
    user_storage_root = current_storage_root()
    cleanup_old_cache(cache_root=user_cache_root)
    archive_path = (user_cache_root / archive_name).resolve()

    try:
        archive_path.relative_to(user_cache_root)
    except ValueError:
        abort(400, description="Invalid archive name")

    # preset=9 is the highest LZMA2 preset exposed by py7zr.
    filters = [{"id": py7zr.FILTER_LZMA2, "preset": 9 | py7zr.PRESET_EXTREME}]

    with py7zr.SevenZipFile(archive_path, "w", filters=filters) as archive:
        used_names = set()

        for source_path in paths:
            source_path = source_path.resolve()
            if not source_path.exists():
                continue

            if source_path == user_storage_root:
                archive_name_in_package = "storage"
            else:
                try:
                    archive_name_in_package = source_path.relative_to(base_dir.resolve()).as_posix()
                except ValueError:
                    archive_name_in_package = source_path.name

            if not archive_name_in_package or archive_name_in_package == ".":
                archive_name_in_package = source_path.name or "storage"

            original_archive_name = archive_name_in_package
            duplicate_index = 1
            while archive_name_in_package in used_names:
                stem = Path(original_archive_name).stem
                suffix = Path(original_archive_name).suffix
                parent = Path(original_archive_name).parent.as_posix()
                renamed = f"{stem}_{duplicate_index}{suffix}"
                archive_name_in_package = renamed if parent == "." else f"{parent}/{renamed}"
                duplicate_index += 1

            used_names.add(archive_name_in_package)
            archive.writeall(source_path, archive_name_in_package) if source_path.is_dir() else archive.write(source_path, archive_name_in_package)

    return archive_path


@app.get("/login")  # Login page.
def login_page():
    if current_username():
        return redirect(url_for("index"))
    return render_template_string(LOGIN_HTML, error="", next_url=request.args.get("next", ""), allow_registration=ALLOW_REGISTRATION)

@app.post("/login")  # Login form handler.
def login_submit():
    username = normalize_username(request.form.get("username", ""))
    password = request.form.get("password", "")
    next_url = request.form.get("next", "") or url_for("index")

    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = url_for("index")

    if verify_user_credentials(username, password):
        session.clear()
        session["username"] = username
        storage_root_for_username(username).mkdir(parents=True, exist_ok=True)
        cache_root_for_username(username).mkdir(parents=True, exist_ok=True)
        return redirect(next_url)

    return render_template_string(LOGIN_HTML, error="Invalid username or password.", next_url=next_url, allow_registration=ALLOW_REGISTRATION), 401

@app.get("/register")  # Registration page.
def register_page():
    if current_username():
        return redirect(url_for("index"))
    if not ALLOW_REGISTRATION:
        return render_template_string(REGISTER_HTML, error="Registration is disabled by FM_ALLOW_REGISTRATION.", allow_registration=False), 403
    return render_template_string(REGISTER_HTML, error="", allow_registration=True)

@app.post("/register")  # Registration form handler.
def register_submit():
    if not ALLOW_REGISTRATION:
        return render_template_string(REGISTER_HTML, error="Registration is disabled by FM_ALLOW_REGISTRATION.", allow_registration=False), 403

    username = normalize_username(request.form.get("username", ""))
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if password != confirm_password:
        return render_template_string(REGISTER_HTML, error="Passwords do not match.", allow_registration=True), 400

    ok, error = create_user(username, password)
    if not ok:
        return render_template_string(REGISTER_HTML, error=error, allow_registration=True), 400

    session.clear()
    session["username"] = username
    return redirect(url_for("index"))

@app.get("/logout")  # Logout page.
def logout_page():
    session.clear()
    return redirect(url_for("login_page"))

@app.get("/account")  # Current account information page.
@require_auth
def account_page():
    return render_template_string(
        ACCOUNT_HTML,
        username=current_username(),
        storage_root=str(current_storage_root()),
        cache_root=str(current_cache_root()),
        registration_enabled=ALLOW_REGISTRATION,
        max_upload_bytes=app.config["MAX_CONTENT_LENGTH"],
    )

@app.get("/")  # Main file manager page.
@require_auth
def index():
    return render_template_string(INDEX_HTML, username=current_username())

@app.get("/editor")  # Text editor iframe page.
@require_auth
def editor_page():
    return render_template_string(EDITOR_HTML)

@app.get("/viewer")  # Media/text viewer iframe page.
@require_auth
def viewer_page():
    return render_template_string(VIEWER_HTML)

@app.get("/share-viewer/<token>")
def share_viewer_page(token: str):
    get_share_or_404(token)
    return render_template_string(SHARE_VIEWER_HTML, token=token)

@app.get("/api/list")  # List files in a directory.
@require_auth
def api_list():
    current = safe_path(request.args.get("path", ""))
    payload = list_dir_payload(current)
    if not payload["ok"]:
        return jsonify(payload), 404
    return jsonify(payload)

@app.post("/api/mkdir")  # Create a folder.
@require_auth
def api_mkdir():
    data = request.get_json(force=True, silent=True) or {}
    parent = safe_path(data.get("path", ""))
    name = (data.get("name") or "").strip()

    if not parent.exists() or not parent.is_dir():
        return jsonify({"ok": False, "error": "Parent directory does not exist"}), 404

    if not name:
        return jsonify({"ok": False, "error": "Folder name cannot be empty"}), 400

    if "/" in name or "\\" in name or name in {".", ".."}:
        return jsonify({"ok": False, "error": "Invalid folder name"}), 400

    root = current_storage_root()
    parent_rel = rel_from_root(parent, root) if parent != root else ""
    target = safe_path(f"{parent_rel}/{name}" if parent_rel else name)

    if target.exists():
        return jsonify({"ok": False, "error": "Folder already exists"}), 409

    target.mkdir(parents=False)
    return jsonify({"ok": True, "item": entry_to_dict(target)})

@app.post("/api/upload")  # Upload selected files.
@require_auth
def api_upload():
    rel_dir = request.form.get("path", "")
    target_dir = safe_path(rel_dir)

    if not target_dir.exists() or not target_dir.is_dir():
        return jsonify({"ok": False, "error": "Upload target folder does not exist"}), 404

    files = request.files.getlist("files")
    if not files:
        return jsonify({"ok": False, "error": "No file selected"}), 400

    saved = []
    for uploaded_file in files:
        if not uploaded_file.filename:
            continue

        filename = Path(uploaded_file.filename).name.replace("/", "_").replace("\\", "_")
        if filename in {"", ".", ".."}:
            continue

        root = current_storage_root()
        parent_rel = rel_from_root(target_dir, root) if target_dir != root else ""
        dest = safe_path(f"{parent_rel}/{filename}" if parent_rel else filename)

        if dest.exists():
            stem = dest.stem
            suffix = dest.suffix
            i = 1
            while dest.exists():
                new_name = f"{stem} ({i}){suffix}"
                dest = safe_path(f"{parent_rel}/{new_name}" if parent_rel else new_name)
                i += 1

        uploaded_file.save(dest)
        saved.append(entry_to_dict(dest))

    return jsonify({"ok": True, "saved": saved})

@app.get("/api/download")  # Download a file.
@require_auth
def api_download():
    path = safe_path(request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File does not exist"}), 404

    return send_file(path, as_attachment=True, download_name=path.name, conditional=True)

@app.get("/api/media")
@require_auth
def api_media():
    path = safe_path(request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File does not exist"}), 404

    if media_type_for(path) not in {"video", "audio"}:
        return jsonify({"ok": False, "error": "This file extension does not support online playback"}), 400

    return partial_response(path)

@app.get("/api/text")
@require_auth
def api_text():
    path = safe_path(request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File does not exist"}), 404

    if not is_text_file(path):
        return jsonify({"ok": False, "error": "This file type does not support online editing"}), 400

    raw = path.read_bytes()
    encoding = detect_encoding(raw)

    try:
        text = raw.decode(encoding)
    except Exception:
        text = raw.decode("utf-8", errors="replace")
        encoding = "utf-8"

    return jsonify({
        "ok": True,
        "path": rel_from_root(path),
        "name": path.name,
        "encoding": encoding,
        "text": text,
    })

@app.post("/api/text")
@require_auth
def api_text_save():
    data = request.get_json(force=True, silent=True) or {}
    path = safe_path(data.get("path", ""))
    text = data.get("text", "")
    encoding = data.get("encoding") or "utf-8"

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File does not exist"}), 404

    if not is_text_file(path):
        return jsonify({"ok": False, "error": "This file type does not support online editing"}), 400

    try:
        path.write_bytes(str(text).encode(encoding))
    except LookupError:
        return jsonify({"ok": False, "error": f"Unsupported encoding: {encoding}"}), 400
    except UnicodeEncodeError:
        return jsonify({"ok": False, "error": f"The current content cannot be saved with {encoding} encoding"}), 400

    return jsonify({"ok": True, "encoding": encoding, "saved_at": int(time.time())})

@app.post("/api/delete")  # Delete a file or folder.
@require_auth
def api_delete():
    data = request.get_json(force=True, silent=True) or {}
    path = safe_path(data.get("path", ""))

    if path == current_storage_root():
        return jsonify({"ok": False, "error": "Cannot delete the root directory"}), 400

    if not path.exists():
        return jsonify({"ok": False, "error": "Path does not exist"}), 404

    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()

    return jsonify({"ok": True})

@app.post("/api/move")  # Move files or folders.
@require_auth
def api_move():  # Move one or more files; supports folder targets.
    data = request.get_json(force=True, silent=True) or {}
    source_values = data.get("src")
    destination_value = data.get("dst", "")
    move_into_directory = bool(data.get("into_directory"))

    if not source_values and source_values != "":
        return jsonify({"ok": False, "error": "Source path is required"}), 400

    if isinstance(source_values, str):
        source_values = [source_values]

    if not isinstance(source_values, list) or not source_values:
        return jsonify({"ok": False, "error": "Source path is required"}), 400

    user_storage_root = current_storage_root()
    destination_path = safe_path(destination_value)

    if len(source_values) > 1:
        move_into_directory = True

    if destination_path.exists() and destination_path.is_dir():
        move_into_directory = True

    if move_into_directory and (not destination_path.exists() or not destination_path.is_dir()):
        return jsonify({"ok": False, "error": "Target folder does not exist"}), 404

    planned_moves = []
    for source_value in source_values:
        source_path = safe_path(source_value)

        if source_path == user_storage_root:
            return jsonify({"ok": False, "error": "Cannot move the root directory"}), 400

        if not source_path.exists():
            return jsonify({"ok": False, "error": "Source path does not exist"}), 404

        target_path = destination_path / source_path.name if move_into_directory else destination_path

        if target_path.exists():
            return jsonify({"ok": False, "error": "Target path already exists"}), 409

        if source_path.is_dir() and is_within(target_path, source_path):
            return jsonify({"ok": False, "error": "Cannot move a folder into itself"}), 400

        planned_moves.append((source_path, target_path))

    moved_items = []
    for source_path, target_path in planned_moves:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source_path), str(target_path))
        moved_items.append(entry_to_dict(target_path))

    return jsonify({"ok": True, "item": moved_items[0] if len(moved_items) == 1 else None, "items": moved_items})

@app.post("/api/rename")  # Rename a file or folder.
@require_auth
def api_rename():
    data = request.get_json(force=True, silent=True) or {}
    user_storage_root = current_storage_root()
    source_path = safe_path(data.get("path", ""))
    new_name = (data.get("name") or "").strip()

    if source_path == user_storage_root:
        return jsonify({"ok": False, "error": "Cannot rename the root directory"}), 400

    if not source_path.exists():
        return jsonify({"ok": False, "error": "Path does not exist"}), 404

    if not new_name or "/" in new_name or "\\" in new_name or new_name in {".", ".."}:
        return jsonify({"ok": False, "error": "Invalid name"}), 400

    destination_path = source_path.with_name(new_name).resolve()

    root = current_storage_root()
    try:
        destination_path.relative_to(root)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid path"}), 400

    if destination_path.exists():
        return jsonify({"ok": False, "error": "Target name already exists"}), 409

    source_path.rename(destination_path)
    return jsonify({"ok": True, "item": entry_to_dict(destination_path)})

@app.post("/api/share")
@require_auth
def api_create_share():
    data = request.get_json(force=True, silent=True) or {}
    path = safe_path(data.get("path", ""))

    if not path.exists():
        return jsonify({"ok": False, "error": "Share path does not exist"}), 404

    token = secrets.token_urlsafe(24)
    shares = load_shares()
    shares[token] = {
        "owner": current_username(),
        "path": rel_from_root(path, current_storage_root()) if path != current_storage_root() else "",
        "name": path.name if path != current_storage_root() else "Root",
        "type": "dir" if path.is_dir() else "file",
        "created": int(time.time()),
    }
    save_shares(shares)

    return jsonify({
        "ok": True,
        "token": token,
        "url": url_for("share_page", token=token, _external=True),
        "share": shares[token],
    })

@app.get("/api/shares")
@require_auth
def api_list_shares():
    shares = load_shares()
    out = []
    owner = current_username()
    for token, share in shares.items():
        if (share.get("owner") or DEFAULT_USERNAME) != owner:
            continue
        share_item = dict(share)
        share_item["token"] = token
        share_item["url"] = url_for("share_page", token=token, _external=True)
        out.append(share_item)
    out.sort(key=lambda share_item: share_item.get("created", 0), reverse=True)
    return jsonify({"ok": True, "shares": out})

@app.delete("/api/share/<token>")
@require_auth
def api_delete_share(token: str):
    shares = load_shares()
    if token in shares and (shares[token].get("owner") or DEFAULT_USERNAME) == current_username():
        shares.pop(token)
        save_shares(shares)
    return jsonify({"ok": True})

@app.get("/share/<token>")
def share_page(token: str):
    share = get_share_or_404(token)
    if share["root_abs"].is_file():
        return render_template_string(SHARE_FILE_HTML, token=token, name=share["root_abs"].name)
    return render_template_string(SHARE_HTML, token=token, name=share["root_abs"].name)

@app.get("/s/<token>/api/list")
def shared_api_list(token: str):
    share = get_share_or_404(token)
    root = share["root_abs"]

    if root.is_file():
        return jsonify({
            "ok": True,
            "cwd": "",
            "parent": "",
            "root_name": root.name,
            "items": [shared_entry_to_dict(root, root)],
        })

    current = resolve_shared_path(share, request.args.get("path", ""))
    payload = list_shared_dir_payload(current, root)
    if not payload["ok"]:
        return jsonify(payload), 404
    return jsonify(payload)

@app.get("/s/<token>/text")
def shared_text(token: str):
    share = get_share_or_404(token)
    path = resolve_shared_path(share, request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File does not exist"}), 404

    if not is_text_file(path):
        return jsonify({"ok": False, "error": "This file type does not support online viewing"}), 400

    raw = path.read_bytes()
    encoding = detect_encoding(raw)

    try:
        text = raw.decode(encoding)
    except Exception:
        text = raw.decode("utf-8", errors="replace")
        encoding = "utf-8"

    return jsonify({
        "ok": True,
        "path": shared_entry_to_dict(path, share["root_abs"])["path"],
        "name": path.name,
        "encoding": encoding,
        "text": text,
    })

@app.get("/s/<token>/download")
def shared_download(token: str):
    share = get_share_or_404(token)
    path = resolve_shared_path(share, request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File does not exist"}), 404

    return send_file(path, as_attachment=True, download_name=path.name, conditional=True)

@app.get("/s/<token>/media")
def shared_media(token: str):
    share = get_share_or_404(token)
    path = resolve_shared_path(share, request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File does not exist"}), 404

    if media_type_for(path) not in {"video", "audio"}:
        return jsonify({"ok": False, "error": "This file extension does not support online playback"}), 400

    return partial_response(path)

@app.post("/api/archive")
@require_auth
def api_create_archive():
    data = request.get_json(force=True, silent=True) or {}
    rel_paths = data.get("paths") or []
    if isinstance(rel_paths, str):
        rel_paths = [rel_paths]

    if not rel_paths:
        return jsonify({"ok": False, "error": "Select at least one file or folder"}), 400

    resolved = []
    for rel in rel_paths:
        resolved_path = safe_path(rel)
        if not resolved_path.exists():
            return jsonify({"ok": False, "error": f"Path does not exist: {rel}"}), 404
        resolved.append(resolved_path)

    if len(resolved) == 1:
        prefix = resolved[0].name or "storage"
        user_storage_root = current_storage_root()
        base_for_arcname = resolved[0].parent if resolved[0] != user_storage_root else user_storage_root
    else:
        prefix = "selected"
        # For multi-select archives, use the current directory as the archive base；Use the storage root when cwd is not provided.
        cwd_rel = data.get("cwd", "")
        base_for_arcname = safe_path(cwd_rel)
        if not base_for_arcname.exists() or not base_for_arcname.is_dir():
            base_for_arcname = current_storage_root()

    archive_name = unique_archive_name(prefix)
    archive_path = make_7z_archive(resolved, base_for_arcname, archive_name)

    return jsonify({
        "ok": True,
        "archive": archive_name,
        "size": archive_path.stat().st_size,
        "url": url_for("api_download_archive", name=archive_name),
    })

@app.get("/api/archive/<name>")
@require_auth
def api_download_archive(name: str):
    if "/" in name or "\\" in name or not name.endswith(".7z"):
        return jsonify({"ok": False, "error": "Invalid archive name"}), 400

    user_cache_root = current_cache_root()
    path = (user_cache_root / name).resolve()
    try:
        path.relative_to(user_cache_root)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid path"}), 400

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "Archive does not exist or has been cleaned"}), 404

    return send_file(path, as_attachment=True, download_name=name, conditional=True)

@app.get("/api/info")
@require_auth
def api_info():
    return jsonify({
        "ok": True,
        "storage_root": str(current_storage_root()),
        "cache_root": str(current_cache_root()),
        "max_upload_bytes": app.config["MAX_CONTENT_LENGTH"],
        "username": current_username(),
        "registration_enabled": ALLOW_REGISTRATION,
    })


LOGIN_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Login - LAN File Manager</title>\n  <style>\n* { box-sizing: border-box; }\nbody { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #fff8f5; color: #50322b; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }\n.card { width: min(420px, calc(100vw - 28px)); padding: 26px; border: 1px solid #efc1b3; border-radius: 18px; background: #fffaf7; box-shadow: 0 18px 50px rgba(80, 50, 43, 0.13); }\nh1 { margin: 0 0 8px; font-size: 24px; }\np { margin: 0 0 20px; color: #8b6a62; }\nlabel { display: block; margin-top: 13px; font-weight: 650; }\ninput { width: 100%; margin-top: 6px; padding: 11px 12px; border: 1px solid #efc1b3; border-radius: 10px; background: #fff; color: #50322b; font: inherit; }\nbutton { width: 100%; margin-top: 18px; padding: 11px 12px; border: 1px solid #e9795f; border-radius: 10px; background: #e9795f; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }\na { color: #c95d45; text-decoration: none; }\n.footer { margin-top: 14px; font-size: 14px; color: #8b6a62; text-align: center; }\n.error { margin: 12px 0 0; padding: 9px 10px; border: 1px solid #f3b0a3; border-radius: 10px; background: #fff1ee; color: #b42318; }\n  </style>\n</head>\n<body>\n  <form class="card" method="post" action="/login">\n    <h1>Login</h1>\n    <p>Sign in to your private file space.</p>\n    {% if error %}<div class="error">{{ error }}</div>{% endif %}\n    <input type="hidden" name="next" value="{{ next_url }}">\n    <label>Username<input name="username" autocomplete="username" required autofocus></label>\n    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>\n    <button type="submit">Login</button>\n    {% if allow_registration %}<div class="footer">No account yet? <a href="/register">Create one</a></div>{% endif %}\n  </form>\n</body>\n</html>'

REGISTER_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Register - LAN File Manager</title>\n  <style>\n* { box-sizing: border-box; }\nbody { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #fff8f5; color: #50322b; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }\n.card { width: min(440px, calc(100vw - 28px)); padding: 26px; border: 1px solid #efc1b3; border-radius: 18px; background: #fffaf7; box-shadow: 0 18px 50px rgba(80, 50, 43, 0.13); }\nh1 { margin: 0 0 8px; font-size: 24px; }\np { margin: 0 0 20px; color: #8b6a62; }\nlabel { display: block; margin-top: 13px; font-weight: 650; }\ninput { width: 100%; margin-top: 6px; padding: 11px 12px; border: 1px solid #efc1b3; border-radius: 10px; background: #fff; color: #50322b; font: inherit; }\nbutton { width: 100%; margin-top: 18px; padding: 11px 12px; border: 1px solid #e9795f; border-radius: 10px; background: #e9795f; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }\na { color: #c95d45; text-decoration: none; }\n.footer { margin-top: 14px; font-size: 14px; color: #8b6a62; text-align: center; }\n.error { margin: 12px 0 0; padding: 9px 10px; border: 1px solid #f3b0a3; border-radius: 10px; background: #fff1ee; color: #b42318; }\n.note { margin-top: 10px; font-size: 13px; color: #8b6a62; }\n  </style>\n</head>\n<body>\n  <form class="card" method="post" action="/register">\n    <h1>Create account</h1>\n    <p>Each account gets an isolated storage folder.</p>\n    {% if error %}<div class="error">{{ error }}</div>{% endif %}\n    {% if allow_registration %}\n      <label>Username<input name="username" autocomplete="username" required autofocus></label>\n      <div class="note">Allowed: 3-32 letters, numbers, underscore, dot, and hyphen.</div>\n      <label>Password<input name="password" type="password" autocomplete="new-password" required></label>\n      <label>Confirm password<input name="confirm_password" type="password" autocomplete="new-password" required></label>\n      <button type="submit">Register</button>\n    {% endif %}\n    <div class="footer">Already have an account? <a href="/login">Login</a></div>\n  </form>\n</body>\n</html>'

ACCOUNT_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Account - LAN File Manager</title>\n  <style>\n* { box-sizing: border-box; }\nbody { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #fff8f5; color: #50322b; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }\n.card { width: min(680px, calc(100vw - 28px)); padding: 26px; border: 1px solid #efc1b3; border-radius: 18px; background: #fffaf7; box-shadow: 0 18px 50px rgba(80, 50, 43, 0.13); }\nh1 { margin: 0 0 18px; font-size: 24px; }\n.row { padding: 10px 0; border-top: 1px solid #f4d0c6; }\n.key { font-weight: 750; }\n.value { margin-top: 4px; color: #8b6a62; word-break: break-all; }\n.actions { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }\na { color: #c95d45; text-decoration: none; }\n.button { display: inline-block; padding: 10px 13px; border: 1px solid #e9795f; border-radius: 10px; background: #e9795f; color: #fff; font-weight: 700; }\n.button.secondary { background: #fff; color: #c95d45; }\n  </style>\n</head>\n<body>\n  <main class="card">\n    <h1>Account</h1>\n    <div class="row"><div class="key">Username</div><div class="value">{{ username }}</div></div>\n    <div class="row"><div class="key">Storage root</div><div class="value">{{ storage_root }}</div></div>\n    <div class="row"><div class="key">Archive cache root</div><div class="value">{{ cache_root }}</div></div>\n    <div class="row"><div class="key">Max upload bytes</div><div class="value">{{ max_upload_bytes }}</div></div>\n    <div class="row"><div class="key">Registration enabled</div><div class="value">{{ registration_enabled }}</div></div>\n    <div class="actions"><a class="button" href="/">Open File Manager</a><a class="button secondary" href="/logout">Logout</a></div>\n  </main>\n</body>\n</html>'

# =========================
# Embedded frontend assets
# =========================

INDEX_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>LAN File Manager</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: 100vh;\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div id="breadcrumb" class="breadcrumb-flat"></div>\n  <div class="path-meta">\n    <span id="countText"></span>\n    <span class="hint">Click to open/download · Ctrl multi-select · Right-click actions</span>\n  </div>\n</header>\n\n<main class="file-pane" id="filePane">\n  <input id="fileInput" class="hidden-file-input" type="file" multiple>\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="emptyState" class="empty-state d-none">This folder is empty. Right-click empty space to create a folder or upload files.</div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div class="modal fade" id="sharesModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-lg modal-dialog-centered">\n    <div class="modal-content share-list-modal">\n      <div class="modal-header">\n        <h5 class="modal-title">Share List</h5>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>\n      </div>\n      <div class="modal-body">\n        <div id="sharesList" class="small"></div>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="selectionBox"></div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Open</button>\n  <button data-action="download">Download</button>\n  <button data-action="archive">Download as 7z archive</button>\n  <button data-action="share">Share</button>\n  <hr data-sep="item">\n  <button data-action="rename">Rename</button>\n  <button data-action="move">Move</button>\n  <button data-action="delete" class="danger">Delete</button>\n\n  <button data-action="mkdir">New Folder</button>\n  <button data-action="upload">Upload Files</button>\n  <button data-action="refresh">Refresh</button>\n  <button data-action="shares">Share List</button>\n</div>\n\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPaths = new Set();\nlet contextTargetPath = null;\nlet dragState = null;\nlet currentItemCount = 0;\nlet activePageModal = null;\n\nconst getById = (elementId) => document.getElementById(elementId);\n\nfunction showMessage(text, type = "muted") {\n  const element = getById("message");\n  element.className = `message small text-${type}`;\n  element.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (element.textContent === text) element.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url, options = {}) {\n  const response = await fetch(url, options);\n  const contentType = response.headers.get("content-type") || "";\n\n  let data = null;\n  if (contentType.includes("application/json")) {\n    data = await response.json();\n  }\n\n  if (!response.ok || (data && data.ok === false)) {\n    throw new Error((data && data.error) || `Request failed: ${response.status}`);\n  }\n\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    selectedPaths.clear();\n    itemsByPath.clear();\n\n    const data = await api(`/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = getById("fileGrid");\n    grid.innerHTML = "";\n    getById("emptyState").classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\n\nfunction dragPathsFromEvent(event) {\n  const dragData = event.dataTransfer.getData("application/json") || event.dataTransfer.getData("text/plain") || "[]";\n  const paths = JSON.parse(dragData);\n  return Array.isArray(paths) ? paths : [paths];\n}\n\nasync function movePathsToDirectory(paths, targetDirectory) {\n  const sourcePaths = paths.filter(path => path !== targetDirectory);\n  if (!sourcePaths.length) return;\n\n  try {\n    await api("/api/move", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({src: sourcePaths, dst: targetDirectory, into_directory: true})\n    });\n    showMessage("Move complete", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction enableDirectoryDrop(element, targetDirectory) {\n  element.ondragover = (event) => {\n    event.preventDefault();\n    event.dataTransfer.dropEffect = "move";\n  };\n\n  element.ondrop = (event) => {\n    event.preventDefault();\n    event.stopPropagation();\n    movePathsToDirectory(dragPathsFromEvent(event), targetDirectory);\n  };\n}\n\nfunction renderBreadcrumb() {\n  const box = getById("breadcrumb");\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = "Root";\n  root.onclick = () => loadList("");\n  enableDirectoryDrop(root, "");\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    enableDirectoryDrop(crumb, target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const count = selectedPaths.size;\n  getById("countText").textContent = count > 0 ? `Selected ${count}  item(s)` : `${currentItemCount} item(s)`;\n}\n\nfunction renderItem(item) {\n  const element = document.createElement("div");\n  element.className = "file-item";\n  element.dataset.path = item.path;\n  element.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Folder"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Folder" : (item.media || (item.editable ? "Text" : fmtSize(item.size)));\n\n  element.append(icon, name, meta);\n\n  element.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  element.onclick = (e) => {\n    if (dragState && dragState.moved) return;\n\n    // Ctrl/Cmd/Shift reserved for multi-select；A normal left click performs the most direct action:\n    // folders open, files download directly.\n    if (e.ctrlKey || e.metaKey) {\n      toggleSelect(item.path);\n      return;\n    }\n\n    if (e.shiftKey) {\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n      return;\n    }\n\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  element.oncontextmenu = (e) => {\n    e.preventDefault();\n    contextTargetPath = item.path;\n    if (!selectedPaths.has(item.path)) {\n      selectedPaths.clear();\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n    }\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  element.draggable = true;\n  element.ondragstart = (e) => {\n    if (!selectedPaths.has(item.path)) {\n      selectedPaths.clear();\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n    }\n    const paths = [...selectedPaths];\n    e.dataTransfer.effectAllowed = "move";\n    e.dataTransfer.setData("application/json", JSON.stringify(paths));\n    e.dataTransfer.setData("text/plain", JSON.stringify(paths));\n  };\n\n  if (item.type === "dir") {\n    enableDirectoryDrop(element, item.path);\n  }\n\n  return element;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction getSelectedItems() {\n  return [...selectedPaths].map(selectedPath => itemsByPath.get(selectedPath)).filter(Boolean);\n}\n\nfunction getContextItems() {\n  const items = getSelectedItems();\n  if (items.length) return items;\n  if (contextTargetPath && itemsByPath.has(contextTargetPath)) return [itemsByPath.get(contextTargetPath)];\n  return [];\n}\n\nfunction toggleSelect(path) {\n  if (selectedPaths.has(path)) selectedPaths.delete(path);\n  else selectedPaths.add(path);\n  syncSelectionUI();\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", selectedPaths.has(row.dataset.path));\n  });\n  updateCountText();\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media) {\n    openPageModal(`Play - ${item.name}`, `/viewer?path=${encodeURIComponent(item.path)}`);\n  } else if (item.editable) {\n    openPageModal("", `/editor?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Open";\n  if (item.type === "dir") return "Open";\n  if (item.media === "video") return "Play Online";\n  if (item.media === "audio") return "Play Online";\n  if (item.editable) return "Edit/View Online";\n  return "Download";\n}\n\nfunction openPageModal(title, url) {\n  getById("pageFrame").src = url;\n  activePageModal = bootstrap.Modal.getOrCreateInstance(getById("pageModal"));\n  activePageModal.show();\n}\n\ngetById("pageModal").addEventListener("hidden.bs.modal", () => {\n  getById("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  window.location.href = `/api/download?path=${encodeURIComponent(path)}`;\n}\n\nasync function mkdirFromContext() {\n  const name = prompt("New folder name:");\n  if (!name || !name.trim()) return;\n\n  try {\n    await api("/api/mkdir", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: cwd, name: name.trim()})\n    });\n    showMessage("Folder created", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction uploadFromContext() {\n  getById("fileInput").click();\n}\n\nasync function uploadSelectedFiles() {\n  const input = getById("fileInput");\n  if (!input.files.length) return;\n\n  const form = new FormData();\n  form.append("path", cwd);\n  for (const file of input.files) {\n    form.append("files", file);\n  }\n\n  try {\n    await api("/api/upload", {\n      method: "POST",\n      body: form\n    });\n    input.value = "";\n    showMessage("Upload complete", "success");\n    await loadList();\n  } catch (err) {\n    input.value = "";\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function deleteItems(items) {\n  if (!items.length) return;\n  const ok = confirm(`Delete selected ${items.length} item(s)? All contents inside folders will be deleted.`);\n  if (!ok) return;\n\n  try {\n    for (const item of items) {\n      await api("/api/delete", {\n        method: "POST",\n        headers: {"Content-Type": "application/json"},\n        body: JSON.stringify({path: item.path})\n      });\n    }\n    showMessage("Delete complete", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function renameItem(item) {\n  const name = prompt("Enter new name:", item.name);\n  if (!name || name === item.name) return;\n\n  try {\n    await api("/api/rename", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: item.path, name})\n    });\n    showMessage("Rename complete", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function moveItems(items) {\n  if (!items.length) return;\n\n  if (items.length === 1) {\n    const dst = prompt("Enter target relative path, e.g. docs/a.txt or backup/folder", items[0].path);\n    if (!dst || dst === items[0].path) return;\n\n    try {\n      await api("/api/move", {\n        method: "POST",\n        headers: {"Content-Type": "application/json"},\n        body: JSON.stringify({src: items[0].path, dst: dst.trim()})\n      });\n      showMessage("Move complete", "success");\n      await loadList();\n    } catch (err) {\n      showMessage(err.message, "danger");\n    }\n    return;\n  }\n\n  const targetDirectory = prompt("Enter target folder relative path, e.g. backup or docs/2026");\n  if (targetDirectory === null) return;\n\n  await movePathsToDirectory(items.map(item => item.path), targetDirectory.trim().replace(/^\\/+|\\/+$/g, ""));\n}\n\nasync function shareItem(item) {\n  try {\n    const data = await api("/api/share", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: item.path})\n    });\n\n    let copied = false;\n    try {\n      await navigator.clipboard.writeText(data.url);\n      copied = true;\n    } catch (_) {\n      copied = false;\n    }\n\n    showMessage(copied ? `Share created. Link copied: ${data.url}` : `Share created. Please copy manually: ${data.url}`, "success");\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function archiveItems(items) {\n  if (!items.length) return;\n  try {\n    showMessage("Creating 7z archive, please wait...", "muted");\n    const data = await api("/api/archive", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({\n        cwd,\n        paths: items.map(x => x.path)\n      })\n    });\n    showMessage(`Archive complete: ${fmtSize(data.size)}`, "success");\n    window.location.href = data.url;\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function showShares() {\n  try {\n    const data = await api("/api/shares");\n    const box = getById("sharesList");\n    if (!data.shares.length) {\n      box.innerHTML = `<div class="text-muted">No shares yet</div>`;\n    } else {\n      box.innerHTML = "";\n      for (const shareInfo of data.shares) {\n        const div = document.createElement("div");\n        div.className = "border rounded p-2 mb-2";\n        div.innerHTML = `\n          <div><strong>${shareInfo.name}</strong> <span class="badge text-bg-light">${shareInfo.type}</span></div>\n          <div class="text-break"><a href="${shareInfo.url}" target="_blank">${shareInfo.url}</a></div>\n          <div class="text-muted">Path: /${shareInfo.path || ""}</div>\n        `;\n        const del = document.createElement("button");\n        del.className = "btn btn-sm btn-outline-danger mt-2";\n        del.textContent = "Revoke Share";\n        del.onclick = async () => {\n          await api(`/api/share/${shareInfo.token}`, {method: "DELETE"});\n          showShares();\n        };\n        div.appendChild(del);\n        box.appendChild(div);\n      }\n    }\n    new bootstrap.Modal(getById("sharesModal")).show();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction setMenuVisible(action, visible) {\n  const element = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction setSepVisible(name, visible) {\n  const element = document.querySelector(`#contextMenu [data-sep="${name}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = getById("contextMenu");\n  const items = mode === "item" ? getContextItems() : [];\n  const single = items.length === 1;\n  const item = single ? items[0] : null;\n\n  ["open", "download", "archive", "share", "rename", "move", "delete", "mkdir", "upload", "refresh", "shares"]\n    .forEach(a => setMenuVisible(a, false));\n  setSepVisible("item", false);\n\n  if (mode === "blank") {\n    selectedPaths.clear();\n    syncSelectionUI();\n    setMenuVisible("mkdir", true);\n    setMenuVisible("upload", true);\n    setMenuVisible("refresh", true);\n    setMenuVisible("shares", true);\n  } else if (single && item.type === "dir") {\n    setMenuVisible("open", true);\n    setMenuVisible("archive", true);\n    setMenuVisible("share", true);\n    setMenuVisible("delete", true);\n    setMenuVisible("rename", true);\n  } else if (single && item.type === "file") {\n    setMenuVisible("open", true);\n    setMenuVisible("download", true);\n    setMenuVisible("share", true);\n    setMenuVisible("rename", true);\n    setMenuVisible("move", true);\n    setMenuVisible("delete", true);\n    // Do not show 7z for a single file；the file already has direct download.\n  } else if (items.length > 1) {\n    setMenuVisible("archive", true);\n    setMenuVisible("move", true);\n    setMenuVisible("delete", true);\n  } else {\n    return;\n  }\n\n  const openBtn = menu.querySelector(\'[data-action="open"]\');\n  if (openBtn && single) openBtn.textContent = openActionLabel(item);\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = getById("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\nfunction setupContextMenu() {\n  getById("contextMenu").addEventListener("click", async (e) => {\n    const btn = e.target.closest("button[data-action]");\n    if (!btn) return;\n    const action = btn.dataset.action;\n    const items = getContextItems();\n    hideContextMenu();\n\n    if (action === "mkdir") return mkdirFromContext();\n    if (action === "upload") return uploadFromContext();\n    if (action === "refresh") return loadList();\n    if (action === "shares") return showShares();\n\n    if (!items.length) return;\n\n    if (action === "open" && items.length === 1) openItem(items[0]);\n    if (action === "download" && items.length === 1) downloadItem(items[0].path);\n    if (action === "archive") archiveItems(items);\n    if (action === "share" && items.length === 1) shareItem(items[0]);\n    if (action === "rename" && items.length === 1) renameItem(items[0]);\n    if (action === "move") moveItems(items);\n    if (action === "delete") deleteItems(items);\n  });\n\n  document.addEventListener("click", (e) => {\n    if (!e.target.closest("#contextMenu")) hideContextMenu();\n  });\n\n  getById("filePane").addEventListener("contextmenu", (e) => {\n    if (!e.target.closest(".file-item")) {\n      e.preventDefault();\n      contextTargetPath = null;\n      showContextMenu(e.clientX, e.clientY, "blank");\n    }\n  });\n}\n\nfunction rectsIntersect(a, b) {\n  return !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);\n}\n\nfunction setupDragSelection() {\n  const pane = getById("filePane");\n  const box = getById("selectionBox");\n\n  pane.addEventListener("mousedown", (e) => {\n    if (e.button !== 0) return;\n    if (e.target.closest(".file-item")) return;\n    if (e.target.closest("#contextMenu")) return;\n\n    const startX = e.clientX;\n    const startY = e.clientY;\n    dragState = {startX, startY, moved: false, additive: e.ctrlKey || e.metaKey};\n    if (!dragState.additive) {\n      selectedPaths.clear();\n      syncSelectionUI();\n    }\n\n    box.style.left = `${startX}px`;\n    box.style.top = `${startY}px`;\n    box.style.width = "0px";\n    box.style.height = "0px";\n    box.style.display = "block";\n    e.preventDefault();\n  });\n\n  document.addEventListener("mousemove", (e) => {\n    if (!dragState) return;\n\n    const x1 = Math.min(dragState.startX, e.clientX);\n    const y1 = Math.min(dragState.startY, e.clientY);\n    const x2 = Math.max(dragState.startX, e.clientX);\n    const y2 = Math.max(dragState.startY, e.clientY);\n\n    if (Math.abs(x2 - x1) > 3 || Math.abs(y2 - y1) > 3) {\n      dragState.moved = true;\n    }\n\n    box.style.left = `${x1}px`;\n    box.style.top = `${y1}px`;\n    box.style.width = `${x2 - x1}px`;\n    box.style.height = `${y2 - y1}px`;\n\n    const selectionRect = {left: x1, top: y1, right: x2, bottom: y2};\n    document.querySelectorAll(".file-item").forEach(row => {\n      const r = row.getBoundingClientRect();\n      if (rectsIntersect(selectionRect, r)) {\n        selectedPaths.add(row.dataset.path);\n      } else if (!dragState.additive) {\n        selectedPaths.delete(row.dataset.path);\n      }\n    });\n    syncSelectionUI();\n  });\n\n  document.addEventListener("mouseup", () => {\n    if (!dragState) return;\n    setTimeout(() => { dragState = null; }, 0);\n    box.style.display = "none";\n  });\n}\n\ndocument.addEventListener("keydown", (e) => {\n  if (e.key === "F5") {\n    e.preventDefault();\n    loadList();\n  }\n});\n\ngetById("fileInput").addEventListener("change", uploadSelectedFiles);\n\nsetupContextMenu();\nsetupDragSelection();\nloadList("");\n\n</script>\n</body>\n</html>\n'

EDITOR_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Text Editor</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n  overflow: hidden;\n  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n}\n\n#toolbar {\n  position: fixed;\n  top: 0;\n  left: 0;\n  right: 0;\n  height: 38px;\n  display: flex;\n  align-items: center;\n  gap: 10px;\n  padding: 0 10px;\n  background: #fffaf7;\n  border-bottom: 1px solid #f1b4a2;\n  z-index: 10;\n}\n\n#filename {\n  min-width: 0;\n  font-weight: 700;\n  color: #50322b;\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n#encoding,\n#status {\n  flex: 0 0 auto;\n  font-size: 12px;\n  color: #8a6a62;\n}\n\n#saveBtn,\n#downloadBtn,\n#closeBtn {\n  flex: 0 0 auto;\n  border: 1px solid #e9795f;\n  background: #e9795f;\n  color: #fff;\n  border-radius: 8px;\n  padding: 6px 12px;\n  cursor: pointer;\n}\n\n#saveBtn {\n  margin-left: auto;\n}\n\n#downloadBtn,\n#closeBtn {\n  background: #fff;\n  color: #c95d45;\n}\n\n#editor {\n  position: fixed;\n  top: 38px;\n  left: 0;\n  right: 0;\n  bottom: 0;\n  width: 100%;\n  height: calc(100% - 38px);\n  border: 0;\n  outline: none;\n  resize: none;\n  padding: 16px;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  color: #222;\n  background: rgba(110, 0, 0, 0.06);\n}\n\n#editor::selection {\n  background: rgba(255, 190, 150, 0.55);\n  color: #50322b;\n}\n\n</style>\n</head>\n<body>\n  <div id="toolbar">\n    <span id="filename"></span>\n    <span id="encoding"></span>\n    <span id="status"></span>\n    <button id="saveBtn">Save</button>\n    <button id="downloadBtn">Download</button>\n    <button id="closeBtn" type="button">Close</button>\n  </div>\n  <textarea id="editor" spellcheck="false"></textarea>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\n\nconst editor = document.getElementById("editor");\nconst filename = document.getElementById("filename");\nconst encodingEl = document.getElementById("encoding");\nconst statusEl = document.getElementById("status");\nconst saveBtn = document.getElementById("saveBtn");\nconst downloadBtn = document.getElementById("downloadBtn");\nconst closeBtn = document.getElementById("closeBtn");\n\nlet currentEncoding = "utf-8";\n\nfunction setStatus(text) {\n  statusEl.textContent = text;\n}\n\nfunction closeEditor() {\n  const parentWindow = window.parent;\n  if (parentWindow && parentWindow !== window && parentWindow.bootstrap) {\n    const modalElement = parentWindow.document.getElementById("pageModal");\n    if (modalElement) {\n      const modalInstance = parentWindow.bootstrap.Modal.getInstance(modalElement) || parentWindow.bootstrap.Modal.getOrCreateInstance(modalElement);\n      modalInstance.hide();\n      return;\n    }\n  }\n  window.close();\n}\n\nasync function api(url, options = {}) {\n  const response = await fetch(url, options);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function loadText() {\n  try {\n    const data = await api(`/api/text?path=${encodeURIComponent(path)}`);\n    filename.textContent = data.name;\n    currentEncoding = data.encoding || "utf-8";\n    encodingEl.textContent = `Encoding: ${currentEncoding}`;\n    editor.value = data.text;\n    downloadBtn.onclick = () => {\n      location.href = `/api/download?path=${encodeURIComponent(path)}`;\n    };\n    setStatus("Loaded");\n  } catch (err) {\n    setStatus(err.message);\n    editor.value = "";\n  }\n}\n\nasync function saveText() {\n  try {\n    saveBtn.disabled = true;\n    await api("/api/text", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({\n        path,\n        text: editor.value,\n        encoding: currentEncoding\n      })\n    });\n    setStatus(`Saved ${new Date().toLocaleTimeString()}`);\n  } catch (err) {\n    setStatus(err.message);\n  } finally {\n    saveBtn.disabled = false;\n  }\n}\n\nsaveBtn.onclick = saveText;\ncloseBtn.onclick = closeEditor;\n\neditor.addEventListener("keydown", (e) => {\n  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {\n    e.preventDefault();\n    saveText();\n  }\n});\n\nloadText();\n\n</script>\n</body>\n</html>\n'

VIEWER_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Online Viewer</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody,\n#viewerRoot {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n}\n\nbody {\n  background: #fff;\n  color: #222;\n  overflow: hidden;\n  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;\n}\n\n#viewerRoot {\n  display: flex;\n  align-items: stretch;\n  justify-content: center;\n}\n\n#status {\n  margin: auto;\n  color: #8a6a62;\n  font-size: 14px;\n}\n\n.viewer-media {\n  width: 100%;\n  height: 100%;\n  max-height: 100vh;\n  background: #000;\n}\n\naudio.viewer-media {\n  width: min(900px, 92vw);\n  height: 44px;\n  margin: auto;\n  background: transparent;\n}\n\n.text-view {\n  width: 100%;\n  height: 100%;\n  margin: 0;\n  padding: 16px;\n  overflow: auto;\n  white-space: pre-wrap;\n  word-break: break-word;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  background: #fff;\n  color: #222;\n}\n\n</style>\n</head>\n<body>\n  <main id="viewerRoot">\n    <div id="status">Loading……</div>\n  </main>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\nconst root = document.getElementById("viewerRoot");\n\nasync function jsonApi(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nfunction extOf(name) {\n  const dotIndex = name.lastIndexOf(".");\n  return dotIndex >= 0 ? name.slice(dotIndex).toLowerCase() : "";\n}\n\nasync function init() {\n  try {\n    const list = await jsonApi(`/api/list?path=${encodeURIComponent(parentPath(path))}`);\n    const item = list.items.find(x => x.path === path);\n\n    if (!item) {\n      throw new Error("File does not exist");\n    }\n\n    if (item.media === "video") {\n      root.innerHTML = `<video class="viewer-media" src="/api/media?path=${encodeURIComponent(path)}" controls autoplay></video>`;\n      return;\n    }\n\n    if (item.media === "audio") {\n      root.innerHTML = `<audio class="viewer-media" src="/api/media?path=${encodeURIComponent(path)}" controls autoplay></audio>`;\n      return;\n    }\n\n    if (item.editable) {\n      const data = await jsonApi(`/api/text?path=${encodeURIComponent(path)}`);\n      const pre = document.createElement("pre");\n      pre.className = "text-view";\n      pre.textContent = data.text;\n      root.innerHTML = "";\n      root.appendChild(pre);\n      return;\n    }\n\n    root.innerHTML = `<div id="status">This file does not support online viewing. Please download it.</div>`;\n  } catch (err) {\n    root.innerHTML = `<div id="status">${err.message}</div>`;\n  }\n}\n\nfunction parentPath(p) {\n  const parts = (p || "").split("/").filter(Boolean);\n  parts.pop();\n  return parts.join("/");\n}\n\ninit();\n\n</script>\n</body>\n</html>\n'

SHARE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Shared Folder - {{ name }}</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-header {\n  height: 38px;\n  padding: 6px 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: var(--warm-panel);\n}\n\n.page-modal-header .modal-title {\n  font-size: 13px;\n  color: var(--warm-text);\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: calc(100vh - 38px);\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div id="breadcrumb" class="breadcrumb-flat"></div>\n  <div class="path-meta">\n    <span class="readonly-badge">Read-only Share</span>\n    <span id="countText"></span>\n    <span class="hint">Click to open/download · Right-click actions</span>\n  </div>\n</header>\n\n<main class="file-pane" id="filePane">\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="emptyState" class="empty-state d-none">This shared folder is empty</div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-header page-modal-header">\n        <div class="modal-title" id="pageModalTitle">View</div>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>\n      </div>\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="share-viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Open</button>\n  <button data-action="download">Download</button>\n  <button data-action="refresh">Refresh</button>\n</div>\n\n<script>\n  window.SHARE_TOKEN = "{{ token }}";\n  window.SHARE_ROOT_NAME = "{{ name }}";\n</script>\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPath = null;\nlet currentItemCount = 0;\n\nconst token = window.SHARE_TOKEN;\nconst rootName = window.SHARE_ROOT_NAME || "Share";\nconst singleFileMode = Boolean(window.SHARE_SINGLE_FILE);\nconst getById = (elementId) => document.getElementById(elementId);\n\nfunction showMessage(text, type = "muted") {\n  const element = getById("message");\n  if (!el) return;\n  element.className = `message small text-${type}`;\n  element.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (element.textContent === text) element.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    itemsByPath.clear();\n    selectedPath = null;\n\n    const data = await api(`/s/${token}/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = getById("fileGrid");\n    grid.innerHTML = "";\n    const empty = getById("emptyState");\n    if (empty) empty.classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n\n    if (singleFileMode && data.items.length === 1) {\n      selectedPath = data.items[0].path;\n      syncSelectionUI();\n    }\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction renderBreadcrumb() {\n  const box = getById("breadcrumb");\n  if (!box) return;\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = rootName;\n  root.onclick = () => {\n    if (!singleFileMode) loadList("");\n  };\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const element = getById("countText");\n  if (element) element.textContent = `${currentItemCount} item(s)`;\n}\n\nfunction renderItem(item) {\n  const element = document.createElement("div");\n  element.className = "file-item";\n  element.dataset.path = item.path;\n  element.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Folder"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Folder" : (item.media || (item.editable ? "Text" : fmtSize(item.size)));\n\n  element.append(icon, name, meta);\n\n  element.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  element.onclick = () => {\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  element.oncontextmenu = (e) => {\n    e.preventDefault();\n    selectedPath = item.path;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  return element;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", row.dataset.path === selectedPath);\n  });\n}\n\nfunction selectedItem() {\n  if (selectedPath === null) return null;\n  return itemsByPath.get(selectedPath) || null;\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media || item.editable) {\n    openPageModal(`View - ${item.name}`, `/share-viewer/${token}?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Open";\n  if (item.type === "dir") return "Open";\n  if (item.media) return "Play Online";\n  if (item.editable) return "Online Viewer";\n  return "Download";\n}\n\nfunction openPageModal(title, url) {\n  getById("pageModalTitle").textContent = title;\n  getById("pageFrame").src = url;\n  bootstrap.Modal.getOrCreateInstance(getById("pageModal")).show();\n}\n\ngetById("pageModal").addEventListener("hidden.bs.modal", () => {\n  getById("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  location.href = `/s/${token}/download?path=${encodeURIComponent(path || "")}`;\n}\n\nfunction setMenuVisible(action, visible) {\n  const element = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = getById("contextMenu");\n  ["open", "download", "refresh"].forEach(a => setMenuVisible(a, false));\n\n  const item = selectedItem();\n\n  if (mode === "blank") {\n    setMenuVisible("refresh", true);\n  } else if (item) {\n    setMenuVisible("open", true);\n    if (item.type === "file") setMenuVisible("download", true);\n    const openBtn = menu.querySelector(\'[data-action="open"]\');\n    if (openBtn) openBtn.textContent = openActionLabel(item);\n  } else {\n    return;\n  }\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = getById("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\ngetById("contextMenu").addEventListener("click", (e) => {\n  const btn = e.target.closest("button[data-action]");\n  if (!btn) return;\n\n  const action = btn.dataset.action;\n  const item = selectedItem();\n  hideContextMenu();\n\n  if (action === "refresh") return loadList();\n  if (!item) return;\n\n  if (action === "open") openItem(item);\n  if (action === "download") downloadItem(item.path);\n});\n\ndocument.addEventListener("click", (e) => {\n  if (!e.target.closest("#contextMenu")) hideContextMenu();\n});\n\ngetById("filePane").addEventListener("contextmenu", (e) => {\n  if (!e.target.closest(".file-item")) {\n    e.preventDefault();\n    selectedPath = null;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "blank");\n  }\n});\n\nloadList("");\n\n</script>\n</body>\n</html>\n'

SHARE_FILE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Shared File - {{ name }}</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-header {\n  height: 38px;\n  padding: 6px 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: var(--warm-panel);\n}\n\n.page-modal-header .modal-title {\n  font-size: 13px;\n  color: var(--warm-text);\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: calc(100vh - 38px);\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div class="breadcrumb-flat">\n    <span class="crumb">Shared File</span>\n    <span class="crumb-sep">/</span>\n    <span class="crumb">{{ name }}</span>\n  </div>\n  <div class="path-meta">\n    <span class="readonly-badge">Read-only Share</span>\n  </div>\n</header>\n\n<main class="file-pane single-share-file" id="filePane">\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-header page-modal-header">\n        <div class="modal-title" id="pageModalTitle">View</div>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>\n      </div>\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="share-viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Open</button>\n  <button data-action="download">Download</button>\n</div>\n\n<script>\n  window.SHARE_TOKEN = "{{ token }}";\n  window.SHARE_ROOT_NAME = "{{ name }}";\n  window.SHARE_SINGLE_FILE = true;\n</script>\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPath = null;\nlet currentItemCount = 0;\n\nconst token = window.SHARE_TOKEN;\nconst rootName = window.SHARE_ROOT_NAME || "Share";\nconst singleFileMode = Boolean(window.SHARE_SINGLE_FILE);\nconst getById = (elementId) => document.getElementById(elementId);\n\nfunction showMessage(text, type = "muted") {\n  const element = getById("message");\n  if (!el) return;\n  element.className = `message small text-${type}`;\n  element.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (element.textContent === text) element.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    itemsByPath.clear();\n    selectedPath = null;\n\n    const data = await api(`/s/${token}/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = getById("fileGrid");\n    grid.innerHTML = "";\n    const empty = getById("emptyState");\n    if (empty) empty.classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n\n    if (singleFileMode && data.items.length === 1) {\n      selectedPath = data.items[0].path;\n      syncSelectionUI();\n    }\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction renderBreadcrumb() {\n  const box = getById("breadcrumb");\n  if (!box) return;\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = rootName;\n  root.onclick = () => {\n    if (!singleFileMode) loadList("");\n  };\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const element = getById("countText");\n  if (element) element.textContent = `${currentItemCount} item(s)`;\n}\n\nfunction renderItem(item) {\n  const element = document.createElement("div");\n  element.className = "file-item";\n  element.dataset.path = item.path;\n  element.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Folder"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Folder" : (item.media || (item.editable ? "Text" : fmtSize(item.size)));\n\n  element.append(icon, name, meta);\n\n  element.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  element.onclick = () => {\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  element.oncontextmenu = (e) => {\n    e.preventDefault();\n    selectedPath = item.path;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  return element;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", row.dataset.path === selectedPath);\n  });\n}\n\nfunction selectedItem() {\n  if (selectedPath === null) return null;\n  return itemsByPath.get(selectedPath) || null;\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media || item.editable) {\n    openPageModal(`View - ${item.name}`, `/share-viewer/${token}?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Open";\n  if (item.type === "dir") return "Open";\n  if (item.media) return "Play Online";\n  if (item.editable) return "Online Viewer";\n  return "Download";\n}\n\nfunction openPageModal(title, url) {\n  getById("pageModalTitle").textContent = title;\n  getById("pageFrame").src = url;\n  bootstrap.Modal.getOrCreateInstance(getById("pageModal")).show();\n}\n\ngetById("pageModal").addEventListener("hidden.bs.modal", () => {\n  getById("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  location.href = `/s/${token}/download?path=${encodeURIComponent(path || "")}`;\n}\n\nfunction setMenuVisible(action, visible) {\n  const element = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = getById("contextMenu");\n  ["open", "download", "refresh"].forEach(a => setMenuVisible(a, false));\n\n  const item = selectedItem();\n\n  if (mode === "blank") {\n    setMenuVisible("refresh", true);\n  } else if (item) {\n    setMenuVisible("open", true);\n    if (item.type === "file") setMenuVisible("download", true);\n    const openBtn = menu.querySelector(\'[data-action="open"]\');\n    if (openBtn) openBtn.textContent = openActionLabel(item);\n  } else {\n    return;\n  }\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = getById("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\ngetById("contextMenu").addEventListener("click", (e) => {\n  const btn = e.target.closest("button[data-action]");\n  if (!btn) return;\n\n  const action = btn.dataset.action;\n  const item = selectedItem();\n  hideContextMenu();\n\n  if (action === "refresh") return loadList();\n  if (!item) return;\n\n  if (action === "open") openItem(item);\n  if (action === "download") downloadItem(item.path);\n});\n\ndocument.addEventListener("click", (e) => {\n  if (!e.target.closest("#contextMenu")) hideContextMenu();\n});\n\ngetById("filePane").addEventListener("contextmenu", (e) => {\n  if (!e.target.closest(".file-item")) {\n    e.preventDefault();\n    selectedPath = null;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "blank");\n  }\n});\n\nloadList("");\n\n</script>\n</body>\n</html>\n'

SHARE_VIEWER_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Shared Viewer</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody,\n#viewerRoot {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n}\n\nbody {\n  background: #fff;\n  color: #222;\n  overflow: hidden;\n  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;\n}\n\n#viewerRoot {\n  display: flex;\n  align-items: stretch;\n  justify-content: center;\n}\n\n#status {\n  margin: auto;\n  color: #8a6a62;\n  font-size: 14px;\n}\n\n.viewer-media {\n  width: 100%;\n  height: 100%;\n  max-height: 100vh;\n  background: #000;\n}\n\naudio.viewer-media {\n  width: min(900px, 92vw);\n  height: 44px;\n  margin: auto;\n  background: transparent;\n}\n\n.text-view {\n  width: 100%;\n  height: 100%;\n  margin: 0;\n  padding: 16px;\n  overflow: auto;\n  white-space: pre-wrap;\n  word-break: break-word;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  background: #fff;\n  color: #222;\n}\n\n</style>\n</head>\n<body>\n  <main id="viewerRoot">\n    <div id="status">Loading……</div>\n  </main>\n  <script>\n    window.SHARE_TOKEN = "{{ token }}";\n  </script>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\nconst token = window.SHARE_TOKEN;\nconst root = document.getElementById("viewerRoot");\n\nasync function jsonApi(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function init() {\n  try {\n    const list = await jsonApi(`/s/${token}/api/list?path=${encodeURIComponent(parentPath(path))}`);\n    const item = list.items.find(x => x.path === path) || list.items[0];\n\n    if (!item) {\n      throw new Error("File does not exist");\n    }\n\n    const effectivePath = item.path || "";\n\n    if (item.media === "video") {\n      root.innerHTML = `<video class="viewer-media" src="/s/${token}/media?path=${encodeURIComponent(effectivePath)}" controls autoplay></video>`;\n      return;\n    }\n\n    if (item.media === "audio") {\n      root.innerHTML = `<audio class="viewer-media" src="/s/${token}/media?path=${encodeURIComponent(effectivePath)}" controls autoplay></audio>`;\n      return;\n    }\n\n    if (item.editable) {\n      const data = await jsonApi(`/s/${token}/text?path=${encodeURIComponent(effectivePath)}`);\n      const pre = document.createElement("pre");\n      pre.className = "text-view";\n      pre.textContent = data.text;\n      root.innerHTML = "";\n      root.appendChild(pre);\n      return;\n    }\n\n    root.innerHTML = `<div id="status">This file does not support online viewing. Please download it.</div>`;\n  } catch (err) {\n    root.innerHTML = `<div id="status">${err.message}</div>`;\n  }\n}\n\nfunction parentPath(p) {\n  const parts = (p || "").split("/").filter(Boolean);\n  parts.pop();\n  return parts.join("/");\n}\n\ninit();\n\n</script>\n</body>\n</html>\n'

if __name__ == "__main__":
    print(f"Default seeded username: {DEFAULT_USERNAME}")
    print("Default seeded password: set by FM_PASSWORD, default is admin123")
    print("Login page: http://127.0.0.1:5000/login")
    print("Registration enabled:" , ALLOW_REGISTRATION)
    app.run(host="0.0.0.0", port=5000, debug=True)
