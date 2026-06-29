"""
FastAPI File Manager Simple - Release V1.
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 The FastAPI File Manager Simple contributors.
This program is a single-file LAN file manager built with FastAPI. It provides
browser-based file browsing, uploading, downloading, folder creation, renaming,
deleting, moving, share-link management, 7z archive export, media preview, and
online editing for supported text files. The backend API, HTML, CSS, and
JavaScript are kept in one Python file so the project remains easy to read,
copy, audit, and deploy in small trusted environments.
License:
    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, version 3 only.
    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
    version 3 for more details.
Security note:
    This program is intended for trusted LAN or self-hosted environments. It
    uses HTTP Basic authentication for the management pages and management APIs,
    while generated share links remain public and read-only. For Internet
    exposure, use HTTPS, strong credentials, rate limiting, reverse-proxy
    hardening, regular dependency updates, and server-level access controls.
Install:
    pip install fastapi uvicorn python-multipart charset-normalizer py7zr
Run:
    python fastapi_file_manager_agpl_release_v1.py
Alternative run:
    uvicorn fastapi_file_manager_agpl_release_v1:app --host 0.0.0.0 --port 8000
Environment variables:
    FM_USERNAME          Login username. Default: admin.
    FM_PASSWORD          Login password. Default: admin123.
    FM_AUTH_REALM        HTTP Basic authentication realm. Default: File Manager.
    FM_MAX_UPLOAD_BYTES  Maximum upload size in bytes. Default: 1 GiB.
Thanks:
    Thank you to the open-source community, FastAPI, Starlette, Uvicorn,
    py7zr, charset-normalizer, Bootstrap, and everyone who shares knowledge,
    reports issues, improves documentation, reviews code, and helps small
    projects become safer and more useful for everyone.
    We are also grateful for the help of ChatGPT (OpenAI) and Meta (developers of Llama 4).
"""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from charset_normalizer import from_bytes
import py7zr
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

APPLICATION_DIRECTORY = Path(__file__).resolve().parent  # Application directory.
STORAGE_DIRECTORY = (APPLICATION_DIRECTORY / "storage").resolve()  # Managed file root.
SHARE_METADATA_FILE = APPLICATION_DIRECTORY / "shares.json"  # Persistent share metadata.
CACHE_DIRECTORY = (APPLICATION_DIRECTORY / "cache").resolve()  # Temporary archive cache.
LOGIN_USERNAME = os.environ.get("FM_USERNAME", "admin")  # Basic-auth username.
LOGIN_PASSWORD = os.environ.get("FM_PASSWORD", "admin123")  # Basic-auth password.
BASIC_AUTH_REALM = os.environ.get("FM_AUTH_REALM", "File Manager")  # Browser login dialog realm.
MAXIMUM_UPLOAD_BYTES = int(os.environ.get("FM_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))  # Default: 1 GiB.

TEXT_EXTENSIONS = {
    ".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".csv", ".log", ".ini", ".conf",
    ".py", ".js", ".ts", ".css", ".html", ".htm", ".vue", ".java", ".c", ".cpp", ".h",
    ".hpp", ".go", ".rs", ".php", ".rb", ".sh", ".bat", ".ps1", ".sql", ".toml",
    ".env", ".gitignore", ".dockerignore", ".jsonc", ".lock",
}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".ogg", ".ogv", ".m4v", ".mov", ".mkv"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".ogg", ".oga", ".m4a", ".aac", ".flac", ".webm"}

app = FastAPI(title="FastAPI File Manager Simple", docs_url=None, redoc_url=None, openapi_url=None)  # Main FastAPI application instance.
basic_auth_security = HTTPBasic(realm=BASIC_AUTH_REALM)  # HTTP Basic authentication helper for browser login prompts.
STORAGE_DIRECTORY.mkdir(parents=True, exist_ok=True)  # Ensure storage exists.
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)  # Ensure cache exists.

def require_auth(credentials: HTTPBasicCredentials = Depends(basic_auth_security)) -> str:  # Validate HTTP Basic credentials.
    username_ok = secrets.compare_digest(credentials.username.encode("utf-8"), LOGIN_USERNAME.encode("utf-8"))
    password_ok = secrets.compare_digest(credentials.password.encode("utf-8"), LOGIN_PASSWORD.encode("utf-8"))
    if not (username_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid username or password", headers={"WWW-Authenticate": f'Basic realm="{BASIC_AUTH_REALM}"'})
    return credentials.username

PROTECTED_ROUTE_DEPENDENCIES = [Depends(require_auth)]  # Reusable dependency list for protected management routes.

@app.middleware("http")
async def enforce_upload_size_limit(request: Request, call_next):  # Reject requests whose declared body is too large.
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAXIMUM_UPLOAD_BYTES:
        return JSONResponse({"ok": False, "error": "Request body is too large"}, status_code=413)
    return await call_next(request)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):  # Keep API errors compatible with the embedded frontend.
    return JSONResponse({"ok": False, "error": str(exc.detail)}, status_code=exc.status_code, headers=exc.headers or None)

@app.get("/openapi.json", dependencies=PROTECTED_ROUTE_DEPENDENCIES, include_in_schema=False)
def protected_openapi():  # Serve the OpenAPI schema only after authentication.
    return app.openapi()

@app.get("/docs", dependencies=PROTECTED_ROUTE_DEPENDENCIES, include_in_schema=False)
def protected_docs():  # Serve Swagger UI only after authentication.
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} - Docs")

@app.get("/redoc", dependencies=PROTECTED_ROUTE_DEPENDENCIES, include_in_schema=False)
def protected_redoc():  # Serve ReDoc only after authentication.
    return get_redoc_html(openapi_url="/openapi.json", title=f"{app.title} - ReDoc")

def create_json_response(data: Dict[str, Any], status_code: int = 200) -> JSONResponse:  # Return a JSON response with an explicit status code.
    return JSONResponse(content=data, status_code=status_code)

def render_embedded_template(template: str, **context: Any) -> str:  # Minimal replacement for the small Jinja placeholders in embedded HTML.
    rendered = template
    for key, value in context.items():
        rendered = rendered.replace("{{ " + key + " }}", str(value)).replace("{{" + key + "}}", str(value))
    return rendered

def load_share_records() -> Dict[str, Any]:  # Read share records from disk.
    if not SHARE_METADATA_FILE.exists():
        return {}
    try:
        return json.loads(SHARE_METADATA_FILE.read_text("utf-8"))
    except Exception:
        return {}

def save_share_records(data: Dict[str, Any]) -> None:  # Atomically save share records.
    temporary_share_file = SHARE_METADATA_FILE.with_suffix(".tmp")
    temporary_share_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    temporary_share_file.replace(SHARE_METADATA_FILE)

def resolve_storage_path(relative_path: str | None = "") -> Path:  # Resolve paths inside STORAGE_DIRECTORY only.
    relative_path = (relative_path or "").strip().lstrip("/\\")
    target = (STORAGE_DIRECTORY / relative_path).resolve()
    try:
        target.relative_to(STORAGE_DIRECTORY)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")
    return target

def relative_path_from_storage_root(path: Path) -> str:  # Convert an absolute path to a storage-relative path.
    return path.resolve().relative_to(STORAGE_DIRECTORY).as_posix()

def path_is_inside_directory(child: Path, parent: Path) -> bool:  # Check path containment.
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False

def get_share_or_404(token: str) -> Dict[str, Any]:  # Load a valid share or abort.
    shares = load_share_records()
    share = shares.get(token)
    if not share:
        raise HTTPException(status_code=404, detail="Share does not exist or has been revoked")
    root = resolve_storage_path(share.get("path", ""))
    if not root.exists():
        raise HTTPException(status_code=404, detail="Shared source file does not exist")
    share["token"] = token
    share["root_abs"] = root
    return share

def resolve_shared_path(share: Dict[str, Any], relative_path: str | None = "") -> Path:  # Resolve read-only share paths.
    root = share["root_abs"]
    if root.is_file():
        target = root
    else:
        relative_path = (relative_path or "").strip().lstrip("/\\")
        target = (root / relative_path).resolve()
    if not path_is_inside_directory(target, root):
        raise HTTPException(status_code=403, detail="Access outside the shared directory is not allowed")
    return target

def entry_to_dict(path: Path) -> Dict[str, Any]:  # Serialize a managed file or folder.
    stat = path.stat()
    is_file = path.is_file()
    return {
        "name": path.name,
        "path": relative_path_from_storage_root(path),
        "type": "dir" if path.is_dir() else "file",
        "size": stat.st_size if is_file else None,
        "modified": int(stat.st_mtime),
        "media": media_type_for_file(path),
        "editable": is_text_file(path),
    }

def shared_entry_to_dict(path: Path, root: Path) -> Dict[str, Any]:  # Serialize a shared file or folder.
    stat = path.stat()
    shared_relative_path = "" if path.resolve() == root.resolve() else path.resolve().relative_to(root.resolve()).as_posix()
    return {
        "name": path.name,
        "path": shared_relative_path,
        "type": "dir" if path.is_dir() else "file",
        "size": stat.st_size if path.is_file() else None,
        "modified": int(stat.st_mtime),
        "media": media_type_for_file(path),
        "editable": is_text_file(path),
    }

def media_type_for_file(path: Path) -> Optional[str]:  # Detect browser-playable media by extension.
    if not path.is_file():
        return None
    suffix = path.suffix.lower()
    if suffix in VIDEO_EXTENSIONS:
        return "video"
    if suffix in AUDIO_EXTENSIONS:
        return "audio"
    return None

def is_text_file(path: Path) -> bool:  # Detect editable text files by extension.
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

def list_dir_payload(current_directory: Path) -> Dict[str, Any]:  # Build a management directory listing payload.
    if not current_directory.exists():
        return {"ok": False, "error": "Path does not exist"}  # Report a missing directory.
    if not current_directory.is_dir():
        return {"ok": False, "error": "Not a directory"}  # Reject file paths for directory listings.

    directory_entries = []  # Store serialized child folders.
    file_entries = []  # Store serialized child files.

    for child_path in current_directory.iterdir():  # Scan only the selected directory level.
        if child_path.name.startswith("."):
            continue  # Hide dotfiles and dot-directories from the browser UI.
        try:
            child_entry = entry_to_dict(child_path)  # Convert the child path to a JSON-safe dictionary.
        except OSError:
            continue  # Skip files that disappear or cannot be stat-read during scanning.
        if child_path.is_dir():
            directory_entries.append(child_entry)  # Keep directories before files in the final listing.
        else:
            file_entries.append(child_entry)  # Keep files after directories in the final listing.

    directory_entries.sort(key=lambda entry: entry["name"].lower())  # Sort folders by case-insensitive name.
    file_entries.sort(key=lambda entry: entry["name"].lower())  # Sort files by case-insensitive name.

    parent_directory = ""  # Root has no parent path in the UI.
    if current_directory != STORAGE_DIRECTORY:
        parent_directory = relative_path_from_storage_root(current_directory.parent)  # Compute the storage-relative parent.

    current_directory_relative_path = ""  # Root is represented by an empty path.
    if current_directory != STORAGE_DIRECTORY:
        current_directory_relative_path = relative_path_from_storage_root(current_directory)  # Compute the current relative path.

    return {
        "ok": True,
        "cwd": current_directory_relative_path,
        "parent": parent_directory,
        "items": directory_entries + file_entries,
    }

def list_shared_dir_payload(current_directory: Path, share_root: Path) -> Dict[str, Any]:  # Build a read-only shared directory listing payload.
    if not current_directory.exists():
        return {"ok": False, "error": "Path does not exist"}  # Report a missing shared directory.
    if not current_directory.is_dir():
        return {"ok": False, "error": "Not a directory"}  # Reject file paths for directory listings.

    directory_entries = []  # Store serialized shared child folders.
    file_entries = []  # Store serialized shared child files.

    for child_path in current_directory.iterdir():  # Scan only the selected shared directory level.
        if child_path.name.startswith("."):
            continue  # Hide dotfiles and dot-directories from public shares.
        try:
            child_entry = shared_entry_to_dict(child_path, share_root)  # Serialize paths relative to the share root.
        except OSError:
            continue  # Skip paths that cannot be read safely during scanning.
        if child_path.is_dir():
            directory_entries.append(child_entry)  # Keep shared directories before shared files.
        else:
            file_entries.append(child_entry)  # Keep shared files after shared directories.

    directory_entries.sort(key=lambda entry: entry["name"].lower())  # Sort folders by case-insensitive name.
    file_entries.sort(key=lambda entry: entry["name"].lower())  # Sort files by case-insensitive name.

    current_share_path = ""  # The share root is represented by an empty path.
    if current_directory.resolve() != share_root.resolve():
        current_share_path = current_directory.resolve().relative_to(share_root.resolve()).as_posix()  # Compute path inside the share.

    parent_share_path = ""  # The share root has no parent path exposed to visitors.
    if current_directory.resolve() != share_root.resolve():
        parent_path = current_directory.parent.resolve()  # Resolve the parent folder safely.
        if parent_path != share_root.resolve():
            parent_share_path = parent_path.relative_to(share_root.resolve()).as_posix()  # Expose only a share-relative parent.

    return {
        "ok": True,
        "cwd": current_share_path,
        "parent": parent_share_path,
        "root_name": share_root.name,
        "items": directory_entries + file_entries,
    }

def partial_file_response(file_path: Path, request: Request):  # Stream a file with optional HTTP Range support.
    file_size = file_path.stat().st_size  # Read the total file size for Range calculations.
    range_header = request.headers.get("Range")  # Browsers send this header when seeking in media files.
    media_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"  # Guess a safe response MIME type.

    if not range_header:
        return FileResponse(file_path, media_type=media_type)  # Send the whole file when no range is requested.

    try:
        range_unit, range_value = range_header.split("=", 1)  # Split strings like bytes=0-1023.
        if range_unit != "bytes":
            raise ValueError  # Only byte ranges are valid for this endpoint.
        start_text, end_text = range_value.split("-", 1)  # Extract the optional start and end byte offsets.
        start_byte = int(start_text) if start_text else 0  # Empty start means beginning of the file.
        end_byte = int(end_text) if end_text else file_size - 1  # Empty end means end of the file.
        end_byte = min(end_byte, file_size - 1)  # Never read beyond the end of the file.
        if start_byte > end_byte:
            raise ValueError  # Reject inverted or invalid ranges.
    except ValueError:
        return Response(status_code=416)  # HTTP 416 means the requested range is not satisfiable.

    response_length = end_byte - start_byte + 1  # Count the exact bytes that will be streamed.

    def stream_file_chunks():  # Yield chunks so large media files do not load fully into memory.
        with file_path.open("rb") as file_handle:
            file_handle.seek(start_byte)  # Start reading from the requested byte offset.
            remaining_bytes = response_length  # Track how many bytes still need to be sent.
            chunk_size = 1024 * 1024  # Stream up to 1 MiB per iteration.
            while remaining_bytes > 0:
                chunk = file_handle.read(min(chunk_size, remaining_bytes))  # Read only the remaining requested range.
                if not chunk:
                    break  # Stop if the file unexpectedly ends.
                remaining_bytes -= len(chunk)  # Reduce the remaining byte count.
                yield chunk  # Send the chunk to the client.

    return StreamingResponse(
        stream_file_chunks(),
        status_code=206,
        media_type=media_type,
        headers={
            "Content-Range": f"bytes {start_byte}-{end_byte}/{file_size}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(response_length),
        },
    )

def unique_archive_name(prefix: str = "download") -> str:  # Create a unique archive filename.
    safe_name_characters = []  # Store sanitized filename characters.
    for character in prefix:  # Check every character instead of using a compressed expression.
        if character.isalnum() or character in "-_.":  # Keep safe filename characters unchanged.
            safe_name_characters.append(character)  # Add an allowed character to the output name.
        else:
            safe_name_characters.append("_")  # Replace unsafe characters with an underscore.
    safe_archive_prefix = "".join(safe_name_characters).strip("._")  # Remove dangerous leading/trailing dots.
    if not safe_archive_prefix:
        safe_archive_prefix = "download"  # Use a stable fallback when the prefix becomes empty.
    timestamp = int(time.time())  # Add seconds to make the archive name easier to sort.
    random_suffix = uuid.uuid4().hex[:8]  # Add randomness to prevent filename collisions.
    return f"{safe_archive_prefix}_{timestamp}_{random_suffix}.7z"  # Return a safe 7z archive filename.

def cleanup_old_cache(max_age_seconds: int = 24 * 3600) -> None:  # Remove expired cached archives.
    now = time.time()
    for cache_file in CACHE_DIRECTORY.iterdir():
        try:
            if cache_file.is_file() and now - cache_file.stat().st_mtime > max_age_seconds:
                cache_file.unlink()
        except OSError:
            pass

def make_7z_archive(paths: list[Path], base_dir: Path, archive_name: str) -> Path:  # Package selected files as 7z.
    cleanup_old_cache()
    archive_path = (CACHE_DIRECTORY / archive_name).resolve()
    try:
        archive_path.relative_to(CACHE_DIRECTORY)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid archive name")
    filters = [{"id": py7zr.FILTER_LZMA2, "preset": 9 | py7zr.PRESET_EXTREME}]
    with py7zr.SevenZipFile(archive_path, "w", filters=filters) as archive:
        used_names = set()
        for source_path in paths:
            source_path = source_path.resolve()
            if not source_path.exists():
                continue
            if source_path == STORAGE_DIRECTORY:
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
            if source_path.is_dir():  # Add a directory recursively when the selected item is a folder.
                archive.writeall(source_path, archive_name_in_package)  # Preserve nested files inside the archive.
            else:
                archive.write(source_path, archive_name_in_package)  # Add a single file to the archive.
    return archive_path

@app.get("/", response_class=HTMLResponse, dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Main file manager page.
def index():
    return HTMLResponse(INDEX_HTML)

@app.get("/editor", response_class=HTMLResponse, dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Text editor iframe page.
def editor_page():
    return HTMLResponse(EDITOR_HTML)

@app.get("/viewer", response_class=HTMLResponse, dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Media/text viewer iframe page.
def viewer_page():
    return HTMLResponse(VIEWER_HTML)

@app.get("/share-viewer/{token}", response_class=HTMLResponse)
def share_viewer_page(token: str):
    get_share_or_404(token)
    return HTMLResponse(render_embedded_template(SHARE_VIEWER_HTML, token=token))

@app.get("/api/list", dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # List files in a directory.
def api_list(path: str = ""):
    current = resolve_storage_path(path)
    payload = list_dir_payload(current)
    if not payload["ok"]:
        return create_json_response(payload, 404)
    return create_json_response(payload)

@app.post("/api/mkdir", dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Create a folder.
def api_mkdir(data: Dict[str, Any] = Body(default_factory=dict)):
    parent = resolve_storage_path(data.get("path", ""))
    name = (data.get("name") or "").strip()
    if not parent.exists() or not parent.is_dir():
        return create_json_response({"ok": False, "error": "Parent directory does not exist"}, 404)
    if not name:
        return create_json_response({"ok": False, "error": "Folder name cannot be empty"}, 400)
    if "/" in name or "\\" in name or name in {".", ".."}:
        return create_json_response({"ok": False, "error": "Invalid folder name"}, 400)
    parent_relative_path = relative_path_from_storage_root(parent) if parent != STORAGE_DIRECTORY else ""
    target = resolve_storage_path(f"{parent_relative_path}/{name}" if parent_relative_path else name)
    if target.exists():
        return create_json_response({"ok": False, "error": "Folder already exists"}, 409)
    target.mkdir(parents=False)
    return create_json_response({"ok": True, "item": entry_to_dict(target)})

@app.post("/api/upload", dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Upload selected files.
def api_upload(path: str = Form(""), files: list[UploadFile] = File(default=[])):
    target_dir = resolve_storage_path(path)
    if not target_dir.exists() or not target_dir.is_dir():
        return create_json_response({"ok": False, "error": "Upload target folder does not exist"}, 404)
    if not files:
        return create_json_response({"ok": False, "error": "No file selected"}, 400)
    saved = []
    for uploaded_file in files:
        if not uploaded_file.filename:
            continue
        filename = Path(uploaded_file.filename).name.replace("/", "_").replace("\\", "_")
        if filename in {"", ".", ".."}:
            continue
        parent_relative_path = relative_path_from_storage_root(target_dir) if target_dir != STORAGE_DIRECTORY else ""
        dest = resolve_storage_path(f"{parent_relative_path}/{filename}" if parent_relative_path else filename)
        if dest.exists():
            stem = dest.stem
            suffix = dest.suffix
            duplicate_index = 1
            while dest.exists():
                new_name = f"{stem} ({duplicate_index}){suffix}"
                dest = resolve_storage_path(f"{parent_relative_path}/{new_name}" if parent_relative_path else new_name)
                duplicate_index += 1
        with dest.open("wb") as output_file:
            shutil.copyfileobj(uploaded_file.file, output_file)
        saved.append(entry_to_dict(dest))
    return create_json_response({"ok": True, "saved": saved})

@app.get("/api/download", dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Download a file.
def api_download(path: str = ""):
    file_path = resolve_storage_path(path)
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "File does not exist"}, 404)
    return FileResponse(file_path, filename=file_path.name, media_type=mimetypes.guess_type(file_path.name)[0] or "application/octet-stream")

@app.get("/api/media", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_media(request: Request, path: str = ""):
    file_path = resolve_storage_path(path)
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "File does not exist"}, 404)
    if media_type_for_file(file_path) not in {"video", "audio"}:
        return create_json_response({"ok": False, "error": "This file extension does not support online playback"}, 400)
    return partial_file_response(file_path, request)

@app.get("/api/text", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_text(path: str = ""):
    file_path = resolve_storage_path(path)
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "File does not exist"}, 404)
    if not is_text_file(file_path):
        return create_json_response({"ok": False, "error": "This file type does not support online editing"}, 400)
    raw = file_path.read_bytes()
    encoding = detect_encoding(raw)
    try:
        text = raw.decode(encoding)
    except Exception:
        text = raw.decode("utf-8", errors="replace")
        encoding = "utf-8"
    return create_json_response({"ok": True, "path": relative_path_from_storage_root(file_path), "name": file_path.name, "encoding": encoding, "text": text})

@app.post("/api/text", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_text_save(data: Dict[str, Any] = Body(default_factory=dict)):
    file_path = resolve_storage_path(data.get("path", ""))
    text = data.get("text", "")
    encoding = data.get("encoding") or "utf-8"
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "File does not exist"}, 404)
    if not is_text_file(file_path):
        return create_json_response({"ok": False, "error": "This file type does not support online editing"}, 400)
    try:
        file_path.write_bytes(str(text).encode(encoding))
    except LookupError:
        return create_json_response({"ok": False, "error": f"Unsupported encoding: {encoding}"}, 400)
    except UnicodeEncodeError:
        return create_json_response({"ok": False, "error": f"The current content cannot be saved with {encoding} encoding"}, 400)
    return create_json_response({"ok": True, "encoding": encoding, "saved_at": int(time.time())})

@app.post("/api/delete", dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Delete a file or folder.
def api_delete(data: Dict[str, Any] = Body(default_factory=dict)):
    file_path = resolve_storage_path(data.get("path", ""))
    if file_path == STORAGE_DIRECTORY:
        return create_json_response({"ok": False, "error": "Cannot delete the root directory"}, 400)
    if not file_path.exists():
        return create_json_response({"ok": False, "error": "Path does not exist"}, 404)
    if file_path.is_dir():
        shutil.rmtree(file_path)
    else:
        file_path.unlink()
    return create_json_response({"ok": True})

@app.post("/api/move", dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Move files or folders.
def api_move(data: Dict[str, Any] = Body(default_factory=dict)):
    source_values = data.get("src")
    destination_value = data.get("dst", "")
    move_into_directory = bool(data.get("into_directory"))
    if not source_values and source_values != "":
        return create_json_response({"ok": False, "error": "Source path is required"}, 400)
    if isinstance(source_values, str):
        source_values = [source_values]
    if not isinstance(source_values, list) or not source_values:
        return create_json_response({"ok": False, "error": "Source path is required"}, 400)
    destination_path = resolve_storage_path(destination_value)
    if len(source_values) > 1:
        move_into_directory = True
    if destination_path.exists() and destination_path.is_dir():
        move_into_directory = True
    if move_into_directory and (not destination_path.exists() or not destination_path.is_dir()):
        return create_json_response({"ok": False, "error": "Target folder does not exist"}, 404)
    planned_moves = []
    for source_value in source_values:
        source_path = resolve_storage_path(source_value)
        if source_path == STORAGE_DIRECTORY:
            return create_json_response({"ok": False, "error": "Cannot move the root directory"}, 400)
        if not source_path.exists():
            return create_json_response({"ok": False, "error": "Source path does not exist"}, 404)
        target_path = destination_path / source_path.name if move_into_directory else destination_path
        if target_path.exists():
            return create_json_response({"ok": False, "error": "Target path already exists"}, 409)
        if source_path.is_dir() and path_is_inside_directory(target_path, source_path):
            return create_json_response({"ok": False, "error": "Cannot move a folder into itself"}, 400)
        planned_moves.append((source_path, target_path))
    moved_items = []
    for source_path, target_path in planned_moves:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source_path), str(target_path))
        moved_items.append(entry_to_dict(target_path))
    return create_json_response({"ok": True, "item": moved_items[0] if len(moved_items) == 1 else None, "items": moved_items})

@app.post("/api/rename", dependencies=PROTECTED_ROUTE_DEPENDENCIES)  # Rename a file or folder.
def api_rename(data: Dict[str, Any] = Body(default_factory=dict)):
    source_path = resolve_storage_path(data.get("path", ""))
    new_name = (data.get("name") or "").strip()
    if source_path == STORAGE_DIRECTORY:
        return create_json_response({"ok": False, "error": "Cannot rename the root directory"}, 400)
    if not source_path.exists():
        return create_json_response({"ok": False, "error": "Path does not exist"}, 404)
    if not new_name or "/" in new_name or "\\" in new_name or new_name in {".", ".."}:
        return create_json_response({"ok": False, "error": "Invalid name"}, 400)
    destination_path = source_path.with_name(new_name).resolve()
    try:
        destination_path.relative_to(STORAGE_DIRECTORY)
    except ValueError:
        return create_json_response({"ok": False, "error": "Invalid path"}, 400)
    if destination_path.exists():
        return create_json_response({"ok": False, "error": "Target name already exists"}, 409)
    source_path.rename(destination_path)
    return create_json_response({"ok": True, "item": entry_to_dict(destination_path)})

@app.post("/api/share", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_create_share(request: Request, data: Dict[str, Any] = Body(default_factory=dict)):
    file_path = resolve_storage_path(data.get("path", ""))
    if not file_path.exists():
        return create_json_response({"ok": False, "error": "Share path does not exist"}, 404)
    token = secrets.token_urlsafe(24)
    shares = load_share_records()
    shares[token] = {
        "path": relative_path_from_storage_root(file_path) if file_path != STORAGE_DIRECTORY else "",
        "name": file_path.name if file_path != STORAGE_DIRECTORY else "Root",
        "type": "dir" if file_path.is_dir() else "file",
        "created": int(time.time()),
    }
    save_share_records(shares)
    return create_json_response({"ok": True, "token": token, "url": str(request.url_for("share_page", token=token)), "share": shares[token]})

@app.get("/api/shares", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_list_shares(request: Request):
    shares = load_share_records()
    out = []
    for token, share in shares.items():
        share_item = dict(share)
        share_item["token"] = token
        share_item["url"] = str(request.url_for("share_page", token=token))
        out.append(share_item)
    out.sort(key=lambda share_item: share_item.get("created", 0), reverse=True)
    return create_json_response({"ok": True, "shares": out})

@app.delete("/api/share/{token}", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_delete_share(token: str):
    shares = load_share_records()
    if token in shares:
        shares.pop(token)
        save_share_records(shares)
    return create_json_response({"ok": True})

@app.get("/share/{token}", response_class=HTMLResponse)
def share_page(token: str):
    share = get_share_or_404(token)
    if share["root_abs"].is_file():
        return HTMLResponse(render_embedded_template(SHARE_FILE_HTML, token=token, name=share["root_abs"].name))
    return HTMLResponse(render_embedded_template(SHARE_HTML, token=token, name=share["root_abs"].name))

@app.get("/s/{token}/api/list")
def shared_api_list(token: str, path: str = ""):
    share = get_share_or_404(token)
    root = share["root_abs"]
    if root.is_file():
        return create_json_response({"ok": True, "cwd": "", "parent": "", "root_name": root.name, "items": [shared_entry_to_dict(root, root)]})
    current = resolve_shared_path(share, path)
    payload = list_shared_dir_payload(current, root)
    if not payload["ok"]:
        return create_json_response(payload, 404)
    return create_json_response(payload)

@app.get("/s/{token}/text")
def shared_text(token: str, path: str = ""):
    share = get_share_or_404(token)
    file_path = resolve_shared_path(share, path)
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "File does not exist"}, 404)
    if not is_text_file(file_path):
        return create_json_response({"ok": False, "error": "This file type does not support online viewing"}, 400)
    raw = file_path.read_bytes()
    encoding = detect_encoding(raw)
    try:
        text = raw.decode(encoding)
    except Exception:
        text = raw.decode("utf-8", errors="replace")
        encoding = "utf-8"
    return create_json_response({"ok": True, "path": shared_entry_to_dict(file_path, share["root_abs"])["path"], "name": file_path.name, "encoding": encoding, "text": text})

@app.get("/s/{token}/download")
def shared_download(token: str, path: str = ""):
    share = get_share_or_404(token)
    file_path = resolve_shared_path(share, path)
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "File does not exist"}, 404)
    return FileResponse(file_path, filename=file_path.name, media_type=mimetypes.guess_type(file_path.name)[0] or "application/octet-stream")

@app.get("/s/{token}/media")
def shared_media(request: Request, token: str, path: str = ""):
    share = get_share_or_404(token)
    file_path = resolve_shared_path(share, path)
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "File does not exist"}, 404)
    if media_type_for_file(file_path) not in {"video", "audio"}:
        return create_json_response({"ok": False, "error": "This file extension does not support online playback"}, 400)
    return partial_file_response(file_path, request)

@app.post("/api/archive", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_create_archive(data: Dict[str, Any] = Body(default_factory=dict)):
    relative_paths = data.get("paths") or []
    if isinstance(relative_paths, str):
        relative_paths = [relative_paths]
    if not relative_paths:
        return create_json_response({"ok": False, "error": "Select at least one file or folder"}, 400)
    resolved_paths = []  # Store validated absolute paths before creating the archive.
    for requested_relative_path in relative_paths:
        resolved_path = resolve_storage_path(requested_relative_path)  # Keep every selected path inside the storage directory.
        if not resolved_path.exists():
            return create_json_response({"ok": False, "error": f"Path does not exist: {requested_relative_path}"}, 404)
        resolved_paths.append(resolved_path)  # Save the validated path for archive creation.
    if len(resolved_paths) == 1:
        archive_prefix = resolved_paths[0].name or "storage"  # Use the selected item name for a single-item archive.
        archive_base_directory = resolved_paths[0].parent if resolved_paths[0] != STORAGE_DIRECTORY else STORAGE_DIRECTORY
    else:
        archive_prefix = "selected"  # Use a neutral name for multi-selection archives.
        current_directory_relative_path = data.get("cwd", "")  # Preserve relative names from the current browser folder.
        archive_base_directory = resolve_storage_path(current_directory_relative_path)  # Resolve the archive base safely.
        if not archive_base_directory.exists() or not archive_base_directory.is_dir():
            archive_base_directory = STORAGE_DIRECTORY  # Fall back to the storage root when the browser path is invalid.
    archive_name = unique_archive_name(archive_prefix)  # Generate a collision-resistant archive filename.
    archive_path = make_7z_archive(resolved_paths, archive_base_directory, archive_name)  # Build the 7z archive in cache.
    return create_json_response({"ok": True, "archive": archive_name, "size": archive_path.stat().st_size, "url": f"/api/archive/{archive_name}"})

@app.get("/api/archive/{name}", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_download_archive(name: str):
    if "/" in name or "\\" in name or not name.endswith(".7z"):
        return create_json_response({"ok": False, "error": "Invalid archive name"}, 400)
    file_path = (CACHE_DIRECTORY / name).resolve()
    try:
        file_path.relative_to(CACHE_DIRECTORY)
    except ValueError:
        return create_json_response({"ok": False, "error": "Invalid path"}, 400)
    if not file_path.exists() or not file_path.is_file():
        return create_json_response({"ok": False, "error": "Archive does not exist or has been cleaned"}, 404)
    return FileResponse(file_path, filename=name, media_type="application/x-7z-compressed")
@app.get("/api/info", dependencies=PROTECTED_ROUTE_DEPENDENCIES)
def api_info():
    return create_json_response({"ok": True, "storage_root": str(STORAGE_DIRECTORY), "cache_root": str(CACHE_DIRECTORY), "max_upload_bytes": MAXIMUM_UPLOAD_BYTES, "framework": "FastAPI", "auth": "http_basic_enabled"})
# =========================
# Embedded frontend assets
# =========================
# The frontend is intentionally embedded to keep this project deployable as one file.
INDEX_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>LAN File Manager</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: 100vh;\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div id="breadcrumb" class="breadcrumb-flat"></div>\n  <div class="path-meta">\n    <span id="countText"></span>\n    <span class="hint">Click to open/download · Ctrl multi-select · Right-click actions</span>\n  </div>\n</header>\n\n<main class="file-pane" id="filePane">\n  <input id="fileInput" class="hidden-file-input" type="file" multiple>\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="emptyState" class="empty-state d-none">This folder is empty. Right-click empty space to create a folder or upload files.</div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div class="modal fade" id="sharesModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-lg modal-dialog-centered">\n    <div class="modal-content share-list-modal">\n      <div class="modal-header">\n        <h5 class="modal-title">Share List</h5>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>\n      </div>\n      <div class="modal-body">\n        <div id="sharesList" class="small"></div>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="selectionBox"></div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Open</button>\n  <button data-action="download">Download</button>\n  <button data-action="archive">Download as 7z archive</button>\n  <button data-action="share">Share</button>\n  <hr data-sep="item">\n  <button data-action="rename">Rename</button>\n  <button data-action="move">Move</button>\n  <button data-action="delete" class="danger">Delete</button>\n\n  <button data-action="mkdir">New Folder</button>\n  <button data-action="upload">Upload Files</button>\n  <button data-action="refresh">Refresh</button>\n  <button data-action="shares">Share List</button>\n</div>\n\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPaths = new Set();\nlet contextTargetPath = null;\nlet dragState = null;\nlet currentItemCount = 0;\nlet activePageModal = null;\n\nconst getById = (elementId) => document.getElementById(elementId);\n\nfunction showMessage(text, type = "muted") {\n  const element = getById("message");\n  element.className = `message small text-${type}`;\n  element.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (element.textContent === text) element.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url, options = {}) {\n  const response = await fetch(url, options);\n  const contentType = response.headers.get("content-type") || "";\n\n  let data = null;\n  if (contentType.includes("application/json")) {\n    data = await response.json();\n  }\n\n  if (!response.ok || (data && data.ok === false)) {\n    throw new Error((data && data.error) || `Request failed: ${response.status}`);\n  }\n\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    selectedPaths.clear();\n    itemsByPath.clear();\n\n    const data = await api(`/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = getById("fileGrid");\n    grid.innerHTML = "";\n    getById("emptyState").classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\n\nfunction dragPathsFromEvent(event) {\n  const dragData = event.dataTransfer.getData("application/json") || event.dataTransfer.getData("text/plain") || "[]";\n  const paths = JSON.parse(dragData);\n  return Array.isArray(paths) ? paths : [paths];\n}\n\nasync function movePathsToDirectory(paths, targetDirectory) {\n  const sourcePaths = paths.filter(path => path !== targetDirectory);\n  if (!sourcePaths.length) return;\n\n  try {\n    await api("/api/move", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({src: sourcePaths, dst: targetDirectory, into_directory: true})\n    });\n    showMessage("Move complete", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction enableDirectoryDrop(element, targetDirectory) {\n  element.ondragover = (event) => {\n    event.preventDefault();\n    event.dataTransfer.dropEffect = "move";\n  };\n\n  element.ondrop = (event) => {\n    event.preventDefault();\n    event.stopPropagation();\n    movePathsToDirectory(dragPathsFromEvent(event), targetDirectory);\n  };\n}\n\nfunction renderBreadcrumb() {\n  const box = getById("breadcrumb");\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = "Root";\n  root.onclick = () => loadList("");\n  enableDirectoryDrop(root, "");\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    enableDirectoryDrop(crumb, target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const count = selectedPaths.size;\n  getById("countText").textContent = count > 0 ? `Selected ${count}  item(s)` : `${currentItemCount} item(s)`;\n}\n\nfunction renderItem(item) {\n  const element = document.createElement("div");\n  element.className = "file-item";\n  element.dataset.path = item.path;\n  element.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Folder"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Folder" : (item.media || (item.editable ? "Text" : fmtSize(item.size)));\n\n  element.append(icon, name, meta);\n\n  element.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  element.onclick = (e) => {\n    if (dragState && dragState.moved) return;\n\n    // Ctrl/Cmd/Shift reserved for multi-select；A normal left click performs the most direct action:\n    // folders open, files download directly.\n    if (e.ctrlKey || e.metaKey) {\n      toggleSelect(item.path);\n      return;\n    }\n\n    if (e.shiftKey) {\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n      return;\n    }\n\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  element.oncontextmenu = (e) => {\n    e.preventDefault();\n    contextTargetPath = item.path;\n    if (!selectedPaths.has(item.path)) {\n      selectedPaths.clear();\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n    }\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  element.draggable = true;\n  element.ondragstart = (e) => {\n    if (!selectedPaths.has(item.path)) {\n      selectedPaths.clear();\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n    }\n    const paths = [...selectedPaths];\n    e.dataTransfer.effectAllowed = "move";\n    e.dataTransfer.setData("application/json", JSON.stringify(paths));\n    e.dataTransfer.setData("text/plain", JSON.stringify(paths));\n  };\n\n  if (item.type === "dir") {\n    enableDirectoryDrop(element, item.path);\n  }\n\n  return element;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction getSelectedItems() {\n  return [...selectedPaths].map(selectedPath => itemsByPath.get(selectedPath)).filter(Boolean);\n}\n\nfunction getContextItems() {\n  const items = getSelectedItems();\n  if (items.length) return items;\n  if (contextTargetPath && itemsByPath.has(contextTargetPath)) return [itemsByPath.get(contextTargetPath)];\n  return [];\n}\n\nfunction toggleSelect(path) {\n  if (selectedPaths.has(path)) selectedPaths.delete(path);\n  else selectedPaths.add(path);\n  syncSelectionUI();\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", selectedPaths.has(row.dataset.path));\n  });\n  updateCountText();\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media) {\n    openPageModal(`Play - ${item.name}`, `/viewer?path=${encodeURIComponent(item.path)}`);\n  } else if (item.editable) {\n    openPageModal("", `/editor?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Open";\n  if (item.type === "dir") return "Open";\n  if (item.media === "video") return "Play Online";\n  if (item.media === "audio") return "Play Online";\n  if (item.editable) return "Edit/View Online";\n  return "Download";\n}\n\nfunction openPageModal(title, url) {\n  getById("pageFrame").src = url;\n  activePageModal = bootstrap.Modal.getOrCreateInstance(getById("pageModal"));\n  activePageModal.show();\n}\n\ngetById("pageModal").addEventListener("hidden.bs.modal", () => {\n  getById("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  window.location.href = `/api/download?path=${encodeURIComponent(path)}`;\n}\n\nasync function mkdirFromContext() {\n  const name = prompt("New folder name:");\n  if (!name || !name.trim()) return;\n\n  try {\n    await api("/api/mkdir", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: cwd, name: name.trim()})\n    });\n    showMessage("Folder created", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction uploadFromContext() {\n  getById("fileInput").click();\n}\n\nasync function uploadSelectedFiles() {\n  const input = getById("fileInput");\n  if (!input.files.length) return;\n\n  const form = new FormData();\n  form.append("path", cwd);\n  for (const file of input.files) {\n    form.append("files", file);\n  }\n\n  try {\n    await api("/api/upload", {\n      method: "POST",\n      body: form\n    });\n    input.value = "";\n    showMessage("Upload complete", "success");\n    await loadList();\n  } catch (err) {\n    input.value = "";\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function deleteItems(items) {\n  if (!items.length) return;\n  const ok = confirm(`Delete selected ${items.length} item(s)? All contents inside folders will be deleted.`);\n  if (!ok) return;\n\n  try {\n    for (const item of items) {\n      await api("/api/delete", {\n        method: "POST",\n        headers: {"Content-Type": "application/json"},\n        body: JSON.stringify({path: item.path})\n      });\n    }\n    showMessage("Delete complete", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function renameItem(item) {\n  const name = prompt("Enter new name:", item.name);\n  if (!name || name === item.name) return;\n\n  try {\n    await api("/api/rename", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: item.path, name})\n    });\n    showMessage("Rename complete", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function moveItems(items) {\n  if (!items.length) return;\n\n  if (items.length === 1) {\n    const dst = prompt("Enter target relative path, e.g. docs/a.txt or backup/folder", items[0].path);\n    if (!dst || dst === items[0].path) return;\n\n    try {\n      await api("/api/move", {\n        method: "POST",\n        headers: {"Content-Type": "application/json"},\n        body: JSON.stringify({src: items[0].path, dst: dst.trim()})\n      });\n      showMessage("Move complete", "success");\n      await loadList();\n    } catch (err) {\n      showMessage(err.message, "danger");\n    }\n    return;\n  }\n\n  const targetDirectory = prompt("Enter target folder relative path, e.g. backup or docs/2026");\n  if (targetDirectory === null) return;\n\n  await movePathsToDirectory(items.map(item => item.path), targetDirectory.trim().replace(/^\\/+|\\/+$/g, ""));\n}\n\nasync function shareItem(item) {\n  try {\n    const data = await api("/api/share", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: item.path})\n    });\n\n    let copied = false;\n    try {\n      await navigator.clipboard.writeText(data.url);\n      copied = true;\n    } catch (_) {\n      copied = false;\n    }\n\n    showMessage(copied ? `Share created. Link copied: ${data.url}` : `Share created. Please copy manually: ${data.url}`, "success");\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function archiveItems(items) {\n  if (!items.length) return;\n  try {\n    showMessage("Creating 7z archive, please wait...", "muted");\n    const data = await api("/api/archive", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({\n        cwd,\n        paths: items.map(x => x.path)\n      })\n    });\n    showMessage(`Archive complete: ${fmtSize(data.size)}`, "success");\n    window.location.href = data.url;\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function showShares() {\n  try {\n    const data = await api("/api/shares");\n    const box = getById("sharesList");\n    if (!data.shares.length) {\n      box.innerHTML = `<div class="text-muted">No shares yet</div>`;\n    } else {\n      box.innerHTML = "";\n      for (const shareInfo of data.shares) {\n        const div = document.createElement("div");\n        div.className = "border rounded p-2 mb-2";\n        div.innerHTML = `\n          <div><strong>${shareInfo.name}</strong> <span class="badge text-bg-light">${shareInfo.type}</span></div>\n          <div class="text-break"><a href="${shareInfo.url}" target="_blank">${shareInfo.url}</a></div>\n          <div class="text-muted">Path: /${shareInfo.path || ""}</div>\n        `;\n        const del = document.createElement("button");\n        del.className = "btn btn-sm btn-outline-danger mt-2";\n        del.textContent = "Revoke Share";\n        del.onclick = async () => {\n          await api(`/api/share/${shareInfo.token}`, {method: "DELETE"});\n          showShares();\n        };\n        div.appendChild(del);\n        box.appendChild(div);\n      }\n    }\n    new bootstrap.Modal(getById("sharesModal")).show();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction setMenuVisible(action, visible) {\n  const element = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction setSepVisible(name, visible) {\n  const element = document.querySelector(`#contextMenu [data-sep="${name}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = getById("contextMenu");\n  const items = mode === "item" ? getContextItems() : [];\n  const single = items.length === 1;\n  const item = single ? items[0] : null;\n\n  ["open", "download", "archive", "share", "rename", "move", "delete", "mkdir", "upload", "refresh", "shares"]\n    .forEach(a => setMenuVisible(a, false));\n  setSepVisible("item", false);\n\n  if (mode === "blank") {\n    selectedPaths.clear();\n    syncSelectionUI();\n    setMenuVisible("mkdir", true);\n    setMenuVisible("upload", true);\n    setMenuVisible("refresh", true);\n    setMenuVisible("shares", true);\n  } else if (single && item.type === "dir") {\n    setMenuVisible("open", true);\n    setMenuVisible("archive", true);\n    setMenuVisible("share", true);\n    setMenuVisible("delete", true);\n    setMenuVisible("rename", true);\n  } else if (single && item.type === "file") {\n    setMenuVisible("open", true);\n    setMenuVisible("download", true);\n    setMenuVisible("share", true);\n    setMenuVisible("rename", true);\n    setMenuVisible("move", true);\n    setMenuVisible("delete", true);\n    // Do not show 7z for a single file；the file already has direct download.\n  } else if (items.length > 1) {\n    setMenuVisible("archive", true);\n    setMenuVisible("move", true);\n    setMenuVisible("delete", true);\n  } else {\n    return;\n  }\n\n  const openBtn = menu.querySelector(\'[data-action="open"]\');\n  if (openBtn && single) openBtn.textContent = openActionLabel(item);\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = getById("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\nfunction setupContextMenu() {\n  getById("contextMenu").addEventListener("click", async (e) => {\n    const btn = e.target.closest("button[data-action]");\n    if (!btn) return;\n    const action = btn.dataset.action;\n    const items = getContextItems();\n    hideContextMenu();\n\n    if (action === "mkdir") return mkdirFromContext();\n    if (action === "upload") return uploadFromContext();\n    if (action === "refresh") return loadList();\n    if (action === "shares") return showShares();\n\n    if (!items.length) return;\n\n    if (action === "open" && items.length === 1) openItem(items[0]);\n    if (action === "download" && items.length === 1) downloadItem(items[0].path);\n    if (action === "archive") archiveItems(items);\n    if (action === "share" && items.length === 1) shareItem(items[0]);\n    if (action === "rename" && items.length === 1) renameItem(items[0]);\n    if (action === "move") moveItems(items);\n    if (action === "delete") deleteItems(items);\n  });\n\n  document.addEventListener("click", (e) => {\n    if (!e.target.closest("#contextMenu")) hideContextMenu();\n  });\n\n  getById("filePane").addEventListener("contextmenu", (e) => {\n    if (!e.target.closest(".file-item")) {\n      e.preventDefault();\n      contextTargetPath = null;\n      showContextMenu(e.clientX, e.clientY, "blank");\n    }\n  });\n}\n\nfunction rectsIntersect(a, b) {\n  return !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);\n}\n\nfunction setupDragSelection() {\n  const pane = getById("filePane");\n  const box = getById("selectionBox");\n\n  pane.addEventListener("mousedown", (e) => {\n    if (e.button !== 0) return;\n    if (e.target.closest(".file-item")) return;\n    if (e.target.closest("#contextMenu")) return;\n\n    const startX = e.clientX;\n    const startY = e.clientY;\n    dragState = {startX, startY, moved: false, additive: e.ctrlKey || e.metaKey};\n    if (!dragState.additive) {\n      selectedPaths.clear();\n      syncSelectionUI();\n    }\n\n    box.style.left = `${startX}px`;\n    box.style.top = `${startY}px`;\n    box.style.width = "0px";\n    box.style.height = "0px";\n    box.style.display = "block";\n    e.preventDefault();\n  });\n\n  document.addEventListener("mousemove", (e) => {\n    if (!dragState) return;\n\n    const x1 = Math.min(dragState.startX, e.clientX);\n    const y1 = Math.min(dragState.startY, e.clientY);\n    const x2 = Math.max(dragState.startX, e.clientX);\n    const y2 = Math.max(dragState.startY, e.clientY);\n\n    if (Math.abs(x2 - x1) > 3 || Math.abs(y2 - y1) > 3) {\n      dragState.moved = true;\n    }\n\n    box.style.left = `${x1}px`;\n    box.style.top = `${y1}px`;\n    box.style.width = `${x2 - x1}px`;\n    box.style.height = `${y2 - y1}px`;\n\n    const selectionRect = {left: x1, top: y1, right: x2, bottom: y2};\n    document.querySelectorAll(".file-item").forEach(row => {\n      const r = row.getBoundingClientRect();\n      if (rectsIntersect(selectionRect, r)) {\n        selectedPaths.add(row.dataset.path);\n      } else if (!dragState.additive) {\n        selectedPaths.delete(row.dataset.path);\n      }\n    });\n    syncSelectionUI();\n  });\n\n  document.addEventListener("mouseup", () => {\n    if (!dragState) return;\n    setTimeout(() => { dragState = null; }, 0);\n    box.style.display = "none";\n  });\n}\n\ndocument.addEventListener("keydown", (e) => {\n  if (e.key === "F5") {\n    e.preventDefault();\n    loadList();\n  }\n});\n\ngetById("fileInput").addEventListener("change", uploadSelectedFiles);\n\nsetupContextMenu();\nsetupDragSelection();\nloadList("");\n\n</script>\n</body>\n</html>\n'
EDITOR_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Text Editor</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n  overflow: hidden;\n  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n}\n\n#toolbar {\n  position: fixed;\n  top: 0;\n  left: 0;\n  right: 0;\n  height: 38px;\n  display: flex;\n  align-items: center;\n  gap: 10px;\n  padding: 0 10px;\n  background: #fffaf7;\n  border-bottom: 1px solid #f1b4a2;\n  z-index: 10;\n}\n\n#filename {\n  min-width: 0;\n  font-weight: 700;\n  color: #50322b;\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n#encoding,\n#status {\n  flex: 0 0 auto;\n  font-size: 12px;\n  color: #8a6a62;\n}\n\n#saveBtn,\n#downloadBtn,\n#closeBtn {\n  flex: 0 0 auto;\n  border: 1px solid #e9795f;\n  background: #e9795f;\n  color: #fff;\n  border-radius: 8px;\n  padding: 6px 12px;\n  cursor: pointer;\n}\n\n#saveBtn {\n  margin-left: auto;\n}\n\n#downloadBtn,\n#closeBtn {\n  background: #fff;\n  color: #c95d45;\n}\n\n#editor {\n  position: fixed;\n  top: 38px;\n  left: 0;\n  right: 0;\n  bottom: 0;\n  width: 100%;\n  height: calc(100% - 38px);\n  border: 0;\n  outline: none;\n  resize: none;\n  padding: 16px;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  color: #222;\n  background: rgba(110, 0, 0, 0.06);\n}\n\n#editor::selection {\n  background: rgba(255, 190, 150, 0.55);\n  color: #50322b;\n}\n\n</style>\n</head>\n<body>\n  <div id="toolbar">\n    <span id="filename"></span>\n    <span id="encoding"></span>\n    <span id="status"></span>\n    <button id="saveBtn">Save</button>\n    <button id="downloadBtn">Download</button>\n    <button id="closeBtn" type="button">Close</button>\n  </div>\n  <textarea id="editor" spellcheck="false"></textarea>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\n\nconst editor = document.getElementById("editor");\nconst filename = document.getElementById("filename");\nconst encodingEl = document.getElementById("encoding");\nconst statusEl = document.getElementById("status");\nconst saveBtn = document.getElementById("saveBtn");\nconst downloadBtn = document.getElementById("downloadBtn");\nconst closeBtn = document.getElementById("closeBtn");\n\nlet currentEncoding = "utf-8";\n\nfunction setStatus(text) {\n  statusEl.textContent = text;\n}\n\nfunction closeEditor() {\n  const parentWindow = window.parent;\n  if (parentWindow && parentWindow !== window && parentWindow.bootstrap) {\n    const modalElement = parentWindow.document.getElementById("pageModal");\n    if (modalElement) {\n      const modalInstance = parentWindow.bootstrap.Modal.getInstance(modalElement) || parentWindow.bootstrap.Modal.getOrCreateInstance(modalElement);\n      modalInstance.hide();\n      return;\n    }\n  }\n  window.close();\n}\n\nasync function api(url, options = {}) {\n  const response = await fetch(url, options);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function loadText() {\n  try {\n    const data = await api(`/api/text?path=${encodeURIComponent(path)}`);\n    filename.textContent = data.name;\n    currentEncoding = data.encoding || "utf-8";\n    encodingEl.textContent = `Encoding: ${currentEncoding}`;\n    editor.value = data.text;\n    downloadBtn.onclick = () => {\n      location.href = `/api/download?path=${encodeURIComponent(path)}`;\n    };\n    setStatus("Loaded");\n  } catch (err) {\n    setStatus(err.message);\n    editor.value = "";\n  }\n}\n\nasync function saveText() {\n  try {\n    saveBtn.disabled = true;\n    await api("/api/text", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({\n        path,\n        text: editor.value,\n        encoding: currentEncoding\n      })\n    });\n    setStatus(`Saved ${new Date().toLocaleTimeString()}`);\n  } catch (err) {\n    setStatus(err.message);\n  } finally {\n    saveBtn.disabled = false;\n  }\n}\n\nsaveBtn.onclick = saveText;\ncloseBtn.onclick = closeEditor;\n\neditor.addEventListener("keydown", (e) => {\n  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {\n    e.preventDefault();\n    saveText();\n  }\n});\n\nloadText();\n\n</script>\n</body>\n</html>\n'
VIEWER_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Online Viewer</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody,\n#viewerRoot {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n}\n\nbody {\n  background: #fff;\n  color: #222;\n  overflow: hidden;\n  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;\n}\n\n#viewerRoot {\n  display: flex;\n  align-items: stretch;\n  justify-content: center;\n}\n\n#status {\n  margin: auto;\n  color: #8a6a62;\n  font-size: 14px;\n}\n\n.viewer-media {\n  width: 100%;\n  height: 100%;\n  max-height: 100vh;\n  background: #000;\n}\n\naudio.viewer-media {\n  width: min(900px, 92vw);\n  height: 44px;\n  margin: auto;\n  background: transparent;\n}\n\n.text-view {\n  width: 100%;\n  height: 100%;\n  margin: 0;\n  padding: 16px;\n  overflow: auto;\n  white-space: pre-wrap;\n  word-break: break-word;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  background: #fff;\n  color: #222;\n}\n\n</style>\n</head>\n<body>\n  <main id="viewerRoot">\n    <div id="status">Loading……</div>\n  </main>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\nconst root = document.getElementById("viewerRoot");\n\nasync function jsonApi(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nfunction extOf(name) {\n  const dotIndex = name.lastIndexOf(".");\n  return dotIndex >= 0 ? name.slice(dotIndex).toLowerCase() : "";\n}\n\nasync function init() {\n  try {\n    const list = await jsonApi(`/api/list?path=${encodeURIComponent(parentPath(path))}`);\n    const item = list.items.find(x => x.path === path);\n\n    if (!item) {\n      throw new Error("File does not exist");\n    }\n\n    if (item.media === "video") {\n      root.innerHTML = `<video class="viewer-media" src="/api/media?path=${encodeURIComponent(path)}" controls autoplay></video>`;\n      return;\n    }\n\n    if (item.media === "audio") {\n      root.innerHTML = `<audio class="viewer-media" src="/api/media?path=${encodeURIComponent(path)}" controls autoplay></audio>`;\n      return;\n    }\n\n    if (item.editable) {\n      const data = await jsonApi(`/api/text?path=${encodeURIComponent(path)}`);\n      const pre = document.createElement("pre");\n      pre.className = "text-view";\n      pre.textContent = data.text;\n      root.innerHTML = "";\n      root.appendChild(pre);\n      return;\n    }\n\n    root.innerHTML = `<div id="status">This file does not support online viewing. Please download it.</div>`;\n  } catch (err) {\n    root.innerHTML = `<div id="status">${err.message}</div>`;\n  }\n}\n\nfunction parentPath(p) {\n  const parts = (p || "").split("/").filter(Boolean);\n  parts.pop();\n  return parts.join("/");\n}\n\ninit();\n\n</script>\n</body>\n</html>\n'
SHARE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Shared Folder - {{ name }}</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-header {\n  height: 38px;\n  padding: 6px 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: var(--warm-panel);\n}\n\n.page-modal-header .modal-title {\n  font-size: 13px;\n  color: var(--warm-text);\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: calc(100vh - 38px);\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div id="breadcrumb" class="breadcrumb-flat"></div>\n  <div class="path-meta">\n    <span class="readonly-badge">Read-only Share</span>\n    <span id="countText"></span>\n    <span class="hint">Click to open/download · Right-click actions</span>\n  </div>\n</header>\n\n<main class="file-pane" id="filePane">\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="emptyState" class="empty-state d-none">This shared folder is empty</div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-header page-modal-header">\n        <div class="modal-title" id="pageModalTitle">View</div>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>\n      </div>\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="share-viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Open</button>\n  <button data-action="download">Download</button>\n  <button data-action="refresh">Refresh</button>\n</div>\n\n<script>\n  window.SHARE_TOKEN = "{{ token }}";\n  window.SHARE_ROOT_NAME = "{{ name }}";\n</script>\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPath = null;\nlet currentItemCount = 0;\n\nconst token = window.SHARE_TOKEN;\nconst rootName = window.SHARE_ROOT_NAME || "Share";\nconst singleFileMode = Boolean(window.SHARE_SINGLE_FILE);\nconst getById = (elementId) => document.getElementById(elementId);\n\nfunction showMessage(text, type = "muted") {\n  const element = getById("message");\n  if (!el) return;\n  element.className = `message small text-${type}`;\n  element.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (element.textContent === text) element.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    itemsByPath.clear();\n    selectedPath = null;\n\n    const data = await api(`/s/${token}/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = getById("fileGrid");\n    grid.innerHTML = "";\n    const empty = getById("emptyState");\n    if (empty) empty.classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n\n    if (singleFileMode && data.items.length === 1) {\n      selectedPath = data.items[0].path;\n      syncSelectionUI();\n    }\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction renderBreadcrumb() {\n  const box = getById("breadcrumb");\n  if (!box) return;\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = rootName;\n  root.onclick = () => {\n    if (!singleFileMode) loadList("");\n  };\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const element = getById("countText");\n  if (element) element.textContent = `${currentItemCount} item(s)`;\n}\n\nfunction renderItem(item) {\n  const element = document.createElement("div");\n  element.className = "file-item";\n  element.dataset.path = item.path;\n  element.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Folder"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Folder" : (item.media || (item.editable ? "Text" : fmtSize(item.size)));\n\n  element.append(icon, name, meta);\n\n  element.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  element.onclick = () => {\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  element.oncontextmenu = (e) => {\n    e.preventDefault();\n    selectedPath = item.path;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  return element;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", row.dataset.path === selectedPath);\n  });\n}\n\nfunction selectedItem() {\n  if (selectedPath === null) return null;\n  return itemsByPath.get(selectedPath) || null;\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media || item.editable) {\n    openPageModal(`View - ${item.name}`, `/share-viewer/${token}?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Open";\n  if (item.type === "dir") return "Open";\n  if (item.media) return "Play Online";\n  if (item.editable) return "Online Viewer";\n  return "Download";\n}\n\nfunction openPageModal(title, url) {\n  getById("pageModalTitle").textContent = title;\n  getById("pageFrame").src = url;\n  bootstrap.Modal.getOrCreateInstance(getById("pageModal")).show();\n}\n\ngetById("pageModal").addEventListener("hidden.bs.modal", () => {\n  getById("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  location.href = `/s/${token}/download?path=${encodeURIComponent(path || "")}`;\n}\n\nfunction setMenuVisible(action, visible) {\n  const element = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = getById("contextMenu");\n  ["open", "download", "refresh"].forEach(a => setMenuVisible(a, false));\n\n  const item = selectedItem();\n\n  if (mode === "blank") {\n    setMenuVisible("refresh", true);\n  } else if (item) {\n    setMenuVisible("open", true);\n    if (item.type === "file") setMenuVisible("download", true);\n    const openBtn = menu.querySelector(\'[data-action="open"]\');\n    if (openBtn) openBtn.textContent = openActionLabel(item);\n  } else {\n    return;\n  }\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = getById("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\ngetById("contextMenu").addEventListener("click", (e) => {\n  const btn = e.target.closest("button[data-action]");\n  if (!btn) return;\n\n  const action = btn.dataset.action;\n  const item = selectedItem();\n  hideContextMenu();\n\n  if (action === "refresh") return loadList();\n  if (!item) return;\n\n  if (action === "open") openItem(item);\n  if (action === "download") downloadItem(item.path);\n});\n\ndocument.addEventListener("click", (e) => {\n  if (!e.target.closest("#contextMenu")) hideContextMenu();\n});\n\ngetById("filePane").addEventListener("contextmenu", (e) => {\n  if (!e.target.closest(".file-item")) {\n    e.preventDefault();\n    selectedPath = null;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "blank");\n  }\n});\n\nloadList("");\n\n</script>\n</body>\n</html>\n'
SHARE_FILE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Shared File - {{ name }}</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-header {\n  height: 38px;\n  padding: 6px 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: var(--warm-panel);\n}\n\n.page-modal-header .modal-title {\n  font-size: 13px;\n  color: var(--warm-text);\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: calc(100vh - 38px);\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div class="breadcrumb-flat">\n    <span class="crumb">Shared File</span>\n    <span class="crumb-sep">/</span>\n    <span class="crumb">{{ name }}</span>\n  </div>\n  <div class="path-meta">\n    <span class="readonly-badge">Read-only Share</span>\n  </div>\n</header>\n\n<main class="file-pane single-share-file" id="filePane">\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-header page-modal-header">\n        <div class="modal-title" id="pageModalTitle">View</div>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>\n      </div>\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="share-viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Open</button>\n  <button data-action="download">Download</button>\n</div>\n\n<script>\n  window.SHARE_TOKEN = "{{ token }}";\n  window.SHARE_ROOT_NAME = "{{ name }}";\n  window.SHARE_SINGLE_FILE = true;\n</script>\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPath = null;\nlet currentItemCount = 0;\n\nconst token = window.SHARE_TOKEN;\nconst rootName = window.SHARE_ROOT_NAME || "Share";\nconst singleFileMode = Boolean(window.SHARE_SINGLE_FILE);\nconst getById = (elementId) => document.getElementById(elementId);\n\nfunction showMessage(text, type = "muted") {\n  const element = getById("message");\n  if (!el) return;\n  element.className = `message small text-${type}`;\n  element.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (element.textContent === text) element.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    itemsByPath.clear();\n    selectedPath = null;\n\n    const data = await api(`/s/${token}/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = getById("fileGrid");\n    grid.innerHTML = "";\n    const empty = getById("emptyState");\n    if (empty) empty.classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n\n    if (singleFileMode && data.items.length === 1) {\n      selectedPath = data.items[0].path;\n      syncSelectionUI();\n    }\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction renderBreadcrumb() {\n  const box = getById("breadcrumb");\n  if (!box) return;\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = rootName;\n  root.onclick = () => {\n    if (!singleFileMode) loadList("");\n  };\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const element = getById("countText");\n  if (element) element.textContent = `${currentItemCount} item(s)`;\n}\n\nfunction renderItem(item) {\n  const element = document.createElement("div");\n  element.className = "file-item";\n  element.dataset.path = item.path;\n  element.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Folder"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Folder" : (item.media || (item.editable ? "Text" : fmtSize(item.size)));\n\n  element.append(icon, name, meta);\n\n  element.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  element.onclick = () => {\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  element.oncontextmenu = (e) => {\n    e.preventDefault();\n    selectedPath = item.path;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  return element;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", row.dataset.path === selectedPath);\n  });\n}\n\nfunction selectedItem() {\n  if (selectedPath === null) return null;\n  return itemsByPath.get(selectedPath) || null;\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media || item.editable) {\n    openPageModal(`View - ${item.name}`, `/share-viewer/${token}?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Open";\n  if (item.type === "dir") return "Open";\n  if (item.media) return "Play Online";\n  if (item.editable) return "Online Viewer";\n  return "Download";\n}\n\nfunction openPageModal(title, url) {\n  getById("pageModalTitle").textContent = title;\n  getById("pageFrame").src = url;\n  bootstrap.Modal.getOrCreateInstance(getById("pageModal")).show();\n}\n\ngetById("pageModal").addEventListener("hidden.bs.modal", () => {\n  getById("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  location.href = `/s/${token}/download?path=${encodeURIComponent(path || "")}`;\n}\n\nfunction setMenuVisible(action, visible) {\n  const element = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (element) element.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = getById("contextMenu");\n  ["open", "download", "refresh"].forEach(a => setMenuVisible(a, false));\n\n  const item = selectedItem();\n\n  if (mode === "blank") {\n    setMenuVisible("refresh", true);\n  } else if (item) {\n    setMenuVisible("open", true);\n    if (item.type === "file") setMenuVisible("download", true);\n    const openBtn = menu.querySelector(\'[data-action="open"]\');\n    if (openBtn) openBtn.textContent = openActionLabel(item);\n  } else {\n    return;\n  }\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = getById("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\ngetById("contextMenu").addEventListener("click", (e) => {\n  const btn = e.target.closest("button[data-action]");\n  if (!btn) return;\n\n  const action = btn.dataset.action;\n  const item = selectedItem();\n  hideContextMenu();\n\n  if (action === "refresh") return loadList();\n  if (!item) return;\n\n  if (action === "open") openItem(item);\n  if (action === "download") downloadItem(item.path);\n});\n\ndocument.addEventListener("click", (e) => {\n  if (!e.target.closest("#contextMenu")) hideContextMenu();\n});\n\ngetById("filePane").addEventListener("contextmenu", (e) => {\n  if (!e.target.closest(".file-item")) {\n    e.preventDefault();\n    selectedPath = null;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "blank");\n  }\n});\n\nloadList("");\n\n</script>\n</body>\n</html>\n'
SHARE_VIEWER_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Shared Viewer</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody,\n#viewerRoot {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n}\n\nbody {\n  background: #fff;\n  color: #222;\n  overflow: hidden;\n  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;\n}\n\n#viewerRoot {\n  display: flex;\n  align-items: stretch;\n  justify-content: center;\n}\n\n#status {\n  margin: auto;\n  color: #8a6a62;\n  font-size: 14px;\n}\n\n.viewer-media {\n  width: 100%;\n  height: 100%;\n  max-height: 100vh;\n  background: #000;\n}\n\naudio.viewer-media {\n  width: min(900px, 92vw);\n  height: 44px;\n  margin: auto;\n  background: transparent;\n}\n\n.text-view {\n  width: 100%;\n  height: 100%;\n  margin: 0;\n  padding: 16px;\n  overflow: auto;\n  white-space: pre-wrap;\n  word-break: break-word;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  background: #fff;\n  color: #222;\n}\n\n</style>\n</head>\n<body>\n  <main id="viewerRoot">\n    <div id="status">Loading……</div>\n  </main>\n  <script>\n    window.SHARE_TOKEN = "{{ token }}";\n  </script>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\nconst token = window.SHARE_TOKEN;\nconst root = document.getElementById("viewerRoot");\n\nasync function jsonApi(url) {\n  const response = await fetch(url);\n  const data = await response.json();\n  if (!response.ok || data.ok === false) {\n    throw new Error(data.error || `Request failed: ${response.status}`);\n  }\n  return data;\n}\n\nasync function init() {\n  try {\n    const list = await jsonApi(`/s/${token}/api/list?path=${encodeURIComponent(parentPath(path))}`);\n    const item = list.items.find(x => x.path === path) || list.items[0];\n\n    if (!item) {\n      throw new Error("File does not exist");\n    }\n\n    const effectivePath = item.path || "";\n\n    if (item.media === "video") {\n      root.innerHTML = `<video class="viewer-media" src="/s/${token}/media?path=${encodeURIComponent(effectivePath)}" controls autoplay></video>`;\n      return;\n    }\n\n    if (item.media === "audio") {\n      root.innerHTML = `<audio class="viewer-media" src="/s/${token}/media?path=${encodeURIComponent(effectivePath)}" controls autoplay></audio>`;\n      return;\n    }\n\n    if (item.editable) {\n      const data = await jsonApi(`/s/${token}/text?path=${encodeURIComponent(effectivePath)}`);\n      const pre = document.createElement("pre");\n      pre.className = "text-view";\n      pre.textContent = data.text;\n      root.innerHTML = "";\n      root.appendChild(pre);\n      return;\n    }\n\n    root.innerHTML = `<div id="status">This file does not support online viewing. Please download it.</div>`;\n  } catch (err) {\n    root.innerHTML = `<div id="status">${err.message}</div>`;\n  }\n}\n\nfunction parentPath(p) {\n  const parts = (p || "").split("/").filter(Boolean);\n  parts.pop();\n  return parts.join("/");\n}\n\ninit();\n\n</script>\n</body>\n</html>\n'
if __name__ == "__main__":
    import uvicorn
    print("FastAPI File Manager V1")
    print("Authentication: disabled in this migration test version")
    print("Open: http://127.0.0.1:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
