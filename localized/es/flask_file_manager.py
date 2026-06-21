"""
Single-file Flask File Manager.

Todo el backend, HTML, CSS y JavaScript está contenido en este archivo.
Instala las dependencias de requirements.txt antes de ejecutar:

    python flask_file_manager.py

Usuario predeterminado: admin
Contraseña predeterminada: admin123

Configurable mediante variables de entorno:
    FM_USERNAME
    FM_PASSWORD
    FM_MAX_UPLOAD_BYTES
"""

from __future__ import annotations

import json
import mimetypes
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
    url_for,
)
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
STORAGE_ROOT = (BASE_DIR / "storage").resolve()
SHARES_FILE = BASE_DIR / "shares.json"
CACHE_ROOT = (BASE_DIR / "cache").resolve()

USERNAME = os.environ.get("FM_USERNAME", "admin")
PASSWORD = os.environ.get("FM_PASSWORD", "admin123")
PASSWORD_HASH = generate_password_hash(PASSWORD)

MAX_UPLOAD_BYTES = int(os.environ.get("FM_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))

TEXT_EXTENSIONS = {
    ".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".csv", ".log", ".ini", ".conf",
    ".py", ".js", ".ts", ".css", ".html", ".htm", ".vue", ".java", ".c", ".cpp", ".h",
    ".hpp", ".go", ".rs", ".php", ".rb", ".sh", ".bat", ".ps1", ".sql", ".toml",
    ".env", ".gitignore", ".dockerignore", ".jsonc", ".lock",
}

VIDEO_EXTENSIONS = {".mp4", ".webm", ".ogg", ".ogv", ".m4v", ".mov", ".mkv"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".ogg", ".oga", ".m4a", ".aac", ".flac", ".webm"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
auth = HTTPBasicAuth()

STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
CACHE_ROOT.mkdir(parents=True, exist_ok=True)


@auth.verify_password
def verify_password(username: str, password: str):
    if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
        return username
    return None


def require_auth(func):
    @wraps(func)
    @auth.login_required
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def load_shares() -> Dict[str, Any]:
    if not SHARES_FILE.exists():
        return {}
    try:
        return json.loads(SHARES_FILE.read_text("utf-8"))
    except Exception:
        return {}


def save_shares(data: Dict[str, Any]) -> None:
    tmp = SHARES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    tmp.replace(SHARES_FILE)


def safe_path(rel_path: str | None = "") -> Path:
    rel_path = (rel_path or "").strip().lstrip("/\\")
    target = (STORAGE_ROOT / rel_path).resolve()

    try:
        target.relative_to(STORAGE_ROOT)
    except ValueError:
        abort(400, description="Ruta no válida")

    return target


def rel_from_root(path: Path) -> str:
    return path.resolve().relative_to(STORAGE_ROOT).as_posix()


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def get_share_or_404(token: str) -> Dict[str, Any]:
    shares = load_shares()
    share = shares.get(token)
    if not share:
        abort(404, description="El enlace no existe o fue revocado")

    root = safe_path(share.get("path", ""))
    if not root.exists():
        abort(404, description="El archivo compartido de origen no existe")

    share["token"] = token
    share["root_abs"] = root
    return share


def resolve_shared_path(share: Dict[str, Any], rel_path: str | None = "") -> Path:
    root = share["root_abs"]
    if root.is_file():
        # En archivos compartidos, solo se puede acceder al propio archivo compartido.
        target = root
    else:
        rel_path = (rel_path or "").strip().lstrip("/\\")
        target = (root / rel_path).resolve()

    if not is_within(target, root):
        abort(403, description="No se permite acceder fuera de la carpeta compartida")

    return target


def entry_to_dict(path: Path) -> Dict[str, Any]:
    stat = path.stat()
    suffix = path.suffix.lower()
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


def shared_entry_to_dict(path: Path, root: Path) -> Dict[str, Any]:
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


def media_type_for(path: Path) -> Optional[str]:
    """
    Determina la reproducción en línea estrictamente por extensión.
    Solo las extensiones registradas en VIDEO_EXTENSIONS / AUDIO_EXTENSIONS mostrarán acciones de reproducción.
    """
    if not path.is_file():
        return None

    suffix = path.suffix.lower()
    if suffix in VIDEO_EXTENSIONS:
        return "video"
    if suffix in AUDIO_EXTENSIONS:
        return "audio"
    return None


def is_text_file(path: Path) -> bool:
    """
    Determina la edición en línea estrictamente por extensión.
    Solo las extensiones registradas en TEXT_EXTENSIONS mostrarán acciones de edición.
    """
    if not path.is_file():
        return False
    return path.suffix.lower() in TEXT_EXTENSIONS


def detect_encoding(raw: bytes) -> str:
    if not raw:
        return "utf-8"

    result = from_bytes(raw).best()
    if result and result.encoding:
        return result.encoding

    return "utf-8"


def list_dir_payload(current: Path) -> Dict[str, Any]:
    if not current.exists():
        return {"ok": False, "error": "La ruta no existe"}
    if not current.is_dir():
        return {"ok": False, "error": "No es una carpeta"}

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
    if current != STORAGE_ROOT:
        parent = rel_from_root(current.parent)

    return {
        "ok": True,
        "cwd": rel_from_root(current) if current != STORAGE_ROOT else "",
        "parent": parent,
        "items": dirs + files,
    }


def list_shared_dir_payload(current: Path, root: Path) -> Dict[str, Any]:
    if not current.exists():
        return {"ok": False, "error": "La ruta no existe"}
    if not current.is_dir():
        return {"ok": False, "error": "No es una carpeta"}

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


def partial_response(path: Path):
    """
    Admite solicitudes Range para que los elementos de video/audio puedan buscar.
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
        with path.open("rb") as f:
            f.seek(start)
            remaining = length
            chunk_size = 1024 * 1024
            while remaining > 0:
                chunk = f.read(min(chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    rv = Response(generate(), status=206, mimetype=mime, direct_passthrough=True)
    rv.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
    rv.headers["Accept-Ranges"] = "bytes"
    rv.headers["Content-Length"] = str(length)
    return rv


def unique_archive_name(prefix: str = "download") -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in prefix).strip("._")
    if not safe:
        safe = "download"
    return f"{safe}_{int(time.time())}_{uuid.uuid4().hex[:8]}.7z"


def cleanup_old_cache(max_age_seconds: int = 24 * 3600) -> None:
    now = time.time()
    for p in CACHE_ROOT.iterdir():
        try:
            if p.is_file() and now - p.stat().st_mtime > max_age_seconds:
                p.unlink()
        except OSError:
            pass


def make_7z_archive(paths: list[Path], base_dir: Path, archive_name: str) -> Path:
    cleanup_old_cache()
    archive_path = (CACHE_ROOT / archive_name).resolve()

    try:
        archive_path.relative_to(CACHE_ROOT)
    except ValueError:
        abort(400, description="Nombre de archivo comprimido no válido")

    # preset=9 es el preset LZMA2 más alto expuesto por py7zr.
    filters = [{"id": py7zr.FILTER_LZMA2, "preset": 9 | py7zr.PRESET_EXTREME}]

    with py7zr.SevenZipFile(archive_path, "w", filters=filters) as archive:
        used_names = set()

        for src in paths:
            src = src.resolve()
            if not src.exists():
                continue

            if src == STORAGE_ROOT:
                arcname = "storage"
            else:
                try:
                    arcname = src.relative_to(base_dir.resolve()).as_posix()
                except ValueError:
                    arcname = src.name

            if not arcname or arcname == ".":
                arcname = src.name or "storage"

            original_arcname = arcname
            i = 1
            while arcname in used_names:
                stem = Path(original_arcname).stem
                suffix = Path(original_arcname).suffix
                parent = Path(original_arcname).parent.as_posix()
                renamed = f"{stem}_{i}{suffix}"
                arcname = renamed if parent == "." else f"{parent}/{renamed}"
                i += 1

            used_names.add(arcname)
            archive.writeall(src, arcname) if src.is_dir() else archive.write(src, arcname)

    return archive_path




@app.get("/")
@require_auth
def index():
    return render_template_string(INDEX_HTML)


@app.get("/editor")
@require_auth
def editor_page():
    return render_template_string(EDITOR_HTML)


@app.get("/viewer")
@require_auth
def viewer_page():
    return render_template_string(VIEWER_HTML)


@app.get("/share-viewer/<token>")
def share_viewer_page(token: str):
    get_share_or_404(token)
    return render_template_string(SHARE_VIEWER_HTML, token=token)


@app.get("/api/list")
@require_auth
def api_list():
    current = safe_path(request.args.get("path", ""))
    payload = list_dir_payload(current)
    if not payload["ok"]:
        return jsonify(payload), 404
    return jsonify(payload)


@app.post("/api/mkdir")
@require_auth
def api_mkdir():
    data = request.get_json(force=True, silent=True) or {}
    parent = safe_path(data.get("path", ""))
    name = (data.get("name") or "").strip()

    if not parent.exists() or not parent.is_dir():
        return jsonify({"ok": False, "error": "La carpeta superior no existe"}), 404

    if not name:
        return jsonify({"ok": False, "error": "El nombre de la carpeta no puede estar vacío"}), 400

    if "/" in name or "\\" in name or name in {".", ".."}:
        return jsonify({"ok": False, "error": "Nombre de carpeta no válido"}), 400

    parent_rel = rel_from_root(parent) if parent != STORAGE_ROOT else ""
    target = safe_path(f"{parent_rel}/{name}" if parent_rel else name)

    if target.exists():
        return jsonify({"ok": False, "error": "La carpeta ya existe"}), 409

    target.mkdir(parents=False)
    return jsonify({"ok": True, "item": entry_to_dict(target)})


@app.post("/api/upload")
@require_auth
def api_upload():
    rel_dir = request.form.get("path", "")
    target_dir = safe_path(rel_dir)

    if not target_dir.exists() or not target_dir.is_dir():
        return jsonify({"ok": False, "error": "La carpeta de destino de subida no existe"}), 404

    files = request.files.getlist("files")
    if not files:
        return jsonify({"ok": False, "error": "No se seleccionó ningún archivo"}), 400

    saved = []
    for f in files:
        if not f.filename:
            continue

        filename = Path(f.filename).name.replace("/", "_").replace("\\", "_")
        if filename in {"", ".", ".."}:
            continue

        parent_rel = rel_from_root(target_dir) if target_dir != STORAGE_ROOT else ""
        dest = safe_path(f"{parent_rel}/{filename}" if parent_rel else filename)

        if dest.exists():
            stem = dest.stem
            suffix = dest.suffix
            i = 1
            while dest.exists():
                new_name = f"{stem} ({i}){suffix}"
                dest = safe_path(f"{parent_rel}/{new_name}" if parent_rel else new_name)
                i += 1

        f.save(dest)
        saved.append(entry_to_dict(dest))

    return jsonify({"ok": True, "saved": saved})


@app.get("/api/download")
@require_auth
def api_download():
    path = safe_path(request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "El archivo no existe"}), 404

    return send_file(path, as_attachment=True, download_name=path.name, conditional=True)


@app.get("/api/media")
@require_auth
def api_media():
    path = safe_path(request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "El archivo no existe"}), 404

    if media_type_for(path) not in {"video", "audio"}:
        return jsonify({"ok": False, "error": "Esta extensión no admite reproducción en línea"}), 400

    return partial_response(path)


@app.get("/api/text")
@require_auth
def api_text():
    path = safe_path(request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "El archivo no existe"}), 404

    if not is_text_file(path):
        return jsonify({"ok": False, "error": "Este tipo de archivo no admite edición en línea"}), 400

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
        return jsonify({"ok": False, "error": "El archivo no existe"}), 404

    if not is_text_file(path):
        return jsonify({"ok": False, "error": "Este tipo de archivo no admite edición en línea"}), 400

    try:
        path.write_bytes(str(text).encode(encoding))
    except LookupError:
        return jsonify({"ok": False, "error": f"Codificación no compatible: {encoding}"}), 400
    except UnicodeEncodeError:
        return jsonify({"ok": False, "error": f"El contenido actual no se puede guardar con {encoding} codificación"}), 400

    return jsonify({"ok": True, "encoding": encoding, "saved_at": int(time.time())})


@app.post("/api/delete")
@require_auth
def api_delete():
    data = request.get_json(force=True, silent=True) or {}
    path = safe_path(data.get("path", ""))

    if path == STORAGE_ROOT:
        return jsonify({"ok": False, "error": "No se puede eliminar la carpeta raíz"}), 400

    if not path.exists():
        return jsonify({"ok": False, "error": "La ruta no existe"}), 404

    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()

    return jsonify({"ok": True})


@app.post("/api/move")
@require_auth
def api_move():
    data = request.get_json(force=True, silent=True) or {}
    src = safe_path(data.get("src", ""))
    dst = safe_path(data.get("dst", ""))

    if src == STORAGE_ROOT:
        return jsonify({"ok": False, "error": "No se puede mover la carpeta raíz"}), 400

    if not src.exists():
        return jsonify({"ok": False, "error": "La ruta de origen no existe"}), 404

    if dst.exists():
        return jsonify({"ok": False, "error": "La ruta de destino ya existe"}), 409

    dst.parent.mkdir(parents=True, exist_ok=True)

    if src.is_dir() and is_within(dst, src):
        return jsonify({"ok": False, "error": "No se puede mover una carpeta dentro de sí misma"}), 400

    shutil.move(str(src), str(dst))
    return jsonify({"ok": True, "item": entry_to_dict(dst)})


@app.post("/api/rename")
@require_auth
def api_rename():
    data = request.get_json(force=True, silent=True) or {}
    src = safe_path(data.get("path", ""))
    new_name = (data.get("name") or "").strip()

    if src == STORAGE_ROOT:
        return jsonify({"ok": False, "error": "No se puede renombrar la carpeta raíz"}), 400

    if not src.exists():
        return jsonify({"ok": False, "error": "La ruta no existe"}), 404

    if not new_name or "/" in new_name or "\\" in new_name or new_name in {".", ".."}:
        return jsonify({"ok": False, "error": "Nombre no válido"}), 400

    dst = src.with_name(new_name).resolve()

    try:
        dst.relative_to(STORAGE_ROOT)
    except ValueError:
        return jsonify({"ok": False, "error": "Ruta no válida"}), 400

    if dst.exists():
        return jsonify({"ok": False, "error": "El nombre de destino ya existe"}), 409

    src.rename(dst)
    return jsonify({"ok": True, "item": entry_to_dict(dst)})


@app.post("/api/share")
@require_auth
def api_create_share():
    data = request.get_json(force=True, silent=True) or {}
    path = safe_path(data.get("path", ""))

    if not path.exists():
        return jsonify({"ok": False, "error": "La ruta compartida no existe"}), 404

    token = secrets.token_urlsafe(24)
    shares = load_shares()
    shares[token] = {
        "path": rel_from_root(path) if path != STORAGE_ROOT else "",
        "name": path.name if path != STORAGE_ROOT else "Raíz",
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
    for token, share in shares.items():
        item = dict(share)
        item["token"] = token
        item["url"] = url_for("share_page", token=token, _external=True)
        out.append(item)
    out.sort(key=lambda x: x.get("created", 0), reverse=True)
    return jsonify({"ok": True, "shares": out})


@app.delete("/api/share/<token>")
@require_auth
def api_delete_share(token: str):
    shares = load_shares()
    if token in shares:
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
        return jsonify({"ok": False, "error": "El archivo no existe"}), 404

    if not is_text_file(path):
        return jsonify({"ok": False, "error": "Este tipo de archivo no admite vista en línea"}), 400

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
        return jsonify({"ok": False, "error": "El archivo no existe"}), 404

    return send_file(path, as_attachment=True, download_name=path.name, conditional=True)


@app.get("/s/<token>/media")
def shared_media(token: str):
    share = get_share_or_404(token)
    path = resolve_shared_path(share, request.args.get("path", ""))

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "El archivo no existe"}), 404

    if media_type_for(path) not in {"video", "audio"}:
        return jsonify({"ok": False, "error": "Esta extensión no admite reproducción en línea"}), 400

    return partial_response(path)


@app.post("/api/archive")
@require_auth
def api_create_archive():
    data = request.get_json(force=True, silent=True) or {}
    rel_paths = data.get("paths") or []
    if isinstance(rel_paths, str):
        rel_paths = [rel_paths]

    if not rel_paths:
        return jsonify({"ok": False, "error": "Selecciona al menos un archivo o carpeta"}), 400

    resolved = []
    for rel in rel_paths:
        p = safe_path(rel)
        if not p.exists():
            return jsonify({"ok": False, "error": f"La ruta no existe: {rel}"}), 404
        resolved.append(p)

    if len(resolved) == 1:
        prefix = resolved[0].name or "storage"
        base_for_arcname = resolved[0].parent if resolved[0] != STORAGE_ROOT else STORAGE_ROOT
    else:
        prefix = "selected"
        # Para archivos de selección múltiple, usa el directorio actual como base；Usa la raíz de storage si no se proporciona cwd.
        cwd_rel = data.get("cwd", "")
        base_for_arcname = safe_path(cwd_rel)
        if not base_for_arcname.exists() or not base_for_arcname.is_dir():
            base_for_arcname = STORAGE_ROOT

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
        return jsonify({"ok": False, "error": "Nombre de archivo comprimido no válido"}), 400

    path = (CACHE_ROOT / name).resolve()
    try:
        path.relative_to(CACHE_ROOT)
    except ValueError:
        return jsonify({"ok": False, "error": "Ruta no válida"}), 400

    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "El archivo comprimido no existe o fue limpiado"}), 404

    return send_file(path, as_attachment=True, download_name=name, conditional=True)




@app.get("/api/info")
@require_auth
def api_info():
    return jsonify({
        "ok": True,
        "storage_root": str(STORAGE_ROOT),
        "cache_root": str(CACHE_ROOT),
        "max_upload_bytes": app.config["MAX_CONTENT_LENGTH"],
        "username": USERNAME,
    })


# =========================
# Embedded frontend assets
# =========================

INDEX_HTML = '<!doctype html>\n<html lang="es">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Administrador de archivos LAN</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-header {\n  height: 38px;\n  padding: 6px 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: var(--warm-panel);\n}\n\n.page-modal-header .modal-title {\n  font-size: 13px;\n  color: var(--warm-text);\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: calc(100vh - 38px);\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div id="breadcrumb" class="breadcrumb-flat"></div>\n  <div class="path-meta">\n    <span id="countText"></span>\n    <span class="hint">Clic para abrir/descargar · Ctrl multiselección · Clic derecho</span>\n  </div>\n</header>\n\n<main class="file-pane" id="filePane">\n  <input id="fileInput" class="hidden-file-input" type="file" multiple>\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="emptyState" class="empty-state d-none">Esta carpeta está vacía. Haz clic derecho en el espacio vacío para crear una carpeta o subir archivos.</div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-header page-modal-header">\n        <div class="modal-title" id="pageModalTitle">Ver</div>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>\n      </div>\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div class="modal fade" id="sharesModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-lg modal-dialog-centered">\n    <div class="modal-content share-list-modal">\n      <div class="modal-header">\n        <h5 class="modal-title">Lista de enlaces</h5>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>\n      </div>\n      <div class="modal-body">\n        <div id="sharesList" class="small"></div>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="selectionBox"></div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Abrir</button>\n  <button data-action="download">Descargar</button>\n  <button data-action="archive">Descargar como archivo 7z</button>\n  <button data-action="share">Compartir</button>\n  <hr data-sep="item">\n  <button data-action="rename">Renombrar</button>\n  <button data-action="move">Mover</button>\n  <button data-action="delete" class="danger">Eliminar</button>\n\n  <button data-action="mkdir">Nueva carpeta</button>\n  <button data-action="upload">Subir archivos</button>\n  <button data-action="refresh">Actualizar</button>\n  <button data-action="shares">Lista de enlaces</button>\n</div>\n\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPaths = new Set();\nlet contextTargetPath = null;\nlet dragState = null;\nlet currentItemCount = 0;\nlet activePageModal = null;\n\nconst $ = (id) => document.getElementById(id);\n\nfunction showMessage(text, type = "muted") {\n  const el = $("message");\n  el.className = `message small text-${type}`;\n  el.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (el.textContent === text) el.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url, options = {}) {\n  const res = await fetch(url, options);\n  const contentType = res.headers.get("content-type") || "";\n\n  let data = null;\n  if (contentType.includes("application/json")) {\n    data = await res.json();\n  }\n\n  if (!res.ok || (data && data.ok === false)) {\n    throw new Error((data && data.error) || `Error de solicitud: ${res.status}`);\n  }\n\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    selectedPaths.clear();\n    itemsByPath.clear();\n\n    const data = await api(`/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = $("fileGrid");\n    grid.innerHTML = "";\n    $("emptyState").classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction renderBreadcrumb() {\n  const box = $("breadcrumb");\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = "Raíz";\n  root.onclick = () => loadList("");\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const count = selectedPaths.size;\n  $("countText").textContent = count > 0 ? `Seleccionados ${count}  elemento(s)` : `${currentItemCount}  elemento(s)`;\n}\n\nfunction renderItem(item) {\n  const el = document.createElement("div");\n  el.className = "file-item";\n  el.dataset.path = item.path;\n  el.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Carpeta"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Carpeta" : (item.media || (item.editable ? "Texto" : fmtSize(item.size)));\n\n  el.append(icon, name, meta);\n\n  el.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  el.onclick = (e) => {\n    if (dragState && dragState.moved) return;\n\n    // Ctrl/Cmd/Shift reservado para multiselección；Un clic izquierdo normal ejecuta la acción más directa:\n    // las carpetas se abren y los archivos se descargan directamente.\n    if (e.ctrlKey || e.metaKey) {\n      toggleSelect(item.path);\n      return;\n    }\n\n    if (e.shiftKey) {\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n      return;\n    }\n\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  el.oncontextmenu = (e) => {\n    e.preventDefault();\n    contextTargetPath = item.path;\n    if (!selectedPaths.has(item.path)) {\n      selectedPaths.clear();\n      selectedPaths.add(item.path);\n      syncSelectionUI();\n    }\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  return el;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction getSelectedItems() {\n  return [...selectedPaths].map(p => itemsByPath.get(p)).filter(Boolean);\n}\n\nfunction getContextItems() {\n  const items = getSelectedItems();\n  if (items.length) return items;\n  if (contextTargetPath && itemsByPath.has(contextTargetPath)) return [itemsByPath.get(contextTargetPath)];\n  return [];\n}\n\nfunction toggleSelect(path) {\n  if (selectedPaths.has(path)) selectedPaths.delete(path);\n  else selectedPaths.add(path);\n  syncSelectionUI();\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", selectedPaths.has(row.dataset.path));\n  });\n  updateCountText();\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media) {\n    openPageModal(`Reproducir - ${item.name}`, `/viewer?path=${encodeURIComponent(item.path)}`);\n  } else if (item.editable) {\n    openPageModal(`Editar - ${item.name}`, `/editor?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Abrir";\n  if (item.type === "dir") return "Abrir";\n  if (item.media === "video") return "Reproducir en línea";\n  if (item.media === "audio") return "Reproducir en línea";\n  if (item.editable) return "Editar/ver en línea";\n  return "Descargar";\n}\n\nfunction openPageModal(title, url) {\n  $("pageModalTitle").textContent = title;\n  $("pageFrame").src = url;\n  activePageModal = bootstrap.Modal.getOrCreateInstance($("pageModal"));\n  activePageModal.show();\n}\n\n$("pageModal").addEventListener("hidden.bs.modal", () => {\n  $("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  window.location.href = `/api/download?path=${encodeURIComponent(path)}`;\n}\n\nasync function mkdirFromContext() {\n  const name = prompt("Nombre de la nueva carpeta:");\n  if (!name || !name.trim()) return;\n\n  try {\n    await api("/api/mkdir", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: cwd, name: name.trim()})\n    });\n    showMessage("Carpeta creada", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction uploadFromContext() {\n  $("fileInput").click();\n}\n\nasync function uploadSelectedFiles() {\n  const input = $("fileInput");\n  if (!input.files.length) return;\n\n  const form = new FormData();\n  form.append("path", cwd);\n  for (const file of input.files) {\n    form.append("files", file);\n  }\n\n  try {\n    await api("/api/upload", {\n      method: "POST",\n      body: form\n    });\n    input.value = "";\n    showMessage("Subida completada", "success");\n    await loadList();\n  } catch (err) {\n    input.value = "";\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function deleteItems(items) {\n  if (!items.length) return;\n  const ok = confirm(`Eliminar seleccionados ${items.length}  elemento(s)?？También se eliminará todo el contenido dentro de las carpetas.`);\n  if (!ok) return;\n\n  try {\n    for (const item of items) {\n      await api("/api/delete", {\n        method: "POST",\n        headers: {"Content-Type": "application/json"},\n        body: JSON.stringify({path: item.path})\n      });\n    }\n    showMessage("Eliminación completada", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function renameItem(item) {\n  const name = prompt("Introduce un nuevo nombre:", item.name);\n  if (!name || name === item.name) return;\n\n  try {\n    await api("/api/rename", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: item.path, name})\n    });\n    showMessage("Renombrado completado", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function moveItems(items) {\n  if (!items.length) return;\n\n  if (items.length === 1) {\n    const dst = prompt("Introduce la ruta relativa de destino, por ejemplo docs/a.txt o backup/folder", items[0].path);\n    if (!dst || dst === items[0].path) return;\n\n    try {\n      await api("/api/move", {\n        method: "POST",\n        headers: {"Content-Type": "application/json"},\n        body: JSON.stringify({src: items[0].path, dst})\n      });\n      showMessage("Movimiento completado", "success");\n      await loadList();\n    } catch (err) {\n      showMessage(err.message, "danger");\n    }\n    return;\n  }\n\n  const targetDir = prompt("Introduce la carpeta de destino relativa, por ejemplo backup o docs/2026");\n  if (targetDir === null) return;\n\n  try {\n    for (const item of items) {\n      const dst = targetDir ? `${targetDir.replace(/\\/+$/, "")}/${item.name}` : item.name;\n      await api("/api/move", {\n        method: "POST",\n        headers: {"Content-Type": "application/json"},\n        body: JSON.stringify({src: item.path, dst})\n      });\n    }\n    showMessage("Movimiento completado", "success");\n    await loadList();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function shareItem(item) {\n  try {\n    const data = await api("/api/share", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({path: item.path})\n    });\n\n    let copied = false;\n    try {\n      await navigator.clipboard.writeText(data.url);\n      copied = true;\n    } catch (_) {\n      copied = false;\n    }\n\n    showMessage(copied ? `Enlace creado. Copiado: ${data.url}` : `Enlace creado. Cópialo manualmente: ${data.url}`, "success");\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function archiveItems(items) {\n  if (!items.length) return;\n  try {\n    showMessage("Creando archivo 7z, espera……", "muted");\n    const data = await api("/api/archive", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({\n        cwd,\n        paths: items.map(x => x.path)\n      })\n    });\n    showMessage(`Archivo creado: ${fmtSize(data.size)}`, "success");\n    window.location.href = data.url;\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nasync function showShares() {\n  try {\n    const data = await api("/api/shares");\n    const box = $("sharesList");\n    if (!data.shares.length) {\n      box.innerHTML = `<div class="text-muted">Aún no hay enlaces compartidos</div>`;\n    } else {\n      box.innerHTML = "";\n      for (const s of data.shares) {\n        const div = document.createElement("div");\n        div.className = "border rounded p-2 mb-2";\n        div.innerHTML = `\n          <div><strong>${s.name}</strong> <span class="badge text-bg-light">${s.type}</span></div>\n          <div class="text-break"><a href="${s.url}" target="_blank">${s.url}</a></div>\n          <div class="text-muted">Ruta: /${s.path || ""}</div>\n        `;\n        const del = document.createElement("button");\n        del.className = "btn btn-sm btn-outline-danger mt-2";\n        del.textContent = "Revocar enlace";\n        del.onclick = async () => {\n          await api(`/api/share/${s.token}`, {method: "DELETE"});\n          showShares();\n        };\n        div.appendChild(del);\n        box.appendChild(div);\n      }\n    }\n    new bootstrap.Modal($("sharesModal")).show();\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction setMenuVisible(action, visible) {\n  const el = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (el) el.style.display = visible ? "block" : "none";\n}\n\nfunction setSepVisible(name, visible) {\n  const el = document.querySelector(`#contextMenu [data-sep="${name}"]`);\n  if (el) el.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = $("contextMenu");\n  const items = mode === "item" ? getContextItems() : [];\n  const single = items.length === 1;\n  const item = single ? items[0] : null;\n\n  ["open", "download", "archive", "share", "rename", "move", "delete", "mkdir", "upload", "refresh", "shares"]\n    .forEach(a => setMenuVisible(a, false));\n  setSepVisible("item", false);\n\n  if (mode === "blank") {\n    selectedPaths.clear();\n    syncSelectionUI();\n    setMenuVisible("mkdir", true);\n    setMenuVisible("upload", true);\n    setMenuVisible("refresh", true);\n    setMenuVisible("shares", true);\n  } else if (single && item.type === "dir") {\n    setMenuVisible("open", true);\n    setMenuVisible("archive", true);\n    setMenuVisible("share", true);\n    setMenuVisible("delete", true);\n    setMenuVisible("rename", true);\n  } else if (single && item.type === "file") {\n    setMenuVisible("open", true);\n    setMenuVisible("download", true);\n    setMenuVisible("share", true);\n    setMenuVisible("rename", true);\n    setMenuVisible("move", true);\n    setMenuVisible("delete", true);\n    // No mostrar 7z para un solo archivo；el archivo ya tiene descarga directa.\n  } else if (items.length > 1) {\n    setMenuVisible("archive", true);\n    setMenuVisible("move", true);\n    setMenuVisible("delete", true);\n  } else {\n    return;\n  }\n\n  const openBtn = menu.querySelector(\'[data-action="open"]\');\n  if (openBtn && single) openBtn.textContent = openActionLabel(item);\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = $("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\nfunction setupContextMenu() {\n  $("contextMenu").addEventListener("click", async (e) => {\n    const btn = e.target.closest("button[data-action]");\n    if (!btn) return;\n    const action = btn.dataset.action;\n    const items = getContextItems();\n    hideContextMenu();\n\n    if (action === "mkdir") return mkdirFromContext();\n    if (action === "upload") return uploadFromContext();\n    if (action === "refresh") return loadList();\n    if (action === "shares") return showShares();\n\n    if (!items.length) return;\n\n    if (action === "open" && items.length === 1) openItem(items[0]);\n    if (action === "download" && items.length === 1) downloadItem(items[0].path);\n    if (action === "archive") archiveItems(items);\n    if (action === "share" && items.length === 1) shareItem(items[0]);\n    if (action === "rename" && items.length === 1) renameItem(items[0]);\n    if (action === "move") moveItems(items);\n    if (action === "delete") deleteItems(items);\n  });\n\n  document.addEventListener("click", (e) => {\n    if (!e.target.closest("#contextMenu")) hideContextMenu();\n  });\n\n  $("filePane").addEventListener("contextmenu", (e) => {\n    if (!e.target.closest(".file-item")) {\n      e.preventDefault();\n      contextTargetPath = null;\n      showContextMenu(e.clientX, e.clientY, "blank");\n    }\n  });\n}\n\nfunction rectsIntersect(a, b) {\n  return !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);\n}\n\nfunction setupDragSelection() {\n  const pane = $("filePane");\n  const box = $("selectionBox");\n\n  pane.addEventListener("mousedown", (e) => {\n    if (e.button !== 0) return;\n    if (e.target.closest(".file-item")) return;\n    if (e.target.closest("#contextMenu")) return;\n\n    const startX = e.clientX;\n    const startY = e.clientY;\n    dragState = {startX, startY, moved: false, additive: e.ctrlKey || e.metaKey};\n    if (!dragState.additive) {\n      selectedPaths.clear();\n      syncSelectionUI();\n    }\n\n    box.style.left = `${startX}px`;\n    box.style.top = `${startY}px`;\n    box.style.width = "0px";\n    box.style.height = "0px";\n    box.style.display = "block";\n    e.preventDefault();\n  });\n\n  document.addEventListener("mousemove", (e) => {\n    if (!dragState) return;\n\n    const x1 = Math.min(dragState.startX, e.clientX);\n    const y1 = Math.min(dragState.startY, e.clientY);\n    const x2 = Math.max(dragState.startX, e.clientX);\n    const y2 = Math.max(dragState.startY, e.clientY);\n\n    if (Math.abs(x2 - x1) > 3 || Math.abs(y2 - y1) > 3) {\n      dragState.moved = true;\n    }\n\n    box.style.left = `${x1}px`;\n    box.style.top = `${y1}px`;\n    box.style.width = `${x2 - x1}px`;\n    box.style.height = `${y2 - y1}px`;\n\n    const selectionRect = {left: x1, top: y1, right: x2, bottom: y2};\n    document.querySelectorAll(".file-item").forEach(row => {\n      const r = row.getBoundingClientRect();\n      if (rectsIntersect(selectionRect, r)) {\n        selectedPaths.add(row.dataset.path);\n      } else if (!dragState.additive) {\n        selectedPaths.delete(row.dataset.path);\n      }\n    });\n    syncSelectionUI();\n  });\n\n  document.addEventListener("mouseup", () => {\n    if (!dragState) return;\n    setTimeout(() => { dragState = null; }, 0);\n    box.style.display = "none";\n  });\n}\n\ndocument.addEventListener("keydown", (e) => {\n  if (e.key === "F5") {\n    e.preventDefault();\n    loadList();\n  }\n});\n\n$("fileInput").addEventListener("change", uploadSelectedFiles);\n\nsetupContextMenu();\nsetupDragSelection();\nloadList("");\n\n</script>\n</body>\n</html>\n'

EDITOR_HTML = '<!doctype html>\n<html lang="es">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Editor de texto</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n  overflow: hidden;\n  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n}\n\n#toolbar {\n  position: fixed;\n  top: 0;\n  left: 0;\n  right: 0;\n  height: 38px;\n  display: flex;\n  align-items: center;\n  gap: 10px;\n  padding: 0 10px;\n  background: #fffaf7;\n  border-bottom: 1px solid #f1b4a2;\n  z-index: 10;\n}\n\n#filename {\n  min-width: 0;\n  font-weight: 700;\n  color: #50322b;\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n#encoding,\n#status {\n  flex: 0 0 auto;\n  font-size: 12px;\n  color: #8a6a62;\n}\n\n#saveBtn,\n#downloadBtn {\n  flex: 0 0 auto;\n  border: 1px solid #e9795f;\n  background: #e9795f;\n  color: #fff;\n  border-radius: 8px;\n  padding: 6px 12px;\n  cursor: pointer;\n}\n\n#saveBtn {\n  margin-left: auto;\n}\n\n#downloadBtn {\n  background: #fff;\n  color: #c95d45;\n}\n\n#editor {\n  position: fixed;\n  top: 38px;\n  left: 0;\n  right: 0;\n  bottom: 0;\n  width: 100%;\n  height: calc(100% - 38px);\n  border: 0;\n  outline: none;\n  resize: none;\n  padding: 16px;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  color: #222;\n  background: #fff;\n}\n\n</style>\n</head>\n<body>\n  <div id="toolbar">\n    <span id="filename"></span>\n    <span id="encoding"></span>\n    <span id="status"></span>\n    <button id="saveBtn">Guardar</button>\n    <button id="downloadBtn">Descargar</button>\n  </div>\n  <textarea id="editor" spellcheck="false"></textarea>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\n\nconst editor = document.getElementById("editor");\nconst filename = document.getElementById("filename");\nconst encodingEl = document.getElementById("encoding");\nconst statusEl = document.getElementById("status");\nconst saveBtn = document.getElementById("saveBtn");\nconst downloadBtn = document.getElementById("downloadBtn");\n\nlet currentEncoding = "utf-8";\n\nfunction setStatus(text) {\n  statusEl.textContent = text;\n}\n\nasync function api(url, options = {}) {\n  const res = await fetch(url, options);\n  const data = await res.json();\n  if (!res.ok || data.ok === false) {\n    throw new Error(data.error || `Error de solicitud: ${res.status}`);\n  }\n  return data;\n}\n\nasync function loadText() {\n  try {\n    const data = await api(`/api/text?path=${encodeURIComponent(path)}`);\n    filename.textContent = data.name;\n    currentEncoding = data.encoding || "utf-8";\n    encodingEl.textContent = `Codificación: ${currentEncoding}`;\n    editor.value = data.text;\n    downloadBtn.onclick = () => {\n      location.href = `/api/download?path=${encodeURIComponent(path)}`;\n    };\n    setStatus("Cargado");\n  } catch (err) {\n    setStatus(err.message);\n    editor.value = "";\n  }\n}\n\nasync function saveText() {\n  try {\n    saveBtn.disabled = true;\n    await api("/api/text", {\n      method: "POST",\n      headers: {"Content-Type": "application/json"},\n      body: JSON.stringify({\n        path,\n        text: editor.value,\n        encoding: currentEncoding\n      })\n    });\n    setStatus(`Guardado ${new Date().toLocaleTimeString()}`);\n  } catch (err) {\n    setStatus(err.message);\n  } finally {\n    saveBtn.disabled = false;\n  }\n}\n\nsaveBtn.onclick = saveText;\n\neditor.addEventListener("keydown", (e) => {\n  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {\n    e.preventDefault();\n    saveText();\n  }\n});\n\nloadText();\n\n</script>\n</body>\n</html>\n'

VIEWER_HTML = '<!doctype html>\n<html lang="es">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Visor en línea</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody,\n#viewerRoot {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n}\n\nbody {\n  background: #fff;\n  color: #222;\n  overflow: hidden;\n  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;\n}\n\n#viewerRoot {\n  display: flex;\n  align-items: stretch;\n  justify-content: center;\n}\n\n#status {\n  margin: auto;\n  color: #8a6a62;\n  font-size: 14px;\n}\n\n.viewer-media {\n  width: 100%;\n  height: 100%;\n  max-height: 100vh;\n  background: #000;\n}\n\naudio.viewer-media {\n  width: min(900px, 92vw);\n  height: 44px;\n  margin: auto;\n  background: transparent;\n}\n\n.text-view {\n  width: 100%;\n  height: 100%;\n  margin: 0;\n  padding: 16px;\n  overflow: auto;\n  white-space: pre-wrap;\n  word-break: break-word;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  background: #fff;\n  color: #222;\n}\n\n</style>\n</head>\n<body>\n  <main id="viewerRoot">\n    <div id="status">Cargando……</div>\n  </main>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\nconst root = document.getElementById("viewerRoot");\n\nasync function jsonApi(url) {\n  const res = await fetch(url);\n  const data = await res.json();\n  if (!res.ok || data.ok === false) {\n    throw new Error(data.error || `Error de solicitud: ${res.status}`);\n  }\n  return data;\n}\n\nfunction extOf(name) {\n  const idx = name.lastIndexOf(".");\n  return idx >= 0 ? name.slice(idx).toLowerCase() : "";\n}\n\nasync function init() {\n  try {\n    const list = await jsonApi(`/api/list?path=${encodeURIComponent(parentPath(path))}`);\n    const item = list.items.find(x => x.path === path);\n\n    if (!item) {\n      throw new Error("El archivo no existe");\n    }\n\n    if (item.media === "video") {\n      root.innerHTML = `<video class="viewer-media" src="/api/media?path=${encodeURIComponent(path)}" controls autoplay></video>`;\n      return;\n    }\n\n    if (item.media === "audio") {\n      root.innerHTML = `<audio class="viewer-media" src="/api/media?path=${encodeURIComponent(path)}" controls autoplay></audio>`;\n      return;\n    }\n\n    if (item.editable) {\n      const data = await jsonApi(`/api/text?path=${encodeURIComponent(path)}`);\n      const pre = document.createElement("pre");\n      pre.className = "text-view";\n      pre.textContent = data.text;\n      root.innerHTML = "";\n      root.appendChild(pre);\n      return;\n    }\n\n    root.innerHTML = `<div id="status">Este archivo no admite vista en línea. Descárgalo.</div>`;\n  } catch (err) {\n    root.innerHTML = `<div id="status">${err.message}</div>`;\n  }\n}\n\nfunction parentPath(p) {\n  const parts = (p || "").split("/").filter(Boolean);\n  parts.pop();\n  return parts.join("/");\n}\n\ninit();\n\n</script>\n</body>\n</html>\n'

SHARE_HTML = '<!doctype html>\n<html lang="es">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Carpeta compartida - {{ name }}</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-header {\n  height: 38px;\n  padding: 6px 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: var(--warm-panel);\n}\n\n.page-modal-header .modal-title {\n  font-size: 13px;\n  color: var(--warm-text);\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: calc(100vh - 38px);\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div id="breadcrumb" class="breadcrumb-flat"></div>\n  <div class="path-meta">\n    <span class="readonly-badge">Compartido de solo lectura</span>\n    <span id="countText"></span>\n    <span class="hint">Clic para abrir/descargar · Clic derecho</span>\n  </div>\n</header>\n\n<main class="file-pane" id="filePane">\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="emptyState" class="empty-state d-none">Esta carpeta compartida está vacía</div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-header page-modal-header">\n        <div class="modal-title" id="pageModalTitle">Ver</div>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>\n      </div>\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="share-viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Abrir</button>\n  <button data-action="download">Descargar</button>\n  <button data-action="refresh">Actualizar</button>\n</div>\n\n<script>\n  window.SHARE_TOKEN = "{{ token }}";\n  window.SHARE_ROOT_NAME = "{{ name }}";\n</script>\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPath = null;\nlet currentItemCount = 0;\n\nconst token = window.SHARE_TOKEN;\nconst rootName = window.SHARE_ROOT_NAME || "Compartir";\nconst singleFileMode = Boolean(window.SHARE_SINGLE_FILE);\nconst $ = (id) => document.getElementById(id);\n\nfunction showMessage(text, type = "muted") {\n  const el = $("message");\n  if (!el) return;\n  el.className = `message small text-${type}`;\n  el.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (el.textContent === text) el.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url) {\n  const res = await fetch(url);\n  const data = await res.json();\n  if (!res.ok || data.ok === false) {\n    throw new Error(data.error || `Error de solicitud: ${res.status}`);\n  }\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    itemsByPath.clear();\n    selectedPath = null;\n\n    const data = await api(`/s/${token}/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = $("fileGrid");\n    grid.innerHTML = "";\n    const empty = $("emptyState");\n    if (empty) empty.classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n\n    if (singleFileMode && data.items.length === 1) {\n      selectedPath = data.items[0].path;\n      syncSelectionUI();\n    }\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction renderBreadcrumb() {\n  const box = $("breadcrumb");\n  if (!box) return;\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = rootName;\n  root.onclick = () => {\n    if (!singleFileMode) loadList("");\n  };\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const el = $("countText");\n  if (el) el.textContent = `${currentItemCount}  elemento(s)`;\n}\n\nfunction renderItem(item) {\n  const el = document.createElement("div");\n  el.className = "file-item";\n  el.dataset.path = item.path;\n  el.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Carpeta"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Carpeta" : (item.media || (item.editable ? "Texto" : fmtSize(item.size)));\n\n  el.append(icon, name, meta);\n\n  el.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  el.onclick = () => {\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  el.oncontextmenu = (e) => {\n    e.preventDefault();\n    selectedPath = item.path;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  return el;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", row.dataset.path === selectedPath);\n  });\n}\n\nfunction selectedItem() {\n  if (selectedPath === null) return null;\n  return itemsByPath.get(selectedPath) || null;\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media || item.editable) {\n    openPageModal(`Ver - ${item.name}`, `/share-viewer/${token}?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Abrir";\n  if (item.type === "dir") return "Abrir";\n  if (item.media) return "Reproducir en línea";\n  if (item.editable) return "Visor en línea";\n  return "Descargar";\n}\n\nfunction openPageModal(title, url) {\n  $("pageModalTitle").textContent = title;\n  $("pageFrame").src = url;\n  bootstrap.Modal.getOrCreateInstance($("pageModal")).show();\n}\n\n$("pageModal").addEventListener("hidden.bs.modal", () => {\n  $("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  location.href = `/s/${token}/download?path=${encodeURIComponent(path || "")}`;\n}\n\nfunction setMenuVisible(action, visible) {\n  const el = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (el) el.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = $("contextMenu");\n  ["open", "download", "refresh"].forEach(a => setMenuVisible(a, false));\n\n  const item = selectedItem();\n\n  if (mode === "blank") {\n    setMenuVisible("refresh", true);\n  } else if (item) {\n    setMenuVisible("open", true);\n    if (item.type === "file") setMenuVisible("download", true);\n    const openBtn = menu.querySelector(\'[data-action="open"]\');\n    if (openBtn) openBtn.textContent = openActionLabel(item);\n  } else {\n    return;\n  }\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = $("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\n$("contextMenu").addEventListener("click", (e) => {\n  const btn = e.target.closest("button[data-action]");\n  if (!btn) return;\n\n  const action = btn.dataset.action;\n  const item = selectedItem();\n  hideContextMenu();\n\n  if (action === "refresh") return loadList();\n  if (!item) return;\n\n  if (action === "open") openItem(item);\n  if (action === "download") downloadItem(item.path);\n});\n\ndocument.addEventListener("click", (e) => {\n  if (!e.target.closest("#contextMenu")) hideContextMenu();\n});\n\n$("filePane").addEventListener("contextmenu", (e) => {\n  if (!e.target.closest(".file-item")) {\n    e.preventDefault();\n    selectedPath = null;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "blank");\n  }\n});\n\nloadList("");\n\n</script>\n</body>\n</html>\n'

SHARE_FILE_HTML = '<!doctype html>\n<html lang="es">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Archivo compartido - {{ name }}</title>\n  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">\n  <style>\n:root {\n  --warm-bg: #fff8f5;\n  --warm-panel: #fffaf7;\n  --warm-soft: #ffe7dd;\n  --warm-main: #e9795f;\n  --warm-main-dark: #c95d45;\n  --warm-border: #efc1b3;\n  --warm-text: #50322b;\n  --muted: #8b6a62;\n}\n\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody {\n  height: 100%;\n}\n\nbody {\n  margin: 0;\n  background: var(--warm-bg);\n  color: var(--warm-text);\n  overflow: hidden;\n}\n\n.pathbar {\n  height: 40px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  padding: 0 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: linear-gradient(180deg, #fffdfb, #fff6f1);\n  box-shadow: 0 1px 8px rgba(80, 50, 43, 0.05);\n}\n\n.breadcrumb-flat {\n  min-width: 0;\n  display: flex;\n  align-items: center;\n  gap: 4px;\n  overflow: hidden;\n  white-space: nowrap;\n  font-size: 13px;\n}\n\n.crumb {\n  color: var(--warm-main-dark);\n  cursor: pointer;\n  border-radius: 7px;\n  padding: 2px 6px;\n  max-width: 220px;\n  overflow: hidden;\n  text-overflow: ellipsis;\n}\n\n.crumb:hover {\n  background: var(--warm-soft);\n}\n\n.crumb-sep {\n  color: var(--muted);\n}\n\n.path-meta {\n  flex: 0 0 auto;\n  display: flex;\n  align-items: center;\n  gap: 12px;\n  color: var(--muted);\n  font-size: 12px;\n}\n\n.file-pane {\n  position: relative;\n  height: calc(100vh - 40px);\n  overflow: auto;\n  padding: 12px 14px 28px;\n}\n\n.file-grid {\n  display: grid;\n  grid-template-columns: repeat(auto-fill, minmax(122px, 1fr));\n  gap: 8px;\n  align-content: start;\n}\n\n.file-item {\n  position: relative;\n  min-height: 106px;\n  padding: 10px 7px 8px;\n  border: 1px solid transparent;\n  border-radius: 11px;\n  background: transparent;\n  cursor: default;\n  user-select: none;\n}\n\n.file-item:hover {\n  background: rgba(255, 231, 221, 0.56);\n}\n\n.file-item.selected-row {\n  border-color: var(--warm-main);\n  background: rgba(233, 121, 95, 0.17);\n}\n\n.file-icon {\n  height: 46px;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  font-size: 35px;\n  line-height: 1;\n}\n\n.file-name {\n  margin-top: 7px;\n  font-size: 13px;\n  line-height: 1.24;\n  text-align: center;\n  overflow-wrap: anywhere;\n  color: var(--warm-text);\n}\n\n.file-meta {\n  margin-top: 3px;\n  font-size: 11px;\n  text-align: center;\n  color: var(--muted);\n}\n\n.message {\n  position: fixed;\n  left: 12px;\n  bottom: 10px;\n  max-width: min(720px, calc(100vw - 24px));\n  padding: 6px 9px;\n  border-radius: 9px;\n  background: rgba(255, 250, 247, 0.92);\n  color: var(--muted);\n  overflow-wrap: anywhere;\n  pointer-events: none;\n}\n\n.hidden-file-input {\n  display: none;\n}\n\n.empty-state {\n  position: absolute;\n  inset: 34% 0 auto;\n  text-align: center;\n  color: var(--muted);\n  font-size: 14px;\n}\n\n.context-menu {\n  position: fixed;\n  z-index: 2000;\n  min-width: 214px;\n  display: none;\n  padding: 6px;\n  border: 1px solid var(--warm-border);\n  border-radius: 12px;\n  background: #fff;\n  box-shadow: 0 16px 40px rgba(80, 50, 43, 0.18);\n}\n\n.context-menu button {\n  display: block;\n  width: 100%;\n  border: 0;\n  background: transparent;\n  padding: 9px 12px;\n  border-radius: 8px;\n  text-align: left;\n  color: var(--warm-text);\n  cursor: pointer;\n}\n\n.context-menu button:hover {\n  background: var(--warm-soft);\n}\n\n.context-menu button.danger {\n  color: #b42318;\n}\n\n.context-menu hr {\n  margin: 6px 0;\n  border-color: var(--warm-border);\n}\n\n#selectionBox {\n  position: fixed;\n  z-index: 1500;\n  display: none;\n  border: 1px solid var(--warm-main);\n  background: rgba(233, 121, 95, 0.12);\n  pointer-events: none;\n}\n\n.page-modal-content {\n  background: #fff;\n}\n\n.page-modal-header {\n  height: 38px;\n  padding: 6px 12px;\n  border-bottom: 1px solid var(--warm-border);\n  background: var(--warm-panel);\n}\n\n.page-modal-header .modal-title {\n  font-size: 13px;\n  color: var(--warm-text);\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.page-modal-body {\n  padding: 0;\n  height: calc(100vh - 38px);\n}\n\n#pageFrame {\n  display: block;\n  width: 100%;\n  height: 100%;\n  border: 0;\n  background: #fff;\n}\n\n.share-list-modal {\n  border-radius: 14px;\n}\n\n.btn-warm {\n  background-color: var(--warm-main);\n  border-color: var(--warm-main);\n  color: #fff;\n}\n\n.btn-warm:hover {\n  background-color: var(--warm-main-dark);\n  border-color: var(--warm-main-dark);\n  color: #fff;\n}\n\n@media (max-width: 760px) {\n  .hint {\n    display: none;\n  }\n\n  .path-meta {\n    gap: 6px;\n  }\n\n  .file-grid {\n    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));\n  }\n\n  .file-item {\n    min-height: 100px;\n  }\n}\n\n\n.readonly-badge {\n  display: inline-block;\n  padding: 2px 7px;\n  border-radius: 999px;\n  background: var(--warm-soft);\n  color: var(--warm-main-dark);\n  border: 1px solid var(--warm-border);\n}\n\n.single-share-file .file-grid {\n  grid-template-columns: repeat(auto-fill, minmax(122px, 140px));\n}\n\n</style>\n</head>\n<body>\n<header class="pathbar">\n  <div class="breadcrumb-flat">\n    <span class="crumb">Archivo compartido</span>\n    <span class="crumb-sep">/</span>\n    <span class="crumb">{{ name }}</span>\n  </div>\n  <div class="path-meta">\n    <span class="readonly-badge">Compartido de solo lectura</span>\n  </div>\n</header>\n\n<main class="file-pane single-share-file" id="filePane">\n  <div id="fileGrid" class="file-grid"></div>\n  <div id="message" class="message small"></div>\n</main>\n\n<div class="modal fade" id="pageModal" tabindex="-1" aria-hidden="true">\n  <div class="modal-dialog modal-fullscreen">\n    <div class="modal-content page-modal-content">\n      <div class="modal-header page-modal-header">\n        <div class="modal-title" id="pageModalTitle">Ver</div>\n        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>\n      </div>\n      <div class="modal-body page-modal-body">\n        <iframe id="pageFrame" title="share-viewer"></iframe>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div id="contextMenu" class="context-menu">\n  <button data-action="open">Abrir</button>\n  <button data-action="download">Descargar</button>\n</div>\n\n<script>\n  window.SHARE_TOKEN = "{{ token }}";\n  window.SHARE_ROOT_NAME = "{{ name }}";\n  window.SHARE_SINGLE_FILE = true;\n</script>\n<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>\n<script>\nlet cwd = "";\nlet itemsByPath = new Map();\nlet selectedPath = null;\nlet currentItemCount = 0;\n\nconst token = window.SHARE_TOKEN;\nconst rootName = window.SHARE_ROOT_NAME || "Compartir";\nconst singleFileMode = Boolean(window.SHARE_SINGLE_FILE);\nconst $ = (id) => document.getElementById(id);\n\nfunction showMessage(text, type = "muted") {\n  const el = $("message");\n  if (!el) return;\n  el.className = `message small text-${type}`;\n  el.textContent = text;\n  if (text) {\n    clearTimeout(showMessage._timer);\n    showMessage._timer = setTimeout(() => {\n      if (el.textContent === text) el.textContent = "";\n    }, 5000);\n  }\n}\n\nfunction fmtSize(bytes) {\n  if (bytes === null || bytes === undefined) return "-";\n  const units = ["B", "KB", "MB", "GB", "TB"];\n  let n = bytes;\n  let i = 0;\n  while (n >= 1024 && i < units.length - 1) {\n    n /= 1024;\n    i++;\n  }\n  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;\n}\n\nfunction fmtTime(ts) {\n  return new Date(ts * 1000).toLocaleString();\n}\n\nasync function api(url) {\n  const res = await fetch(url);\n  const data = await res.json();\n  if (!res.ok || data.ok === false) {\n    throw new Error(data.error || `Error de solicitud: ${res.status}`);\n  }\n  return data;\n}\n\nasync function loadList(path = cwd) {\n  try {\n    hideContextMenu();\n    itemsByPath.clear();\n    selectedPath = null;\n\n    const data = await api(`/s/${token}/api/list?path=${encodeURIComponent(path)}`);\n    cwd = data.cwd || "";\n    currentItemCount = data.items.length;\n\n    renderBreadcrumb();\n    updateCountText();\n\n    const grid = $("fileGrid");\n    grid.innerHTML = "";\n    const empty = $("emptyState");\n    if (empty) empty.classList.toggle("d-none", data.items.length > 0);\n\n    for (const item of data.items) {\n      itemsByPath.set(item.path, item);\n      grid.appendChild(renderItem(item));\n    }\n    syncSelectionUI();\n\n    if (singleFileMode && data.items.length === 1) {\n      selectedPath = data.items[0].path;\n      syncSelectionUI();\n    }\n  } catch (err) {\n    showMessage(err.message, "danger");\n  }\n}\n\nfunction renderBreadcrumb() {\n  const box = $("breadcrumb");\n  if (!box) return;\n  box.innerHTML = "";\n\n  const root = document.createElement("span");\n  root.className = "crumb";\n  root.textContent = rootName;\n  root.onclick = () => {\n    if (!singleFileMode) loadList("");\n  };\n  box.appendChild(root);\n\n  const parts = cwd.split("/").filter(Boolean);\n  let acc = "";\n  parts.forEach(part => {\n    const sep = document.createElement("span");\n    sep.className = "crumb-sep";\n    sep.textContent = "/";\n    box.appendChild(sep);\n\n    acc = acc ? `${acc}/${part}` : part;\n    const crumb = document.createElement("span");\n    crumb.className = "crumb";\n    crumb.textContent = part;\n    const target = acc;\n    crumb.onclick = () => loadList(target);\n    box.appendChild(crumb);\n  });\n}\n\nfunction updateCountText() {\n  const el = $("countText");\n  if (el) el.textContent = `${currentItemCount}  elemento(s)`;\n}\n\nfunction renderItem(item) {\n  const el = document.createElement("div");\n  el.className = "file-item";\n  el.dataset.path = item.path;\n  el.title = `${item.name}\\n${item.type === "file" ? fmtSize(item.size) : "Carpeta"}\\n${fmtTime(item.modified)}`;\n\n  const icon = document.createElement("div");\n  icon.className = "file-icon";\n  icon.textContent = iconFor(item);\n\n  const name = document.createElement("div");\n  name.className = "file-name";\n  name.textContent = item.name;\n\n  const meta = document.createElement("div");\n  meta.className = "file-meta";\n  meta.textContent = item.type === "dir" ? "Carpeta" : (item.media || (item.editable ? "Texto" : fmtSize(item.size)));\n\n  el.append(icon, name, meta);\n\n  el.ondblclick = (e) => {\n    e.stopPropagation();\n    openItem(item);\n  };\n\n  el.onclick = () => {\n    if (item.type === "dir") {\n      loadList(item.path);\n    } else {\n      downloadItem(item.path);\n    }\n  };\n\n  el.oncontextmenu = (e) => {\n    e.preventDefault();\n    selectedPath = item.path;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "item");\n  };\n\n  return el;\n}\n\nfunction iconFor(item) {\n  if (item.type === "dir") return "📁";\n  if (item.media === "video") return "🎬";\n  if (item.media === "audio") return "🎵";\n  if (item.editable) return "📝";\n  return "📄";\n}\n\nfunction syncSelectionUI() {\n  document.querySelectorAll(".file-item").forEach(row => {\n    row.classList.toggle("selected-row", row.dataset.path === selectedPath);\n  });\n}\n\nfunction selectedItem() {\n  if (selectedPath === null) return null;\n  return itemsByPath.get(selectedPath) || null;\n}\n\nfunction openItem(item) {\n  if (item.type === "dir") {\n    loadList(item.path);\n  } else if (item.media || item.editable) {\n    openPageModal(`Ver - ${item.name}`, `/share-viewer/${token}?path=${encodeURIComponent(item.path)}`);\n  } else {\n    downloadItem(item.path);\n  }\n}\n\nfunction openActionLabel(item) {\n  if (!item) return "Abrir";\n  if (item.type === "dir") return "Abrir";\n  if (item.media) return "Reproducir en línea";\n  if (item.editable) return "Visor en línea";\n  return "Descargar";\n}\n\nfunction openPageModal(title, url) {\n  $("pageModalTitle").textContent = title;\n  $("pageFrame").src = url;\n  bootstrap.Modal.getOrCreateInstance($("pageModal")).show();\n}\n\n$("pageModal").addEventListener("hidden.bs.modal", () => {\n  $("pageFrame").src = "about:blank";\n});\n\nfunction downloadItem(path) {\n  location.href = `/s/${token}/download?path=${encodeURIComponent(path || "")}`;\n}\n\nfunction setMenuVisible(action, visible) {\n  const el = document.querySelector(`#contextMenu [data-action="${action}"]`);\n  if (el) el.style.display = visible ? "block" : "none";\n}\n\nfunction showContextMenu(x, y, mode = "blank") {\n  const menu = $("contextMenu");\n  ["open", "download", "refresh"].forEach(a => setMenuVisible(a, false));\n\n  const item = selectedItem();\n\n  if (mode === "blank") {\n    setMenuVisible("refresh", true);\n  } else if (item) {\n    setMenuVisible("open", true);\n    if (item.type === "file") setMenuVisible("download", true);\n    const openBtn = menu.querySelector(\'[data-action="open"]\');\n    if (openBtn) openBtn.textContent = openActionLabel(item);\n  } else {\n    return;\n  }\n\n  menu.style.display = "block";\n\n  const rect = menu.getBoundingClientRect();\n  const left = Math.min(x, window.innerWidth - rect.width - 8);\n  const top = Math.min(y, window.innerHeight - rect.height - 8);\n\n  menu.style.left = `${Math.max(8, left)}px`;\n  menu.style.top = `${Math.max(8, top)}px`;\n}\n\nfunction hideContextMenu() {\n  const menu = $("contextMenu");\n  if (menu) menu.style.display = "none";\n}\n\n$("contextMenu").addEventListener("click", (e) => {\n  const btn = e.target.closest("button[data-action]");\n  if (!btn) return;\n\n  const action = btn.dataset.action;\n  const item = selectedItem();\n  hideContextMenu();\n\n  if (action === "refresh") return loadList();\n  if (!item) return;\n\n  if (action === "open") openItem(item);\n  if (action === "download") downloadItem(item.path);\n});\n\ndocument.addEventListener("click", (e) => {\n  if (!e.target.closest("#contextMenu")) hideContextMenu();\n});\n\n$("filePane").addEventListener("contextmenu", (e) => {\n  if (!e.target.closest(".file-item")) {\n    e.preventDefault();\n    selectedPath = null;\n    syncSelectionUI();\n    showContextMenu(e.clientX, e.clientY, "blank");\n  }\n});\n\nloadList("");\n\n</script>\n</body>\n</html>\n'

SHARE_VIEWER_HTML = '<!doctype html>\n<html lang="es">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Visor compartido</title>\n  <style>\n* {\n  box-sizing: border-box;\n}\n\nhtml,\nbody,\n#viewerRoot {\n  margin: 0;\n  width: 100%;\n  height: 100%;\n}\n\nbody {\n  background: #fff;\n  color: #222;\n  overflow: hidden;\n  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;\n}\n\n#viewerRoot {\n  display: flex;\n  align-items: stretch;\n  justify-content: center;\n}\n\n#status {\n  margin: auto;\n  color: #8a6a62;\n  font-size: 14px;\n}\n\n.viewer-media {\n  width: 100%;\n  height: 100%;\n  max-height: 100vh;\n  background: #000;\n}\n\naudio.viewer-media {\n  width: min(900px, 92vw);\n  height: 44px;\n  margin: auto;\n  background: transparent;\n}\n\n.text-view {\n  width: 100%;\n  height: 100%;\n  margin: 0;\n  padding: 16px;\n  overflow: auto;\n  white-space: pre-wrap;\n  word-break: break-word;\n  font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;\n  background: #fff;\n  color: #222;\n}\n\n</style>\n</head>\n<body>\n  <main id="viewerRoot">\n    <div id="status">Cargando……</div>\n  </main>\n  <script>\n    window.SHARE_TOKEN = "{{ token }}";\n  </script>\n  <script>\nconst params = new URLSearchParams(location.search);\nconst path = params.get("path") || "";\nconst token = window.SHARE_TOKEN;\nconst root = document.getElementById("viewerRoot");\n\nasync function jsonApi(url) {\n  const res = await fetch(url);\n  const data = await res.json();\n  if (!res.ok || data.ok === false) {\n    throw new Error(data.error || `Error de solicitud: ${res.status}`);\n  }\n  return data;\n}\n\nasync function init() {\n  try {\n    const list = await jsonApi(`/s/${token}/api/list?path=${encodeURIComponent(parentPath(path))}`);\n    const item = list.items.find(x => x.path === path) || list.items[0];\n\n    if (!item) {\n      throw new Error("El archivo no existe");\n    }\n\n    const effectivePath = item.path || "";\n\n    if (item.media === "video") {\n      root.innerHTML = `<video class="viewer-media" src="/s/${token}/media?path=${encodeURIComponent(effectivePath)}" controls autoplay></video>`;\n      return;\n    }\n\n    if (item.media === "audio") {\n      root.innerHTML = `<audio class="viewer-media" src="/s/${token}/media?path=${encodeURIComponent(effectivePath)}" controls autoplay></audio>`;\n      return;\n    }\n\n    if (item.editable) {\n      const data = await jsonApi(`/s/${token}/text?path=${encodeURIComponent(effectivePath)}`);\n      const pre = document.createElement("pre");\n      pre.className = "text-view";\n      pre.textContent = data.text;\n      root.innerHTML = "";\n      root.appendChild(pre);\n      return;\n    }\n\n    root.innerHTML = `<div id="status">Este archivo no admite vista en línea. Descárgalo.</div>`;\n  } catch (err) {\n    root.innerHTML = `<div id="status">${err.message}</div>`;\n  }\n}\n\nfunction parentPath(p) {\n  const parts = (p || "").split("/").filter(Boolean);\n  parts.pop();\n  return parts.join("/");\n}\n\ninit();\n\n</script>\n</body>\n</html>\n'


if __name__ == "__main__":
    print("Usuario predeterminado: admin")
    print("Contraseña predeterminada: admin123")
    print("Puedes cambiarlo con FM_USERNAME / FM_PASSWORD.")
    app.run(host="0.0.0.0", port=5000, debug=True)
