#!/usr/bin/env python3
"""
Sync clean project repository files to Google Drive folder 'soc-automation-main'.
Preserves folder hierarchy, updates existing files in-place (retaining IDs),
and uploads new files.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT_FOLDER_ID = "15x8G60Qt0JOD-EHh-nUgEK_WMCB1ymqF"
REPO_ROOT = Path(__file__).resolve().parent.parent


def run_gdrive(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["gdrive"] + args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )


def list_drive_folder(folder_id: str) -> list[dict]:
    try:
        res = run_gdrive(["readonly", "ls", folder_id, "--json"])
        out = res.stdout.strip()
        if not out or out == "null":
            return []
        return json.loads(out)
    except Exception as e:
        print(f"Error listing folder {folder_id}: {e}", file=sys.stderr)
        return []


def main():
    print(f"[*] Discovering existing structure in Drive folder {ROOT_FOLDER_ID}...")
    folder_map = {"": ROOT_FOLDER_ID}  # rel_dir -> folder_id
    file_map = {}  # (rel_dir, filename) -> {"id": id, "size": size}

    queue = [("", ROOT_FOLDER_ID)]
    while queue:
        rel_dir, fid = queue.pop(0)
        items = list_drive_folder(fid)
        for item in items:
            name = item["name"]
            item_id = item["id"]
            mime = item.get("mimeType", "")
            if mime == "application/vnd.google-apps.folder":
                sub_rel = f"{rel_dir}/{name}" if rel_dir else name
                folder_map[sub_rel] = item_id
                queue.append((sub_rel, item_id))
            else:
                file_map[(rel_dir, name)] = {
                    "id": item_id,
                    "size": int(item.get("size", 0)),
                }

    print(f"[+] Found {len(folder_map)} folders and {len(file_map)} files on Drive.")

    # Get clean git tracked + non-ignored untracked files
    res = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    tracked_files = sorted(set(f.strip() for f in res.stdout.splitlines() if f.strip()))
    print(f"[*] Found {len(tracked_files)} clean project files in repository.")

    # Get changed/untracked files in working tree + recent commit
    changed_files = set()
    for cmd in (
        ["git", "diff", "--name-only", "HEAD"],
        ["git", "diff", "--cached", "--name-only"],
        ["git", "ls-files", "--others", "--exclude-standard"],
        ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
    ):
        try:
            r = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
            changed_files.update(f.strip() for f in r.stdout.splitlines() if f.strip())
        except Exception:
            pass
    if not changed_files:
        changed_files = set(tracked_files)

    print(f"[*] Identified {len(changed_files)} recently modified or added files.")

    def ensure_drive_folder(rel_dir: str) -> str:
        if not rel_dir or rel_dir in folder_map:
            return folder_map[rel_dir]
        parent_dir = os.path.dirname(rel_dir)
        parent_id = ensure_drive_folder(parent_dir)
        folder_name = os.path.basename(rel_dir)
        print(f"[*] Creating folder on Drive: '{rel_dir}' in parent {parent_id}...")
        res = run_gdrive(["mutate", "mkdir", folder_name, "--parent", parent_id, "--json"])
        data = json.loads(res.stdout) if res.stdout.strip().startswith("{") else {}
        new_id = data.get("id")
        if not new_id:
            for item in list_drive_folder(parent_id):
                if item["name"] == folder_name:
                    new_id = item["id"]
                    break
        if not new_id:
            raise RuntimeError(f"Failed to obtain ID for created folder '{rel_dir}'")
        folder_map[rel_dir] = new_id
        return new_id

    updated_count = 0
    uploaded_count = 0
    skipped_count = 0

    for rel_path in sorted(tracked_files):
        local_path = REPO_ROOT / rel_path
        if not local_path.is_file():
            continue

        rel_dir = os.path.dirname(rel_path)
        filename = os.path.basename(rel_path)
        local_size = local_path.stat().st_size

        parent_folder_id = ensure_drive_folder(rel_dir)
        key = (rel_dir, filename)

        if key in file_map:
            remote_info = file_map[key]
            remote_id = remote_info["id"]
            remote_size = remote_info["size"]

            if rel_path in changed_files or local_size != remote_size:
                print(f"[UPDATE] {rel_path} (local: {local_size}B, remote: {remote_size}B) -> Drive ID {remote_id}...")
                try:
                    run_gdrive(["mutate", "update", remote_id, str(local_path)])
                    updated_count += 1
                except Exception as e:
                    print(f"  [ERROR] Failed to update {rel_path}: {e}", file=sys.stderr)
            else:
                skipped_count += 1
        else:
            print(f"[UPLOAD NEW] {rel_path} ({local_size}B) -> Parent {parent_folder_id}...")
            try:
                run_gdrive(["mutate", "upload", str(local_path), "--parent", parent_folder_id])
                uploaded_count += 1
            except Exception as e:
                print(f"  [ERROR] Failed to upload {rel_path}: {e}", file=sys.stderr)

    print("\n" + "=" * 60)
    print(f"SYNC COMPLETE: {updated_count} updated, {uploaded_count} newly uploaded, {skipped_count} skipped.")
    print("=" * 60)


if __name__ == "__main__":
    main()
