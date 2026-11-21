#!/usr/bin/env python3
"""RZP2 —— GNOME 文件管理器（Nautilus）右键菜单扩展。

在 Nautilus 右键菜单中集成 RZP2 的压缩 / 解压，后台执行不阻塞文件管理器。

RZP2 是单文件工具（不支持目录归档），因此仅对单文件提供菜单：
    - 选中单个普通文件    → 「用 RZP2 压缩」：生成同名 .rzp2
    - 选中单个 .rzp2 文件 → 「用 RZP2 解压」：解压到同目录（去掉 .rzp2 后缀）

安装（用户级）：
    1. 安装依赖（nautilus-python 与 python3-gi）：
         Debian/Ubuntu:  sudo apt install python3-nautilus python3-gi
         Fedora:         sudo dnf install nautilus-python python3-gobject
    2. 安装扩展：
         mkdir -p ~/.local/share/nautilus-python/extensions
         cp rzp2-menu.py ~/.local/share/nautilus-python/extensions/
    3. 确保 `rzp2` 在 PATH 中；否则用环境变量 RZP2_BIN 指定其绝对路径。
    4. 重启 Nautilus：`nautilus -q`（或注销重登）。
"""

import os
import shutil
import subprocess
import threading
import urllib.parse

import gi

# Nautilus 扩展 API 版本随 GTK4 迁移推进（新版 4.1，旧发行版可能 4.0 / 3.0），
# 逐级尝试取系统可用者。
for _ver in ("4.1", "4.0", "3.0"):
    try:
        gi.require_version("Nautilus", _ver)
        break
    except ValueError:
        continue

from gi.repository import Nautilus, GObject  # noqa: E402

# 可用环境变量 RZP2_BIN 覆盖 rzp2 可执行文件路径；否则从 PATH 查找。
RZP2_BIN = os.environ.get("RZP2_BIN") or shutil.which("rzp2")


def _notify(title, body):
    """尽量用 notify-send 弹系统通知；缺失时静默降级。"""
    try:
        subprocess.Popen(
            ["notify-send", "--app-name=RZP2", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


class Rzp2MenuProvider(GObject.GObject, Nautilus.MenuProvider):
    """在右键菜单中挂载 RZP2 压缩 / 解压入口。"""

    def __init__(self):
        super().__init__()

    # ---- 路径解析 ---------------------------------------------------------
    @staticmethod
    def _local_path(file_info):
        """返回 FileInfo 对应的本地路径；非本地（远程挂载等）返回 None。"""
        try:
            loc = file_info.get_location()
            if loc is not None:
                path = loc.get_path()
                if path:
                    return path
        except Exception:
            pass
        try:
            uri = file_info.get_uri()
            if uri and uri.startswith("file://"):
                return urllib.parse.unquote(uri[len("file://"):])
        except Exception:
            pass
        return None

    # ---- 后台执行 ---------------------------------------------------------
    def _run(self, args):
        if not RZP2_BIN:
            _notify("RZP2", "未找到 rzp2 可执行文件：请把 rzp2 安装到 PATH，或设置 RZP2_BIN。")
            return

        full = [RZP2_BIN] + args

        def worker():
            try:
                proc = subprocess.Popen(
                    full,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                _, stderr = proc.communicate()
                if proc.returncode == 0:
                    _notify("RZP2", "操作完成。")
                else:
                    tail = stderr.decode("utf-8", "replace").strip().splitlines()
                    detail = tail[-1] if tail else "退出码 {}".format(proc.returncode)
                    _notify("RZP2 操作失败", detail)
            except Exception as exc:  # noqa: BLE001
                _notify("RZP2 操作失败", str(exc))

        threading.Thread(target=worker, daemon=True).start()

    # ---- 菜单回调 ---------------------------------------------------------
    def _compress_cb(self, _menu, paths):
        # 单文件压缩：输出为 <path>.rzp2。
        self._run(["compress", paths[0], "-o", paths[0] + ".rzp2"])

    def _decompress_cb(self, _menu, paths):
        # 去掉 .rzp2 后缀作为输出；防御性兜底避免输出为空。
        path = paths[0]
        out = path[:-5] if path.endswith(".rzp2") else path + ".out"
        self._run(["decompress", path, "-o", out])

    # ---- 菜单提供 ---------------------------------------------------------
    def _item(self, name, label, callback, paths):
        item = Nautilus.MenuItem(name=name, label=label)
        item.connect("activate", callback, paths)
        return item

    def get_file_items(self, *args):
        files = args[-1] if args else []
        paths = [self._local_path(f) for f in files]
        paths = [p for p in paths if p]
        if not paths:
            return []

        # RZP2 为单文件工具：仅对单个选中项提供菜单。
        if len(paths) != 1:
            return []

        if paths[0].endswith(".rzp2"):
            return [self._item(
                "Rzp2MenuProvider::Decompress", "用 RZP2 解压", self._decompress_cb, paths,
            )]
        return [self._item(
            "Rzp2MenuProvider::Compress", "用 RZP2 压缩", self._compress_cb, paths,
        )]
