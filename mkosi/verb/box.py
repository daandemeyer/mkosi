# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import re
import sys
import tempfile
import zipapp
from pathlib import Path

from mkosi.config import Args, Config, in_box, systemd_pty_forward
from mkosi.distribution import detect_distribution
from mkosi.log import die
from mkosi.mounts import finalize_certificate_mounts
from mkosi.run import run
from mkosi.tree import copy_tree
from mkosi.util import make_executable, resource_path, scopedenv


def run_box(args: Args, config: Config) -> None:
    if not args.cmdline:
        die("Please specify a command to execute in the sandbox")

    mounts = finalize_certificate_mounts(config, relaxed=True)

    # Since we reuse almost every top level directory from the host except /usr and /etc, the crypto
    # mountpoints have to exist already in these directories or we'll fail with a permission error. Let's
    # check this early and show a better error and a suggestion on how users can fix this issue. We use
    # slice notation to get every 3rd item from the mounts list which is the destination path.
    for dst in mounts[2::3]:
        if not Path(dst).exists():
            die(
                f"Missing mountpoint {dst}",
                hint=f"Create an empty directory at {dst} using 'mkdir -p {dst}' as root and try again",
            )

    hd, hr = detect_distribution()

    env = {"MKOSI_IN_BOX": "1"}

    prefix = os.getenv("SHELL_PROMPT_PREFIX", "")
    m = re.search(r"\(box(?::(?P<level>[1-9][0-9]*))?\)", prefix)
    if in_box() and m:
        level = int(m.group("level") or 1) + 1
        prefix = prefix[: m.start()] + f"(box:{level})" + prefix[m.end() :]
    else:
        prefix = f"(box){prefix}"
    env |= {"SHELL_PROMPT_PREFIX": prefix}

    if hd:
        env |= {"MKOSI_HOST_DISTRIBUTION": str(hd)}
    if hr:
        env |= {"MKOSI_HOST_RELEASE": hr}
    if config.tools() != Path("/"):
        env |= {"MKOSI_DEFAULT_TOOLS_TREE_PATH": os.fspath(config.tools())}
    if config.extra_search_paths:
        extra = ":".join(os.fspath(p) for p in config.extra_search_paths)
        existing = os.environ.get("PYTHONPATH", "")
        env |= {"PYTHONPATH": f"{extra}:{existing}" if existing else extra}

    cmdline = [*args.cmdline]

    if sys.stdin.isatty() and sys.stdout.isatty():
        cmdline = systemd_pty_forward(config, background="48;2;12;51;51", title="mkosi-sandbox") + cmdline

    with contextlib.ExitStack() as stack:
        if config.tools() != Path("/"):
            d = stack.enter_context(tempfile.TemporaryDirectory(prefix="mkosi-path-"))

            # We have to point zipapp to a directory containing the mkosi module and set the entrypoint
            # manually instead of directly at the mkosi package, otherwise we get ModuleNotFoundError when
            # trying to run a zipapp created from a packaged version of mkosi. While zipapp.create_archive()
            # supports a filter= argument, trying to use this within a site-packages directory is rather slow
            # so we copy the mkosi package to a temporary directory instead which is much faster.
            with (
                tempfile.TemporaryDirectory(prefix="mkosi-zipapp-") as tmp,
                resource_path(sys.modules[__package__ or __name__]) as module,
            ):
                copy_tree(module, Path(tmp) / module.name, sandbox=config.sandbox)
                zipapp.create_archive(
                    source=tmp,
                    target=Path(d) / "mkosi",
                    main="mkosi.__main__:main",
                    interpreter="/usr/bin/env python3",
                )

            make_executable(Path(d) / "mkosi")
            mounts += ["--ro-bind", d, "/mkosi"]
            stack.enter_context(scopedenv({"PATH": f"/mkosi:{os.environ['PATH']}"}))

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | env,
            log=False,
            sandbox=config.sandbox(
                devices=True,
                network=True,
                relaxed=True,
                options=["--same-dir", *mounts],
            ),
        )
