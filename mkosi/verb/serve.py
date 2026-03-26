# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import signal
import sys
from contextlib import AbstractContextManager
from typing import Optional

from mkosi.bootloader import python_binary
from mkosi.config import Args, Config, ConfigFeature, OutputFormat
from mkosi.log import die
from mkosi.run import Popen, spawn
from mkosi.user import become_root_cmd


def start_storage_target_mode(config: Config) -> AbstractContextManager[Optional[Popen]]:
    if config.storage_target_mode == ConfigFeature.disabled:
        return contextlib.nullcontext()

    if config.storage_target_mode == ConfigFeature.auto and os.getuid() != 0:
        return contextlib.nullcontext()

    if config.output_format != OutputFormat.disk:
        if config.storage_target_mode == ConfigFeature.enabled:
            die("Storage target mode is only supported for the 'disk' output format")

        return contextlib.nullcontext()

    if not config.find_binary("/usr/lib/systemd/systemd-storagetm"):
        if config.storage_target_mode == ConfigFeature.enabled:
            die("Storage target mode enabled but systemd-storagetm is not installed")

        return contextlib.nullcontext()

    return spawn(
        ["/usr/lib/systemd/systemd-storagetm", config.output_with_format],
        stdin=sys.stdin,
        stdout=sys.stdout,
        sandbox=config.sandbox(
            network=True,
            relaxed=True,
            options=["--chdir", config.output_dir_or_cwd()],
        ),
        setup=become_root_cmd(),
    )


def run_serve(args: Args, config: Config) -> None:
    """Serve the output directory via a tiny HTTP server"""

    with contextlib.ExitStack() as stack:
        http = stack.enter_context(
            spawn(
                [python_binary(config), "-m", "http.server", "8081"],
                stdin=sys.stdin,
                stdout=sys.stdout,
                sandbox=config.sandbox(
                    network=True,
                    relaxed=True,
                    options=["--chdir", config.output_dir_or_cwd()],
                ),
            )
        )

        storagetm = stack.enter_context(start_storage_target_mode(config))

        # If we run systemd-storagetm with run0, it replaces the foreground process group with its own which
        # means the http process doesn't get SIGINT from the terminal, so let's send it ourselves in that
        # case.
        if storagetm and os.getuid() != 0:
            storagetm.wait()
            http.send_signal(signal.SIGINT)
