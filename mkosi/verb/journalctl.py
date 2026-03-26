# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import sys

from mkosi.config import Args, Config, OutputFormat
from mkosi.log import die
from mkosi.run import run


def run_systemd_tool(tool: str, args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        die(f"{config.output_format} images cannot be inspected with {tool}")

    if (tool_path := config.find_binary(tool)) is None:
        die(f"Failed to find {tool}")

    if config.ephemeral:
        die(f"Images booted in ephemeral mode cannot be inspected with {tool}")

    if not (output := config.output_dir_or_cwd() / config.output).exists():
        die(
            f"Output {output} does not exist, cannot inspect with {tool}",
            hint=f"Build and boot the image first before inspecting it with {tool}",
        )

    run(
        [tool_path, "--root" if output.is_dir() else "--image", output, *args.cmdline],
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ | config.finalize_environment(),
        log=False,
        sandbox=config.sandbox(network=True, relaxed=True),
    )


def run_journalctl(args: Args, config: Config) -> None:
    run_systemd_tool("journalctl", args, config)


def run_coredumpctl(args: Args, config: Config) -> None:
    run_systemd_tool("coredumpctl", args, config)
