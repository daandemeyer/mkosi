# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import os
import sys

from mkosi.config import Args, Config
from mkosi.log import die
from mkosi.run import run
from mkosi.user import INVOKING_USER
from mkosi.util import PathString, flock


def run_ssh(args: Args, config: Config) -> None:
    statedir = INVOKING_USER.runtime_dir() / "mkosi/machine"
    with flock(statedir):
        if not (p := statedir / f"{config.machine_or_name()}.json").exists():
            die(
                f"{p} not found, cannot SSH into virtual machine {config.machine_or_name()}",
                hint="Is the machine running and was it built with Ssh=yes and Vsock=yes?",
            )

        state = json.loads(p.read_text())

    if not state["SshKey"]:
        die(
            "An SSH key must be configured when booting the image to use 'mkosi ssh'",
            hint="Use 'mkosi genkey' to generate a new SSH key and certificate",
        )

    cmd: list[PathString] = [
        "ssh",
        "-i", state["SshKey"],
        "-F", "none",
        # Silence known hosts file errors/warnings.
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "LogLevel=ERROR",
        "-o", f"ProxyCommand={state['ProxyCommand']}",
        "root@mkosi",
    ]  # fmt: skip

    cmd += args.cmdline

    run(
        cmd,
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ | config.finalize_environment() | {"SHELL": "/bin/bash"},
        log=False,
        sandbox=config.sandbox(
            network=True,
            devices=True,
            relaxed=True,
            # ssh insists on being able to resolve the current user which doesn't always work (think sssd or
            # similar) so let's switch to root which is always resolvable.
            options=["--same-dir", "--become-root"],
        ),
    )
