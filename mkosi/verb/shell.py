# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import getpass
import itertools
import os
import resource
import socket
import sys
import uuid
from pathlib import Path

from mkosi.config import (
    Args,
    Config,
    ConfigFeature,
    Network,
    OutputFormat,
    Verb,
    yes_no,
)
from mkosi.log import die
from mkosi.run import run, workdir
from mkosi.user import become_root_cmd
from mkosi.util import PathString, copyfile2, format_rlimit
from mkosi.verb.qemu import (
    copy_ephemeral,
    finalize_credentials,
    finalize_kernel_command_line_extra,
    start_journal_remote,
)


def run_shell(args: Args, config: Config) -> None:
    opname = "acquire shell in" if args.verb == Verb.shell else "boot"
    if config.output_format not in (OutputFormat.directory, OutputFormat.disk):
        die(f"Cannot {opname} {config.output_format} images with systemd-nspawn")
    if config.output_format.use_outer_compression() and config.compress_output:
        die(f"Cannot {opname} compressed {config.output_format} images with systemd-nspawn")

    cmdline: list[PathString] = ["systemd-nspawn", "--quiet", "--link-journal=no", "--suppress-sync=yes"]

    if config.runtime_network == Network.user:
        cmdline += ["--resolv-conf=auto"]
    elif config.runtime_network == Network.interface:
        cmdline += ["--private-network", "--network-veth"]
    elif config.runtime_network == Network.none:
        cmdline += ["--private-network"]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings:
        cmdline += ["--settings=trusted"]

    if args.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += [
            f"--rlimit=RLIMIT_CORE={format_rlimit(resource.RLIMIT_CORE)}",
            "--console=autopipe",
        ]

    # Underscores are not allowed in machine names so replace them with hyphens.
    name = config.machine_or_name().replace("_", "-")
    cmdline += ["--machine", name, "--register", yes_no(config.register != ConfigFeature.disabled)]

    with contextlib.ExitStack() as stack:
        for f in finalize_credentials(config, stack).iterdir():
            cmdline += [f"--load-credential={f.name}:{f}"]

        # Make sure the latest nspawn settings are always used.
        if config.nspawn_settings:
            if not (config.output_dir_or_cwd() / f"{name}.nspawn").exists():
                stack.callback((config.output_dir_or_cwd() / f"{name}.nspawn").unlink, missing_ok=True)
            copyfile2(config.nspawn_settings, config.output_dir_or_cwd() / f"{name}.nspawn")

        fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))

        if config.output_format == OutputFormat.disk and args.verb == Verb.boot:
            run(
                [
                    "systemd-repart",
                    "--image", workdir(fname),
                    *([f"--size={config.runtime_size}"] if config.runtime_size else []),
                    "--no-pager",
                    "--dry-run=no",
                    "--offline=no",
                    "--pretty=no",
                    workdir(fname),
                ],
                stdin=sys.stdin,
                env=config.finalize_environment(),
                sandbox=config.sandbox(
                    network=True,
                    devices=True,
                    options=["--bind", fname, workdir(fname)],
                ),
                setup=become_root_cmd(),
            )  # fmt: skip

        cmdline += ["--directory" if fname.is_dir() else "--image", fname]

        if config.runtime_build_sources:
            for t in config.build_sources:
                src, dst = t.with_prefix("/work/src")
                uidmap = "rootidmap" if src.stat().st_uid != 0 else "noidmap"
                cmdline += ["--bind", f"{src}:{dst}:norbind,{uidmap}"]

            if config.build_dir:
                uidmap = "rootidmap" if config.build_subdir.stat().st_uid != 0 else "noidmap"
                cmdline += ["--bind", f"{config.build_subdir}:/work/build:norbind,{uidmap}"]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or "")
            # We add norbind because very often RuntimeTrees= will be used to mount the source
            # directory into the container and the output directory from which we're running will
            # very likely be a subdirectory of the source directory which would mean we'd be
            # mounting the container root directory as a subdirectory in itself which tends to lead
            # to all kinds of weird issues, which we avoid by not doing a recursive mount which
            # means the container root directory mounts will be skipped.
            uidmap = "rootidmap" if tree.source.stat().st_uid != 0 else "noidmap"
            cmdline += ["--bind", f"{tree.source}:{target}:norbind,{uidmap}"]

        if config.bind_user:
            cmdline += ["--bind-user", getpass.getuser(), "--bind-user-group=wheel"]

        if args.verb == Verb.boot and config.forward_journal:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                addr = (
                    Path(os.getenv("TMPDIR", "/tmp")) / f"mkosi-journal-remote-unix-{uuid.uuid4().hex[:16]}"
                )
                sock.bind(os.fspath(addr))
                sock.listen()
                if config.output_format == OutputFormat.directory and (stat := os.stat(fname)).st_uid != 0:
                    os.chown(addr, stat.st_uid, stat.st_gid)
                stack.enter_context(start_journal_remote(config, sock.fileno()))
                uidmap = "rootidmap" if addr.stat().st_uid != 0 else "noidmap"
                cmdline += [
                    f"--bind={addr}:/run/host/journal/socket:{uidmap}",
                    "--set-credential=journal.forward_to_socket:/run/host/journal/socket",
                ]

        if args.verb == Verb.boot:
            # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
            argv = args.cmdline

            # When invoked by the kernel, all unknown arguments are passed as environment variables
            # to pid1. Let's mimic the same behavior when we invoke nspawn as a container.
            for arg in itertools.chain(
                config.kernel_command_line,
                finalize_kernel_command_line_extra(args, config),
            ):
                name, sep, value = arg.partition("=")

                # If there's a '.' in the argument name, it's not considered an environment
                # variable by the kernel.
                if sep and "." not in name:
                    cmdline += ["--setenv", f"{name.replace('-', '_')}={value}"]
                else:
                    # kernel cmdline config of the form systemd.xxx= get interpreted by systemd
                    # when running in nspawn as well.
                    argv += [arg]

            cmdline += argv
        elif args.cmdline:
            cmdline += ["--"]
            cmdline += args.cmdline

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | config.finalize_environment(),
            log=False,
            sandbox=config.sandbox(
                devices=True,
                network=True,
                relaxed=True,
                options=["--same-dir"],
            ),
        )
