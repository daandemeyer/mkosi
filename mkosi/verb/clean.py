# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import functools
import os
import sys

from mkosi.config import Args, Config, Incremental, Verb
from mkosi.log import ARG_DEBUG, complete_step
from mkosi.mounts import finalize_source_mounts
from mkosi.run import run
from mkosi.tree import rmtree
from mkosi.util import flock_or_die, one_zero


def run_clean_scripts(config: Config) -> None:
    # Import here to avoid circular dependency with mkosi.__init__
    from mkosi import check_script, finalize_config_json

    if not config.clean_scripts:
        return

    for script in config.clean_scripts:
        check_script(config, script)

    env = dict(
        DISTRIBUTION=str(config.distribution),
        RELEASE=config.release,
        ARCHITECTURE=str(config.architecture),
        DISTRIBUTION_ARCHITECTURE=config.distribution.installer.architecture(config.architecture),
        SRCDIR="/work/src",
        OUTPUTDIR="/work/out",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if config.architecture.to_efi() is not None:
        env["EFI_ARCHITECTURE"] = str(config.architecture.to_efi())

    if config.profiles:
        env["PROFILES"] = " ".join(config.profiles)

    with (
        finalize_source_mounts(config, ephemeral=False) as sources,
        finalize_config_json(config) as json,
    ):
        for script in config.clean_scripts:
            with complete_step(f"Running clean script {script}…"):
                run(
                    ["/work/clean"],
                    env=env | config.finalize_environment(),
                    sandbox=config.sandbox(
                        tools=False,
                        options=[
                            "--dir", "/work/src",
                            "--chdir", "/work/src",
                            "--dir", "/work/out",
                            "--ro-bind", script, "/work/clean",
                            "--ro-bind", json, "/work/config.json",
                            *(["--bind", os.fspath(o), "/work/out"] if (o := config.output_dir_or_cwd()).exists() else []),  # noqa: E501
                            *sources,
                        ],
                    ),
                    stdin=sys.stdin,
                )  # fmt: skip


def run_clean(args: Args, config: Config, repository_metadata_needs_sync: bool = False) -> None:
    # Import here to avoid circular dependency with mkosi.__init__
    from mkosi import cache_tree_paths, have_cache, keyring_cache, metadata_cache

    # We remove any cached images if either the user used --force twice, or he/she called "clean"
    # with it passed once. Let's also remove the downloaded package cache if the user specified one
    # additional "--force".

    # We don't want to require a tools tree to run mkosi clean so we pass in a sandbox that
    # disables use of the tools tree. We still need a sandbox as we need to acquire privileges to
    # be able to remove various files from the rootfs.
    sandbox = functools.partial(config.sandbox, tools=False)

    if args.verb == Verb.clean:
        remove_outputs = True
        remove_build_cache = args.force > 0 or args.wipe_build_dir
        remove_image_cache = args.force > 0
        remove_package_cache = args.force > 1
    else:
        # Rely on the fact that True is 1 and False is 0 in numeric contexts.
        remove_outputs = args.force > (config.incremental == Incremental.relaxed) or (
            config.is_incremental() and not have_cache(config)
        )
        remove_build_cache = args.force > 1 or args.wipe_build_dir
        remove_image_cache = args.force > 1 or not have_cache(config) or repository_metadata_needs_sync
        remove_package_cache = args.force > 2

    if remove_outputs:
        outputs = {
            config.output_dir_or_cwd() / output
            for output in config.outputs
            if (
                (config.output_dir_or_cwd() / output).exists()
                or (config.output_dir_or_cwd() / output).is_symlink()
            )
        }

        # Make sure we resolve the symlink we create in the output directory and remove its target
        # as well as it might not be in the list of outputs anymore if the compression or output
        # format was changed.
        outputs |= {o.resolve() for o in outputs}

        if outputs:
            with (
                complete_step(f"Removing output files of {config.image} image…"),
                flock_or_die(config.output_dir_or_cwd() / config.output)
                if (config.output_dir_or_cwd() / config.output).exists()
                else contextlib.nullcontext(),
            ):
                rmtree(*outputs, sandbox=sandbox)

        run_clean_scripts(config)

    if (
        remove_build_cache
        and config.build_dir
        and config.build_subdir.exists()
        and any(config.build_subdir.iterdir())
    ):
        with complete_step(f"Clearing out build directory of {config.image} image…"):
            rmtree(*config.build_subdir.iterdir(), sandbox=sandbox)

    if remove_image_cache and config.cache_dir and any(p.exists() for p in cache_tree_paths(config)):
        with complete_step(f"Removing cache entries of {config.image} image…"):
            rmtree(*(p for p in cache_tree_paths(config) if p.exists()), sandbox=sandbox)

    if remove_package_cache and config.cache_dir and config.image in ("main", "tools"):
        with complete_step(f"Clearing out metadata and keyring cache of {config.image} image…"):
            rmtree(
                metadata_cache(config),
                keyring_cache(config),
                sandbox=sandbox,
            )
