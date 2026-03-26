# SPDX-License-Identifier: LGPL-2.1-or-later

import logging

from mkosi.config import Args, Config, finalize_configdir
from mkosi.log import die


def finalize_image_version(args: Args, config: Config) -> None:
    configdir = finalize_configdir(args.directory)
    if not configdir:
        die("Image version cannot be finalized with empty --directory")
    p = configdir / "mkosi.version"
    assert config.image_version
    p.write_text(config.image_version)
    logging.info(f"Wrote new version {config.image_version} to {p}")
