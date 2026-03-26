# SPDX-License-Identifier: LGPL-2.1-or-later

from mkosi.config import Args, Config


def run_latest_snapshot(args: Args, config: Config) -> None:
    print(config.distribution.installer.latest_snapshot(config))
