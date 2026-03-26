# SPDX-License-Identifier: LGPL-2.1-or-later

import datetime
import logging
import textwrap

from mkosi.config import Args, finalize_configdir
from mkosi.log import die, log_step
from mkosi.run import run


def generate_key_cert_pair(args: Args) -> None:
    """Generate a private key and accompanying X509 certificate using openssl"""

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(args.genkey_valid_days))

    configdir = finalize_configdir(args.directory)
    if not configdir:
        die("genkey cannot be used with empty --directory")

    for f in (configdir / "mkosi.key", configdir / "mkosi.crt"):
        if f.exists() and not args.force:
            die(
                f"{f} already exists",
                hint="To generate new keys, first remove mkosi.key and mkosi.crt",
            )

    log_step(f"Generating keys rsa:{keylength} for CN {args.genkey_common_name!r}.")
    logging.info(
        textwrap.dedent(
            f"""
            The keys will expire in {args.genkey_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey", f"rsa:{keylength}",
            "-keyout", configdir / "mkosi.key",
            "-out", configdir / "mkosi.crt",
            "-days", str(args.genkey_valid_days),
            "-subj", f"/CN={args.genkey_common_name}/",
            "-nodes"
        ],
        env=dict(OPENSSL_CONF="/dev/null"),
    )  # fmt: skip
