import os
import subprocess
import sys

from opendrop.config import AirDropConfig


def test_config_import_without_pkg_resources():
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.modules['pkg_resources'] = None; "
            "from opendrop.config import AirDropConfig",
        ],
        check=True,
    )


def test_bundled_root_certificate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AirDropConfig(airdrop_dir=str(tmp_path / "opendrop"))

    assert os.path.isfile(config.root_ca_file)
    context = config.get_ssl_context()
    assert context.cert_store_stats()["x509_ca"] > 0
