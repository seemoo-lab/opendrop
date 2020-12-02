"""
OpenDrop: an open source AirDrop implementation
Copyright (C) 2018  Milan Stute
Copyright (C) 2018  Alexander Heinrich

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import platform

__version__ = "0.12.2"

if platform.system() == "Darwin":
    dyld_path = os.environ.get("DYLD_LIBRARY_PATH", "")  # save old path
    archive_path = "/usr/local/opt/libarchive/lib"
    os.environ["DYLD_LIBRARY_PATH"] = f"{dyld_path}:{archive_path}"

logger = logging.getLogger(__name__)
