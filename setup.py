import os
import re
from setuptools import find_packages, setup

# Based on https://github.com/mitmproxy/mitmproxy/blob/main/setup.py

here = os.path.abspath(os.path.dirname(__file__))

# get version
with open(os.path.join(here, "ae64", "ae64.py")) as f:
    match = re.search(r'VERSION = "(.+?)"', f.read())
    if not match:
        raise Exception("Can't find version string")
    VERSION = match.group(1)

# get requirements
with open(os.path.join(here, "requirements.txt")) as f:
    req = []
    for r in f.read().strip().split("\n"):
        if not r.startswith('#'):
            req.append(r)

setup(
    name="ae64",
    version=VERSION,
    description="AE64: amd64 shellcode alphanumeric encoder",
    packages=find_packages(
        include=["ae64", "ae64.*"]
    ),
    include_package_data=True,
    python_requires=">=3.6",
    install_requires=req
)