"""The scanners, one module each; scanners.py describes what a module defines.

Adding a scanner: a new module here and one line in SCANNERS.
"""
from . import hibs, opensquat, shodan

# Scanner name (as stored in jobs.scanner and findings.scanner): its module.
SCANNERS = {"opensquat": opensquat, "hibs": hibs, "shodan": shodan}
