"""The `sheriffmark` distribution's entry-point package.

Everything that actually does the work lives in the existing hexagonal
packages (core/, adapters/, shared/, web/, worker/) — this package only
exists to give `pip install sheriffmark` a `sheriffmark` command (see
cli.py, [project.scripts] in pyproject.toml) that wires those together
for the single most common case: "download and run one process."
"""

__version__ = "0.1.0"
