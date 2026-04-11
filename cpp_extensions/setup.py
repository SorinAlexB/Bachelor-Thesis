"""
Build script for the security_cpp pybind11 extension.

Build:
    cd cpp_extensions
    pip install pybind11
    pip install -e .

Or with explicit build:
    python setup.py build_ext --inplace
"""

from pathlib import Path
from setuptools import setup

try:
    from pybind11.setup_helpers import Pybind11Extension, build_ext
except ImportError:
    raise RuntimeError("pybind11 is required. Run: pip install pybind11")

ROOT = Path(__file__).parent

ext_modules = [
    Pybind11Extension(
        "security_cpp",
        sources=[
            "src/mitre_graph.cpp",
            "src/pattern_matcher.cpp",
            "src/bindings.cpp",
        ],
        include_dirs=["include"],
        extra_compile_args=["-O3", "-std=c++17", "-Wall"],
        language="c++",
    ),
]

setup(
    name="security_cpp",
    version="1.0.0",
    description="C++ extensions for the security AI pipeline (MITRE graph A* + Aho-Corasick)",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    python_requires=">=3.10",
)
