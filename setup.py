from setuptools import setup, find_packages

setup(
    name="valkyrie",
    version="1.0.0",
    description="Professional-grade CLI Malware Analyzer. Automates Static, Dynamic, and Intel analysis.",
    author="Valkyrie Security",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.1.7",
        "pefile>=2023.2.7",
        "yara-python>=4.5.1",
        "docker>=7.1.0",
        "rich>=13.9.4",
        "openai>=1.54.3",
        "python-dotenv>=1.0.1",
        "requests>=2.32.3",
        "Jinja2>=3.1.4",
        "stix2>=3.0.1",
        "fpdf2>=2.8.2"
    ],
    entry_points={
        "console_scripts": [
            "valkyrie=valkyrie.cli.main:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
)
