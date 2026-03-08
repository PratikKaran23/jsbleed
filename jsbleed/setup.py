from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="jsbleed",
    version="1.0.0",
    author="PratikKaran",
    author_email="",
    description="Recon & JS analysis tool for bug bounty hunters — bleeds secrets out of JS files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PratikKaran23/jsbleed",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "rich>=13.0.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "jsbleed=jsbleed.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    keywords="bug-bounty recon javascript security pentest secrets api-keys",
)
