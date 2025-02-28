from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="api-security-tester",
    version="0.1.0",
    author="ASHINNO",
    author_email="contact@ashinno.com",
    description="A machine learning based mobile app security testing framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ashinno/APISecurityTester",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.19.0",
        "pandas>=1.2.0",
        "tensorflow>=2.8.0",
        "scikit-learn>=0.24.0",
        "pytest>=6.0.0",
        "matplotlib>=3.4.0"
    ],
    include_package_data=True,
    package_data={
        'api_security_tester': ['config.json', 'models/*.h5']
    }
)