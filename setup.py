from setuptools import setup, find_packages

VERSION = '1.0.0'
DESCRIPTION = 'A Python 3 module that leverages the IP Quality Score API to scan links in real-time to detect suspicious URLs.'
EXCLUDES = ('.gitignore', 'Sphinx-docs', 'tests')

# Setting up
setup(
    name="malurl",
    version=VERSION,
    author="Techno-Hwizrdry (Alexan Mardigian)",
    author_email="<alexan@expresspolygon.com>",
    url='https://github.com/Techno-Hwizrdry/python-malurl',
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=DESCRIPTION,
    packages=find_packages(exclude=EXCLUDES),
    python_requires=">=3.6",
    install_requires=['requests', 'validators', 'rainbowprint-TechnoHwizrdry'],
    keywords=['python', 'infosec', 'urls', 'security', 'malicious-url-detection'],
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'License :: OSI Approved :: MIT License',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Operating System :: Unix',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
    ]
)
