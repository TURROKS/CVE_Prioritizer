from setuptools import setup, find_packages

setup(
    name='CVE_Prioritizer',
    version='1.8.2',
    author='Mario Rojas',
    author_email='prioritizer@proton.me',
    description='Streamline vulnerability patching with CVSS, EPSS, Known Exploited Vulnerabilities and more.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/TURROKS/CVE_Prioritizer',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=[
        'pandas',
        'requests',
        'setuptools',
        'requests',
        'python-dotenv',
        'termcolor',
        'click'
    ],
    entry_points={
        'console_scripts': [
            'cve_prioritizer=cve_prioritizer:main',
        ],
    },
)