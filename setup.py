from setuptools import setup, find_packages


install_requires = open('requirements.txt', 'r').readlines()


setup(
    name='AndroCFG',
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "AndroCFG=AndroCFG:main",
        ]
    },
    scripts=['AndroCFG.py'],
    version='0.0.1',
    packages=find_packages(),
    url='',
    license='GNU Affero General Public License 3.0',
    author='U+039b',
    author_email='github@0x39b.fr',
    package_data={'androcfg': ['*.json', 'fonts/*']},
    description='Extract both control flow graphs and code parts from APK based on API calls.'
)
