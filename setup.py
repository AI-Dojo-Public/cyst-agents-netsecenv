from setuptools import setup, find_packages, find_namespace_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / 'README.md').read_text(encoding='utf-8')

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.

setup(
    name='cyst-agents-netsecenv',
    version='0.1.0',
    description='An agent for interfacing CYST with NetSecEnv',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://muni.cz/go/cyst/',
    author='Martin Drasar et al.',
    author_email='drasar@ics.muni.cz',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
        'Topic :: Security',
        'Typing :: Typed',

        # Pick your license as you wish
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate you support Python 3. These classifiers are *not*
        # checked by 'pip install'. See instead 'python_requires' below.
        'Programming Language :: Python :: 3',

        'Operating System :: OS Independent'
    ],
    packages=find_packages(exclude=['tests', 'docs']) + find_namespace_packages(include=['cyst_models.*', 'cyst_services.*']),
    python_requires='>=3.11, <4',

    # This field lists other packages that your project depends on to run.
    # Any package you put here will be installed by pip when your project is
    # installed, so they must be valid existing projects.
    #
    # For an analysis of "install_requires" vs pip's requirements files see:
    # https://packaging.python.org/discussions/install-requires-vs-requirements/
    install_requires=[
        'cyst-core',
        'aiohttp'
    ],

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # `pip` to create the appropriate form of executable for the target
    # platform.
    #
    # For example, the following would provide a command called `sample` which
    # executes the function `main` from this package when invoked:
    entry_points={
        'cyst.services': [
            'netsecenv_agent=cyst_services.netsecenv_agent.main:service_description'
        ]
    },

    # List additional URLs that are relevant to your project as a dict.
    #
    # This field corresponds to the "Project-URL" metadata fields:
    # https://packaging.python.org/specifications/core-metadata/#project-url-multiple-use
    #
    # Examples listed include a pattern for specifying where the package tracks
    # issues, where the source is hosted, where to say thanks to the package
    # maintainers, and where to support the project financially. The key is
    # what's used to render the link text on PyPI.
    #project_urls={  # Optional
    #    'Bug Reports': 'https://github.com/pypa/sampleproject/issues',
    #    'Funding': 'https://donate.pypi.org',
    #    'Say Thanks!': 'http://saythanks.io/to/example',
    #    'Source': 'https://github.com/pypa/sampleproject/',
    #},
)
