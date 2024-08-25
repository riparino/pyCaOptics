from setuptools import setup, find_packages

setup(
    name='pyCaOptics',
    version='0.1',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'azure-identity==1.16.1',
        'requests==2.31.0',
        'pandas==2.0.3',
    ],
    entry_points={
        'console_scripts': [
            'pyCaOptics-app=pyCaOptics_app:main',
            'pyCaOptics-usermode=pyCaOptics_usermode:main',
            'pyCaOptics-app-iter=pyCaOptics_app_iter:main'
        ],
    },
    include_package_data=True,
    description='A tool to analyze Azure Conditional Access policies, inspired by caOptics.',
    author='Riparino',
    author_email='riparino618@outlook.com',
    url='https://github.com/your-repo/pyCaOptics',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)
