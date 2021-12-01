import setuptools

setuptools.setup(
    name="jswipl",
    version="1.0.2",
    author="Luca Corbatto",
    author_email="luca-pip@corbatto.de",
    description="A Jupyter Kernel for SWI-Prolog.",
    url="https://github.com/targodan/jupyter-swi-prolog",
    packages=setuptools.find_packages(),
    install_requires=[
        "pyswip",
        "ipykernel"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        'console_scripts': ['jswiplkernel=jswipl.jupyter:main'],
    }
)
