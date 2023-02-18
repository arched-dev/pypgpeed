from setuptools import setup

setup(
    name='pypgped',
    version='0.1.0',
    packages=['pypgped'],
    entry_points={
        'console_scripts': [
            'pypgpeed = loadgui:run'
        ]
    },
    url='https://github.com/lewis-morris/pypgped',
    license='mit',
    author='Lewis Morris',
    author_email='lewis.morris@gmail.com',
    description='Python local PGP tool'
)
