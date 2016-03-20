from distutils.core import setup
from const import VERSION


setup(
    name='amg',
    version=VERSION,
    py_modules=['amg', 'const'],
    author='zewait',
    author_email='wait@h4fan.com',
    description='app manager tool',
    license='MIT',
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'console_scripts': [
            'amg = amg:main'
        ]
    }
)
