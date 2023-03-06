from setuptools import setup, find_packages

version = '0.0.1'

install_requires = [
    'setuptools>=67.5.1',
    'certbot>=2.3.0',
    'acme>=2.3.0'
]

setup(
    name='certbot-dns-1cloud',
    version=version,
    description="1cloud DNS Authenticator for Certbot",
    url="https://github.com/mikhailkilyakov/certbot-1cloud",
    author="Mikhail Kilyakov",
    author_email="mikhail.kilyakov@gmail.com",
    license="Apache License 2.0",
    python_requires=">=3.7",
        classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities'
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'certbot.plugins': [
            'dns-1cloud = certbot_dns_1cloud._internal.dns_1cloud:Authenticator'
        ]
    }
)
