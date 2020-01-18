import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='dnsrewriteproxy',
    version='0.0.4',
    author='Department for International Trade',
    author_email='webops@digital.trade.gov.uk',
    description='A DNS proxy server that conditionally rewrites and filters A record requests',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/uktrade/dns-rewrite-proxy',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Topic :: Internet :: Name Service (DNS)',
    ],
    python_requires='>=3.7.0',
    py_modules=[
        'dnsrewriteproxy',
    ],
    install_requires=[
        'aiodnsresolver>=0.0.149',
    ],
    test_suite='test',
)
