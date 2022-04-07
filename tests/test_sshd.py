import json
import logging
import os
import subprocess

from .util import (
    SRCDIR,
    TESTSDIR,
    needs_sshd,
)

logger = logging.getLogger(__name__)

# Skip all tests here if the required sshd is not available.
pytestmark = needs_sshd


def test_basic(sshd, ssh_options):
    cmd = (
        ['ssh', '-p', str(sshd.port)] +
        ssh_options +
        [sshd.address, 'dumpenv']
    )
    logger.debug('SSH command: %s', ' '.join(cmd))
    logger.debug('Source PATH=%s', os.getenv('PATH'))
    out = subprocess.check_output(cmd)
    data = json.loads(out.decode('utf-8'))

    args = data['args']
    assert args == [os.path.join(TESTSDIR, 'dumpenv')]

    env = data['env']
    assert 'PATH' in env
    assert 'PYTHONPATH' in env

    path = env['PATH'].split(os.pathsep)
    logger.debug('Destination PATH=%s', path)
    assert TESTSDIR in path
    toxbindir = os.getenv('TOXBINDIR')
    if toxbindir:
        assert toxbindir in path
        assert path.index(toxbindir) < path.index(TESTSDIR)

    pypath = env['PYTHONPATH'].split(os.pathsep)
    logger.debug('Destination PYTHONPATH=%s', path)
    if not toxbindir:
        assert SRCDIR in pypath
