import logging
import os
import subprocess

from .util import SRCDIR, TESTSDIR

logger = logging.getLogger(__name__)


def test_basic(sshd, ssh_options):
    cmd = ['ssh', '-p', str(sshd.port)] + ssh_options + [sshd.address, 'env']
    logger.debug('SSH command: %s', ' '.join(cmd))
    logger.debug('PATH=%s', os.getenv('PATH'))
    out = subprocess.check_output(cmd)
    env_lines = out.decode('utf-8').splitlines()
    env = dict([line.split('=', 1) for line in env_lines])
    assert 'PATH' in env
    assert 'PYTHONPATH' in env

    path = env['PATH'].split(os.pathsep)
    assert path[0] == TESTSDIR

    pypath = env['PYTHONPATH'].split(os.pathsep)
    assert pypath[0] == SRCDIR
