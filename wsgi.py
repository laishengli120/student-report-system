import sys
import os

# 将项目目录加入 Python 路径
project_home = '/home/{username}/student-report-system'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# 确保 instance 目录存在
instance_path = os.path.join(project_home, 'instance')
os.makedirs(instance_path, exist_ok=True)

from app import app as application
