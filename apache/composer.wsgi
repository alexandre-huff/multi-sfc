#!/usr/bin/env python

import sys

#activate_this = '/home/alexandre/PycharmProjects/Holistic-Composer/venv/bin/activate_this.py'
#with open(activate_this) as file_:
#    exec(file_.read(), dict(__file__=activate_this))

#sys.path.insert(0, '/home/alexandre/PycharmProjects/Holistic-Composer')

sys.stdout = sys.stderr

from core import app as application
