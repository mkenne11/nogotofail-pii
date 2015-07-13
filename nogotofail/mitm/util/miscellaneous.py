r'''
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import inspect
import time
from functools import wraps

### Miscellaneous utility functions

# Truncates/pads a float f to n decimal places without rounding and
# returns a string.
def truncate(f, n):
    s = '{}'.format(f)
    if 'e' in s or 'E' in s:
        return '{0:.{1}f}'.format(f, n)
    i, p, d = s.partition('.')
    return '.'.join([i, (d+'0'*n)[:n]])

def fn_timer(class_name):
    """ Decorator "fn_timer" which times a function and has argument "class-name".
        Based on code at: http://www.marinamele.com/7-tips-to-time-python-scripts-and-control-memory-and-cpu-usage
    """
    def _fn_timer(function):
        @wraps(function)
        def function_timer(*args, **kwargs):
            t0 = time.time()
            result = function(*args, **kwargs)
            t1 = time.time()
            print ("Total time running %s:: %s: %s seconds" %
                   (class_name, function.func_name, str(t1-t0))
                   )
            return result
        return function_timer
    return _fn_timer
