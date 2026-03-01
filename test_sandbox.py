import sys
import builtins

original_import = builtins.__import__
def secure_import(name, globals=None, locals=None, fromlist=(), level=0):
    blocked_direct = ['shutil', 'os', 'sys', 'subprocess']
    
    if name in blocked_direct:
        frame = sys._getframe(1)
        if frame.f_code.co_filename == '<string>':
            raise ImportError(f"Blocked: {name}")
            
    return original_import(name, globals, locals, fromlist, level)

builtins.__import__ = secure_import

script = """
print("Trying to import requests...")
import requests
print("Requests imported successfully!")

try:
    import shutil
    print("FAILED: Shutil imported!")
except ImportError as e:
    print(f"SUCCESS: {e}")
"""

exec(script, {'__name__': '__main__', '__builtins__': builtins})
