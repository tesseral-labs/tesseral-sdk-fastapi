import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.discover("tests")
    )
