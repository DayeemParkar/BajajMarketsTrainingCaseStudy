import unittest
from helpers import *

class TestMethods(unittest.TestCase):
    def test_unique_user(self):
        self.assertEqual(checkIfUserIsUnique('uname'), True)
    def test_unique_mobile(self):
        self.assertEqual(checkIfMobileIsUnique(9702785199), True)


if __name__ == '__main__':
    unittest.main()