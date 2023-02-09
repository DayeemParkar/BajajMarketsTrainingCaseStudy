import unittest
import HtmlTestRunner
from helpers import getCustomer, tryToViewAccounts, tryToViewTransactionHistory, checkIfAccountExists, checkIfAccountBelongsToCustomer
import datetime


class TestMethods(unittest.TestCase):
    def test_get_customer(self):
        self.assertEqual(getCustomer('uname')[1], 'uname')
    def test_view_accounts(self):
        self.assertEqual(tryToViewAccounts(1), [(2, 'Savings Account', '5696'), (3, 'Salary Account', '5000'), (1, 'Salary Account', '6004')])
    def test_view_history(self):
        self.assertEqual(tryToViewTransactionHistory(1, 'uname'), (True, [[11, 5, 'NULL', 400, datetime.datetime(2023, 2, 9, 12, 56, 1, 349245)], [9, 'Withdrew cash', 300, 'NULL', datetime.datetime(2023, 2, 9, 0, 40, 44, 588868)], [8, 'Deposited cash', 'NULL', 100, datetime.datetime(2023, 2, 9, 0, 40, 14, 255619)], [7, 'Deposited cash', 'NULL', 100, datetime.datetime(2023, 2, 9, 0, 39, 45, 531399)], [6, 2, 200, 'NULL', datetime.datetime(2023, 2, 9, 0, 19, 53, 273718)], [5, 2, 'NULL', 101, datetime.datetime(2023, 2, 8, 17, 34, 8, 845674)], [3, 'Withdrew cash', 202, 'NULL', datetime.datetime(2023, 2, 8, 16, 3, 4, 909231)], [2, 'Deposited cash', 'NULL', 101, datetime.datetime(2023, 2, 8, 15, 59, 15, 977737)], [1, 'Deposited cash', 'NULL', 101, datetime.datetime(2023, 2, 8, 15, 41, 28, 936314)]]))
    def test_check_if_account_exists(self):
        self.assertTrue(checkIfAccountExists(1)[0])
        self.assertFalse(checkIfAccountExists(100101012)[0])
    def test_if_account_exists(self):
        self.assertEqual(checkIfAccountExists(1), (True, [(1, '$2b$12$1XhSV5D5I4fj14U6Vup8gu6uV9WpqaZx3WCxio5ZphjnWyuECJK7y', 'Salary Account', '6004')]))
    def test_if_account_belongs_to_customer(self):
        self.assertTrue(checkIfAccountBelongsToCustomer(1, 'uname'))
        self.assertFalse(checkIfAccountBelongsToCustomer(100019323, 'uname'))


if __name__ == '__main__':
    unittest.main(testRunner=HtmlTestRunner.HTMLTestRunner(output='/Users/dayeemparkar/Desktop/Training/BajajMarketsTrainingCaseStudy/TestResults/'))