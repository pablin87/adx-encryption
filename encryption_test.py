'''
Created on 18/06/2014

@author: pablin
'''
import unittest
from adx_encryption_utils import adx_unencrypt_price, adx_encrypt_price
from adx_encryption_utils import decrypt_HyperlocalSet, encrypt_HyperlocalSet
import random, string

class TestAdxEncryptionPrice(unittest.TestCase):


    def setUp(self):
        self.encryption_key = "b08c70cfbcb0eb6cab7e82c6b75da52072ae62b2bf4b990bb80a48d8141eec07"
        self.integrity_key = "bf77ec55c30130c1d8cd1862ed2a4cd2c76ac33bc0c4ce8a3d3bbd3ad5687792"
        self.encrypted_price = "SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA"
        self.price = 709959680
        self.iv = "4a3a6f470001e2407b8c4a605b9200f2"

    def tearDown(self):
        pass

    def testEncryptPrice(self):
        enc_price = adx_encrypt_price(self.price, 
                                      self.encryption_key.decode("hex"),
                                      self.integrity_key.decode("hex"),
                                      self.iv.decode("hex"))
        exp_enc_price = self.encrypted_price + "==" # make it base64 compliant
        self.assertEquals(enc_price, exp_enc_price)

    def testDecryptPrice(self):
        price_dec = adx_unencrypt_price(self.encrypted_price, 
                                        self.encryption_key.decode("hex"),
                                        self.integrity_key.decode("hex"))
        price_expected = self.price
        self.assertEqual(price_expected,int(price_dec))


class TestAdxEncryptionHyperLocal(unittest.TestCase):


    def setUp(self):
        self.encryption_key = "b08c70cfbcb0eb6cab7e82c6b75da52072ae62b2bf4b990bb80a48d8141eec07"
        self.integrity_key = "bf77ec55c30130c1d8cd1862ed2a4cd2c76ac33bc0c4ce8a3d3bbd3ad5687792"
        self.iv = "4a3a6f470001e2407b8c4a605b9200f2"
        self.rand_str = lambda l : "".join([random.choice(string.ascii_letters 
                                           + string.digits) for _ in range(l)])

    def tearDown(self):
        pass

    def encryptDecryptCompatibility(self, s):
        enc_msg = encrypt_HyperlocalSet(s, self.encryption_key.decode("hex"),
                                        self.integrity_key.decode("hex"), 
                                        self.iv.decode("hex"))
        exp_s = decrypt_HyperlocalSet(enc_msg, self.encryption_key.decode("hex"),
                                      self.integrity_key.decode("hex"))
        self.assertEquals(s, exp_s)

    def testEncDecCompatibilitySmall(self):
        self.encryptDecryptCompatibility(self.rand_str(15))

    def testEncDecCompatibilityLarge(self):
        self.encryptDecryptCompatibility(self.rand_str(35))
        
    def testEncDecCompatibilityLarger(self):
        self.encryptDecryptCompatibility(self.rand_str(200))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()