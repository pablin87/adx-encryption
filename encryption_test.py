'''
Created on 18/06/2014

@author: pablin
'''
import unittest
from adx_encryption_utils import adx_unencrypt_price, adx_encrypt_price,\
    hex2bytes, decrypt_hyperlocalset
from adx_encryption_utils import adx_decrypt, adx_encrypt
import random, string

import realtime_bidding_pb2

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
        enc_msg = adx_encrypt(s, self.encryption_key.decode("hex"),
                                        self.integrity_key.decode("hex"), 
                                        self.iv.decode("hex"))
        exp_s = adx_decrypt(enc_msg, self.encryption_key.decode("hex"),
                                      self.integrity_key.decode("hex"))
        self.assertEquals(s, exp_s)

    def testEncDecCompatibilitySmall(self):
        self.encryptDecryptCompatibility(self.rand_str(15))

    def testEncDecCompatibilityLarge(self):
        self.encryptDecryptCompatibility(self.rand_str(35))
        
    def testEncDecCompatibilityLarger(self):
        self.encryptDecryptCompatibility(self.rand_str(200))
        
    def assertContains(self, val, lst):
        self.assertTrue(val in lst, "%s not in %s" % (val, lst))
        
    def testGoogleAdxExample(self):
        '''
        This is an example extracted from the Adx google Developers web :
        https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-hyperlocal
        
        '''
        hex_enc_key = "02EEa83c6c1211e10b9f88966ceec34908eb946f7ed6e441af42b3c0f3218140"
        hex_inte_key = "bfFFec55c30130c1d8cd1862ed2a4cd2c76ac33bc0c4ce8a3d3bbd3ad5687792"
        hex_br = "E2014EA201246E6F6E636520736F7572636501414243C0ADF6B9B6AC17DA218FB50331EDB376701309CAAA01246E6F6E636520736F7572636501414243C09ED4ECF2DB7143A9341FDEFD125D96844E25C3C202466E6F6E636520736F7572636502414243517C16BAFADCFAB841DE3A8C617B2F20A1FB7F9EA3A3600256D68151C093C793B0116DB3D0B8BE9709304134EC9235A026844F276797"
        
        # Get the bytes from hex strings...
        br_bytes = hex2bytes(hex_br)
        enc_key = hex2bytes(hex_enc_key)
        inte_key = hex2bytes(hex_inte_key)

        # Parse the br...
        br = realtime_bidding_pb2.BidRequest()
        br.ParseFromString(br_bytes)

        # Decrypt HyperLocalSet
        exp_hp_points = [ (100, 100), (200, -300), (-400, 500), (-600, -700)]
        
        hpls = decrypt_hyperlocalset(br.encrypted_hyperlocal_set, 
                                    enc_key, inte_key)
        
        # Check contained points
        self.assertEquals(len(hpls.hyperlocal[0].corners), 4)
        corners = hpls.hyperlocal[0].corners
        for i in range(len(corners)):
            point = ( corners[i].latitude, corners[i].longitude)
            self.assertContains(point, exp_hp_points)

        # Now decrypt and check idfa and hashed idfa
        exp_idfa = "11111111111111111111111111111111"
        exp_hashed_idfa =  "112233445566778899AABBCCDDEEFFF1".lower()
        
        idfa = adx_decrypt(br.mobile.encrypted_advertising_id, 
                           enc_key, inte_key).encode("hex")
        hashed_idfa = adx_decrypt(br.mobile.encrypted_hashed_idfa, 
                                  enc_key, inte_key).encode("hex")
        self.assertEquals(idfa, exp_idfa)
        self.assertEquals(hashed_idfa, exp_hashed_idfa)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()