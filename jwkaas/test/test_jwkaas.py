# coding: utf-8

import unittest
import logging
import jwt
import base64
import json
from time import time

from jwkaas.algorithms import RSAAlgorithm
from jwkaas import JWKaas


class TestJWKaas(unittest.TestCase):
    """JWKaas integration test stubs"""

    def setUp(self):
        self.private_key = open('jwkaas/test/test-key').read()
        self.my_jwkaas = JWKaas("expected_audience", "expected_issuer", jwks_file='jwkaas/test/test-jwks.json')

    def generate_jwks(self):
        public_key = open('jwkaas/test/test-key.pub').read()
        rsa_pub_key = RSAAlgorithm(RSAAlgorithm.SHA256).prepare_key(public_key)
        jwks_key = RSAAlgorithm.to_jwk(rsa_pub_key)
        logging.info('to_jwk {}'.format(jwks_key))
        return jwks_key

    def test_decode_valid_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, token_body)

    def test_decode_expired_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())-50,
            'nbf': int(time())-100
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Expired token should not be decoded")

    def test_decode_premature_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+200,
            'nbf': int(time())+100
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Premature token should not be decoded")

    def test_decode_unexpected_issuer_token(self):
        token_body = {
            'iss': 'unexpected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Token with unexpected issuer should not be decoded")

    def test_decode_unexpected_audience_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'unexpected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Token with unexpected audience should not be decoded")

    def test_decode_hmac_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10
        }
        token = jwt.encode(token_body, self.private_key, algorithm='HS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Token with unexpected audience should not be decoded")

    def test_decode_no_kid_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256')
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Token without kid should not be decoded")

    def test_decode_invalid_kid_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'invalid-key'})
        info = self.my_jwkaas.get_token_info(token)
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Token with invalid kid should not be decoded")

    def test_decode_rubbish_header_token(self):
        info = self.my_jwkaas.get_token_info("eydfkjdflkjdlflkjDJFLKJEFLKJDLKJFdlkfjlkj")
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Rubbish header token should not be decoded")

    def test_decode_tampered_body_token(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10,
            'scp': 'scope'
        }
        tampered_token_body = token_body.copy()
        tampered_token_body['scp'] = 'scape'
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'}).decode('utf-8')
        new_body = base64.b64encode(json.dumps(tampered_token_body).encode('utf-8')).decode('utf-8')
        tampered_body_token = f"{token.split('.')[0]}.{new_body}.{token.split('.')[2]}"
        logging.info("rubtoken "+tampered_body_token)
        info = self.my_jwkaas.get_token_info(tampered_body_token.encode('utf-8'))
        logging.info('Token info: {}'.format(info))
        self.assertEqual(info, None, "Tampered token should not be decoded")

    def test_connexion_decode_valid_token_with_scp(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10,
            'scp': 'scope'
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_connexion_token_info(token)
        logging.info('Token info: {}'.format(info))
        expected_token_body = token_body.copy()
        expected_token_body['scopes'] = [token_body['scp']]
        self.assertEqual(info, expected_token_body)

    def test_connexion_decode_valid_token_with_scp_and_roles(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10,
            'scp': 'scope',
            'roles': ['role1', 'role2']
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_connexion_token_info(token)
        logging.info('Token info: {}'.format(info))
        expected_token_body = token_body.copy()
        expected_token_body['scopes'] = [token_body['scp'], *token_body['roles']]
        self.assertEqual(info, expected_token_body)

    def test_connexion_decode_invalid_token_with_scp_and_roles(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())-10,
            'nbf': int(time())-20,
            'scp': 'scope',
            'roles': ['role1', 'role2']
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_connexion_token_info(token)
        self.assertEqual(info, None, "Invalid token should not be decoded by connexion_decode")

    def test_connexion_decode_valid_token_only_roles(self):
        token_body = {
            'iss': 'expected_issuer',
            'aud': 'expected_audience',
            'exp': int(time())+100,
            'nbf': int(time())-10,
            'roles': ['role1', 'role2']
        }
        token = jwt.encode(token_body, self.private_key, algorithm='RS256', headers={'kid': 'test-key'})
        info = self.my_jwkaas.get_connexion_token_info(token)
        logging.info('Token info: {}'.format(info))
        expected_token_body = token_body.copy()
        expected_token_body['scopes'] = token_body['roles']
        self.assertEqual(info, expected_token_body)


if __name__ == '__main__':
    unittest.main()
