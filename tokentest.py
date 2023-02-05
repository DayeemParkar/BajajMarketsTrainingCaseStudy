import jwt
from jwt.exceptions import ExpiredSignature, InvalidAlgorithmError, InvalidKeyError, InvalidTokenError

class Token:
    _instance = None
    
    def __new__(cls):
        if not cls._instance:
            cls._instance = super(Token, cls).__new__(cls)
        return cls._instance
    
    @classmethod
    def generateToken(cls, payload, key):
        try:
            return jwt.encode(payload=payload, key=key,)
        except InvalidKeyError as ike:
            print(f'{ike}')
            return ''
    
    @classmethod
    def checkToken(cls, token, key):
        header = jwt.get_unverified_header(token)
        try:
            payload = jwt.decode(token, key=key, algorithms=[header['alg'], ],)
            return payload
        except ExpiredSignature as es:
            print(f'{es}')
            return None
        except Exception as e:
            print(f'{e}')
            return None


# if __name__ == '__main__':
    # payload_data = {
    #     "sub": "4242",
    #     "name": "Jessica Temporal",
    #     "pass": "JessPass"
    # }

    # my_secret = 'my_super_secret'
    
    # token = Token.generateToken(payload_data, my_secret)
    # print('Token', token)
    # payload = Token.checkToken(token, my_secret)
    # print(payload)
