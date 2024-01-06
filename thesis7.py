import secretsharing
from Crypto.Protocol.SecretSharing import Shamir

# Original Message
redundancy = b'abcdefghijklmnop'
plain=b'1234567812345678'

plain1=bytes([x^y for x,y in zip(redundancy,plain)])
print("\n",plain1) 

shares=Shamir.split(2,3,plain1)
print("\n",shares)

#recieveer end
plain2=Shamir.combine([shares[0],shares[1]])
print("\n",plain2==plain)