#timing was very poor of new model so made changes by splitting the key rather than the cipher


from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
import numpy as np
import timeit
from Crypto.Util.number import getPrime
from charm.core.math.pairing import hashPair as extractor


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils


import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


import random
import timeit

from odf import text, teletype
from odf.opendocument import load
import ezodf
import csv


from Crypto.Protocol.SecretSharing import Shamir


import random
import functools
import secretsharing as sss
from binascii import hexlify
from binascii import unhexlify
from collections import Counter
import math
from helpers import *
import sys


# ------------------------record timings and load data---------------------------
def write_time(path,new_data):
   
    with open(path, 'a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerows([new_data])

def load_attribute_list(path_of_attribute_list):
    content=load(path_of_attribute_list)
    attrs_content=""
    for element in content.getElementsByType(text.P):
        attrs_content+=(teletype.extractText(element))

    attrs=attrs_content.split(",")
    return attrs

def load_access_policies(path_of_access_policies):
    doc = ezodf.opendoc(path_of_access_policies)

    # Assume there is only one sheet in the ODS file
    sheet = doc.sheets[0]

    # Read data from the sheet
    access_policy = {}
    for row in sheet.rows():
        row_data = [cell.value for cell in row]
        access_policy[row_data[0]]=row_data[1:6]
      
    return access_policy

def load_possessed_attributes(path_of_possessed_attributes):
    doc = ezodf.opendoc(path_of_possessed_attributes)

    # Assume there is only one sheet in the ODS file
    sheet = doc.sheets[0]

    # Read data from the sheet
    possessed_attribute = {}
    for row in sheet.rows():
        row_data = [cell.value for cell in row]
        possessed_attribute[row_data[0]]=row_data[1].split(",")
    

    return possessed_attribute

def calculate_entropy(data):
    # Step 1: Calculate symbol frequencies
    symbol_counts = Counter(data)
    
    # Step 2: Calculate symbol probabilities
    total_symbols = len(data)
    probabilities = [count / total_symbols for count in symbol_counts.values()]
    
    # Step 3: Calculate entropy
    entropy = -sum(probability * math.log2(probability) for probability in probabilities if probability != 0)
    
    print("\n entropy",entropy)
    return


#-----------------------------user registration------------------------
def authority_setup(group,q,G):

    #select yi,ki randoms from ZR as MSK
    yi=group.random(ZR)
    ki=group.random(ZR)

    msk=(yi,ki)

    #calculate PK as {yi.G,ki.G}
    pk=(yi*G,ki*G)


    return (msk,pk)

def registration_user_phase(user_no):
    #each DU selects a number Ku randomly from ZR 
    #and computes Ru=Ku*G
    Ku=group.random(ZR)
    Ru=Ku*G
    GID=user_list[user_no]

    #then DU sends its general identity and Ru, R to the CA
    #to get registered
    return(Ru,GID)

def registration_CA(GID,Ru,user_no):
    #select a random number Kc from ZR and calculate
    #Pc=Ru+Kc*G

    Kc=group.random(ZR)
    Pc=Ru+Kc*G
    Pc=extractor(Pc)

    #create signature
    Cp = ec.generate_private_key(ec.SECP384R1(),default_backend())
    CP = Cp.public_key()

    Cu=Cp.sign(Pc,ec.ECDSA(hashes.SHA256()))

    if debug==True:
        print("\nRedundancy",redundancy)
        print("\nPc",Pc)
        print("\nCu",Cu)


    #CA send the signature to DU
    return (Cu,Pc,CP)

def registration_Complete(Cu,CP,Pc):
    #validate the signature
    try:
        D_Cu=CP.verify(Cu,Pc,ec.ECDSA(hashes.SHA256()))
        if debug==True:
            print("\nVerification done")
    except Exception as e:
        print("\nVerification failed")
  

#-------------------------key generation---------------------------
def key_generation(msk,pk):

    #Ai calculates partial user secret key Us for DU
    #and maintains list for it.

    #Usi=yi+H(GID)*ki
    Us={}
    for GID in user_list:
        attribute_of_user=possessed_attribute[GID]
        Hash_gid=group.hash(GID)
        temp={}
        for attr in attribute_of_user:     
            Yi=msk[0]
            Ki=msk[1]
            Usi=Yi+Hash_gid*Ki
            temp[attr]=Usi
        Us[GID]=temp

    
    #send it to DU
    if debug == True:
        print("\nUs",Us)

    return Us


def key_generation_user(Us):
    #DU selects a random integer p from ZR
    #Usi'=yi+H(G)*Ki+p

    for user in user_list:
        p=group.random(ZR)
        P[user]=p
        Us_user=Us[user]
        for idx,val in enumerate(Us_user.keys()):
            temp=Us_user[val]
            temp+=p
            Us_user[val]=temp
        Us[user]=Us_user
        
    
    if debug == True:
    
        print("\nUs",Us)

    return Us
#--------------------------------RC6---------------------
def decrypt(esentence,s):
    encoded = blockConverter(esentence)
    enlength = len(encoded)
    A = long(encoded[0],2)
    B = long(encoded[1],2)
    C = long(encoded[2],2)
    D = long(encoded[3],2)
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    C = (C - s[2*r+3])%modulo
    A = (A - s[2*r+2])%modulo
    for j in range(1,r+1):
        i = r+1-j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        tmod=t%32
        umod=u%32
        C = (ROR((C-s[2*i+1])%modulo,tmod,32)  ^u)  
        A = (ROR((A-s[2*i])%modulo,umod,32)   ^t) 
    D = (D - s[1])%modulo 
    B = (B - s[0])%modulo
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    return cipher,orgi

def encrypt(sentence,s):
    encoded = blockConverter(sentence)
    enlength = len(encoded)
    A = long(encoded[0],2)
    B = long(encoded[1],2)
    C = long(encoded[2],2)
    D = long(encoded[3],2)
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    B = (B + s[0])%modulo
    D = (D + s[1])%modulo 
    for i in range(1,r+1):
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        tmod=t%32
        umod=u%32
        A = (ROL(A^t,umod,32) + s[2*i])%modulo 
        C = (ROL(C^u,tmod,32) + s[2*i+ 1])%modulo
        (A, B, C, D)  =  (B, C, D, A)
    A = (A + s[2*r + 2])%modulo 
    C = (C + s[2*r + 3])%modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return orgi,cipher
#-----------------------DNA operation-----------------------------------
def DNA(byte_string):
    
    binary_string=''
    for ch in byte_string:
        binary_string+=str((bin(ch)[2:]).zfill(8))


    return binary_string

def inverseDNA(binary_string):
     # Split the binary string into chunks of 8 characters
    binary_chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    
    # Convert each binary chunk back to bytes
    byte_string = bytes(int(chunk, 2) for chunk in binary_chunks)
    return byte_string

def substitute(binary_string):
    cnt=0
    new_string=''
    idx=0
    while(idx<len(binary_string)):
        
        if (binary_string[idx]=='0'and binary_string[idx+1]=='0'):
            if(reference_dna[cnt]=='A'):
                new_string+='A'
            if(reference_dna[cnt]=='C'):
                new_string+='C'
            if(reference_dna[cnt]=='T'):
                new_string+='T'
            if(reference_dna[cnt]=='G'):
                new_string+='G'
        if(binary_string[idx]=='0'and binary_string[idx+1]=='1'):
            if(reference_dna[cnt]=='A'):
                new_string+='C'
            if(reference_dna[cnt]=='C'):
                new_string+='T'
            if(reference_dna[cnt]=='T'):
                new_string+='G'
            if(reference_dna[cnt]=='G'):
                new_string+='A'

        if(binary_string[idx]=='1'and binary_string[idx+1]=='0'):
            if(reference_dna[cnt]=='A'):
                new_string+='T'
            if(reference_dna[cnt]=='C'):
                new_string+='G'
            if(reference_dna[cnt]=='T'):
                new_string+='A'
            if(reference_dna[cnt]=='G'):
                new_string+='C'
        if(binary_string[idx]=='1'and binary_string[idx+1]=='1'):
            if(reference_dna[cnt]=='A'):
                new_string+='G'
            if(reference_dna[cnt]=='C'):
                new_string+='A'
            if(reference_dna[cnt]=='T'):
                new_string+='C'
            if(reference_dna[cnt]=='G'):
                new_string+='T'
        
        idx+=2
        cnt+=1
    return new_string
        
def inverseSub(binary_string):

    new_string=b''
    cnt=0
    for idx in range(len(binary_string)):
        if binary_string[idx]=='A':
            if reference_dna[cnt]=='A':
                new_string+=b'00'
            if reference_dna[cnt]=='C':
                new_string+=b'11'
            if reference_dna[cnt]=='T':
                new_string+=b'10'
            if reference_dna[cnt]=='G':
                new_string+=b'01'
        if binary_string[idx]=='C':
            if reference_dna[cnt]=='A':
                new_string+=b'01'
            if reference_dna[cnt]=='C':
                new_string+=b'00'
            if reference_dna[cnt]=='T':
                new_string+=b'11'
            if reference_dna[cnt]=='G':
                new_string+=b'10'
        if binary_string[idx]=='T':
            if reference_dna[cnt]=='A':
                new_string+=b'10'
            if reference_dna[cnt]=='C':
                new_string+=b'01'
            if reference_dna[cnt]=='T':
                new_string+=b'00'
            if reference_dna[cnt]=='G':
                new_string+=b'11'
        if binary_string[idx]=='G':
            if reference_dna[cnt]=='A':
                new_string+=b'11'
            if reference_dna[cnt]=='C':
                new_string+=b'10'
            if reference_dna[cnt]=='T':
                new_string+=b'01'
            if reference_dna[cnt]=='G':
                new_string+=b'00'
       
        cnt+=1
    return new_string



#-----------------------------------encrypt---------------------------
def encrypt_DO(P):

    t=0
    group.InitBenchmark( )
    group.StartBenchmark(["RealTime"])

    key = os.urandom(16)
    #add padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(P) + padder.finalize()

    C=rc6_encrypt_block(P,key,w=32,r=20)

    #split the aes key
    shares1=[]
    shares1=Shamir.split(4,5,key)
    shares_of_key=[]
    for idx in range(len(shares1)):
        if idx==0:
            temp_share=DNA(hexlify(shares1[idx][1]))
            temp_share=substitute(temp_share)
            shares_of_key.append((shares1[idx][0],temp_share))
        else:
            shares_of_key.append((shares1[idx][0],hexlify(shares1[idx][1])))
   
 

    group.EndBenchmark()
    t= t + group.GetBenchmark("RealTime") 
   
     
    #C,C0,C1,C2,CH- cipher text CD
    return (C,shares_of_key,t*1000)


#---------------------------------validating user--------------------
def recoverSecret(shares,coeff,pruned_list):
        #take shares and attempt to recover secret by taking sum of coeff * share for all shares.
        #if user indeed has at least k of n shares, then secret will be recovered.
        list = shares.keys()
        secret = 0
        for attrs in pruned_list:
            attr=attrs.getAttribute()
            secret += (coeff[attr] * shares[attr])

        return secret


#---------------------------Decryption----------------------------

def decryption_DU(C,shares_of_key):
    
    t=0
    group.InitBenchmark( )
    group.StartBenchmark(["RealTime"])

    #reconstrcut the aes key
    key=''
    shares=[]
    for idx in range(len(shares_of_key)):
        if idx==0:
            temp_share=shares_of_key[idx][1]
            temp_share=inverseSub(temp_share)
            temp_share=inverseDNA(temp_share)
            shares.append((shares_of_key[idx][0],unhexlify(temp_share)))
        else:
            shares.append((shares_of_key[idx][0],unhexlify(shares_of_key[idx][1])))
    key=Shamir.combine(shares)
    
    
    
    M = rc6_decrypt_block(C,key,w=32,r=20)
    unpadder = padding.PKCS7(128).unpadder()
    M = unpadder.update(M) + unpadder.finalize()

    group.EndBenchmark()
    t= t + group.GetBenchmark("RealTime") 

    return (True,M,t*1000)


def calc(Message):

    C,shares_of_key,t1=encrypt_DO(Message)
    encryption_time=t1
    calculate_entropy(C)

    #write the encrypted image
    fin=open(encrypted_path,'wb')
    fin.write(C)
    fin.close()

  
    # D,N1,N2,C,ok,t2=decryption_DUA(C,shares_of_key)
    ok,M,t2=decryption_DU(C,shares_of_key) 

    if (ok==True):
        print("\n same",M==Message)
        
        #write decrypted image
        fin=open(path_to_write,'wb')
        fin.write(M)
        fin.close()

        decryption_time=t2
        return encryption_time,decryption_time
    


global group,q,G,P,a,user_list,key,Hash_gid,debug,Hash_g,attrs,possessed_attribute,no_of_attributes,access_policies,redundancy
#defining an elliptic cruve group
group=PairingGroup('SS512')
#define a random prime 
bits=160
q=getPrime(bits)
#define G a random int from finite filed ZR
G=group.random(G1)
#genral identity
DO='Alice'
DU='Bob'
user_list=['Alice','Bob']
P={}
redundancy={}
debug=False
reference_dna='TGCCCTCTGTGCGTTTCGGTCTATATCCGCTCCTGCTTAACCGTGTACTGCAGTATACGGTATCAGCCACTCTCCACGGGTCTTACGGGCAAACTAAGTCGACGAACGATTCAACATCGAAAGGGCTGTGCCCTCTGTGCGTTTCGGTCTATATCCGCTCCTGCTTAACCGTGTACTGCAGTATACGGTATCAGCCACTCTCCACGGGTCTTACGGGCAAACTAAGTCGACGAACGATTCAACATCGAAAGGGCTG'


path='/home/anika/Desktop/Thesis/Image_data/Images/first_20_resized/'
encrypted_path='/home/anika/Desktop/Thesis/Image_data/Images/encrypted/'
path_to_write='/home/anika/Desktop/Thesis/Image_data/Images/decrypted/'


path_of_times = '/home/anika/Desktop/Thesis/Image_data/image_timings/model3_timings.csv'


#global symmtric key
key={}
iv = os.urandom(16)


if __name__=="__main__":

    encryption_time=0
    decryption_time=0
    total_rows=0

    for i in range(0,20):
        path='/home/anika/Desktop/Thesis/Image_data/Images/first_20_resized_changed/'
        encrypted_path='/home/anika/Desktop/Thesis/Image_data/Images/encrypted_changed/'
        path_to_write='/home/anika/Desktop/Thesis/Image_data/Images/decrypted_changed/'

        temp_string=str(i+1)
        path+=temp_string
        path+='.png'
      

        encrypted_path+=temp_string
        encrypted_path+='.txt'

        path_to_write+=temp_string
        path_to_write+='.png'


        #read image data
        fin=open(path,'rb')
        image=fin.read()
        fin.close()

        e_t,d_t=calc(image)
        

   
        encryption_time+=e_t
        decryption_time+=d_t
        total_rows+=1
    


 

    encryption_time/=total_rows
    decryption_time/=total_rows


    print("\nEncryption time",encryption_time)
    print("\nDecryption time",decryption_time)

    times=[encryption_time,decryption_time]
    print("\n",times)
    write_time(path_of_times,times)

    

    
