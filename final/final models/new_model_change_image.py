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
    
    print(entropy)
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
def encrypt_DO(P,access_policy,pk):

    t=0
    group.InitBenchmark( )
    group.StartBenchmark(["RealTime"])


    policy_string=access_policy

    #add padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(P) + padder.finalize()

    #select an abe key to validate the user
    abe_key=group.random(ZR)
    abe_key=abe_key*G
    
    key[abe_key]=os.urandom(16)
    abe_hash=group.hash(key[abe_key])


    #DO does performs a symmetric encryption on P message
    #using AES
    aes_key = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),default_backend())
    encryptor = cipher.encryptor()
    C = encryptor.update(padded_data) + encryptor.finalize()   

   

    #Dd,Qd data owners secret key and public key
    D=group.random(ZR)
    Q=D*G
     

    #DO calculate the hash of the C as Ch=H(C)*D*G
    CH=group.hash(C)*D*G

    #DO defines an LSSS access policy and create 
    #Access tree A

    util=SecretUtil(group)
    A = util.createPolicy(policy_string)
    attr_list = util.getAttributeList(A)
    no_of_attributes=len(attr_list)

    s=group.random(ZR)
    shares = util.calculateSharesDict(s, A)

    #abe_key=abe_key+s*G
    abe_key=abe_key+s*G

    #split the aes key
    shares1=[]
    shares1=Shamir.split(4,5,aes_key)
    shares_of_key=[]
    for idx in range(len(shares1)):
        if idx==0:
            temp_share=DNA(hexlify(shares1[idx][1]))
            # print("\n",shares1[idx][1])
            # print("\n",hexlify(shares1[idx][1]))
            # print("\n",DNA(shares1[idx][1]))
            temp_share=substitute(temp_share)
            shares_of_key.append((shares1[idx][0],temp_share))
        else:
            shares_of_key.append((shares1[idx][0],hexlify(shares1[idx][1])))
 
 


    #two random vector v=(s,v1....vm) and
    #u=(0,u1....um)
    v=[s]
    u=[0]

    for attr in attr_list:
        ui=group.random(ZR)
        vi=group.random(ZR)
        u.append(ui)
        v.append(vi)


    #DO calculates ax=access_policy*v
    #Wx=access_policy*u
    a={}
    w={}
    for x in attr_list:
        temp=[]
        for vals in v:
            temp.append(shares[x]*vals)
        a[x]=temp

    for x in attr_list:
        temp=[]
        for vals in u:
            temp.append(shares[x]*vals)
        w[x]=temp

    C1={}
    C2={}
    #C1,x=ax*G+yi*G
    #C2,x=wx*G+ki*G

    yi=pk[0]
    ki=pk[1]
    for x in attr_list:
       temp=[]
       for idx,val in enumerate(a[x]):
           temp.append(a[x][idx]*G+yi)
       C1[x]=temp
     

    for x in attr_list:
        temp=[]
        for idx,val in enumerate(w[x]):
            comp=(w[x][idx])
            comp*=G
            comp+=ki
            temp.append(comp)
        C2[x]=temp

   

    group.EndBenchmark()
    t= t + group.GetBenchmark("RealTime") 
   

    if debug==True:
    
        print("\ct",C)
        print("\nA",A)
        print("\nShares",shares)
        print("\na",a)
        print("\nw",w)

        print("\nC1",C1)
        print("\nC2",C2)
        print("\nC0",aes_key)
 
    #C,C0,C1,C2,CH- cipher text CD
    return (C,shares_of_key,abe_key,abe_hash,C1,C2,CH,Q,shares,a,w,no_of_attributes,t*1000)


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
def decryption_DUA(DU,C,C0,C1,C2,CH,Us,shares,access_policy,a,w):

    t=0
    group.InitBenchmark( )
    group.StartBenchmark(["RealTime"])

    
    ok=True
    #whether attrs of DU satisfies access policy
    attrs_DU=possessed_attribute[DU]

    util=SecretUtil(group)
    policy = util.createPolicy(access_policy)
    pruned_list= util.prune(policy,attrs_DU)



    if pruned_list == False:
        ok=False
        return(-1,-1,-1,-1,ok,-1)

    coeff = util.getCoefficients(policy)
  

    #recover secret any such cx from ZR which satisfies
    #sum(cx.Ax) over x is (1,0,0,0,0...)
    #and cx.ax=s
    s=recoverSecret(shares,coeff,pruned_list)

    # for _,val in enumerate(Us.keys()):
    #     #converting back to pairing element
    #     Us[val]=group.init(ZR, int(Us[val]))

    #get cx
    cx={}
    l=len(pruned_list)
    sum=0
    l1=0
    for attr in pruned_list:
        x=attr.getAttribute()
        cx[x]=[]
        for idx,val in enumerate(a[x]):
            if idx==0:
                if l1<l-1:
                    cx[x].append(1)
                    sum+=(a[x][idx]*1)
                else:
                    cx[x].append((s-sum)/a[x][idx])

            else:
                sum+=(a[x][idx]*0)
                cx[x].append(0)
        l1+=1



    if debug==True:
        print("\ncx",cx)
        print("\na",a)
        print("\nw",w)
        print("\nPruned List",pruned_list)
        print("\ns",s)
        print("\ncx",cx)


    #############################
    #Dx=c1,x-Us*G+H_gid*c2,x
    #=ax*G+H_gid*wx*G-p*G
    D={}
    Hash_gid=group.hash(DU)

    for attr in pruned_list:
        x=attr.getAttribute()
        temp_arr=[]
        for idx in range(len(C1[x])):
                temp1=C1[x][idx]
                temp2=Us[x]*G
                temp3=C2[x][idx]*Hash_gid
                temp=temp1-temp2+temp3
                temp_arr.append(temp)
                idx+=1
        D[x]=temp_arr
    
    N1=G-G
    for attr in pruned_list:
        x=attr.getAttribute()
        for idx in range(len(cx[x])):
            if cx[x][idx]!=0:
                N1+=(D[x][idx]*cx[x][idx])
                idx+=1
        


   
    temp=0
    for attr in pruned_list:
        x=attr.getAttribute()
        temp+=(np.sum(cx[x]))

    temp*=G
    N2=temp

    if debug==True:
    
        print("\nN1",N1)
        print("\nN2",N2)
      
 
    group.EndBenchmark()
    t= t + group.GetBenchmark("RealTime") 

    return (D,N1,N2,C,ok,t*1000)


def decryption_DU(DU,N1,N2,C,shares_of_key,abe_key,abe_hash,CH,p,Qd,ok):
    
    t=0
    group.InitBenchmark( )
    group.StartBenchmark(["RealTime"])

    if(ok==False):
        print("\nDecryption Failed")
        return(False,"",-1)
    else:

        
        #abe_key'=abe_key-N1-p*N2
        re=N1+p*N2
        abe_key=abe_key-re

        #if the hash is equal it means the user reconstructed the abe key successfull
        #with his/her attributes
        if (group.hash(key[abe_key])!=abe_hash):
            return (False,"",-1)

        #check if the hash value is same
        #Ch=Hash(C)*G*Qd
        Ch_new=group.hash(C)*Qd

        if CH!=Ch_new:
            return (False,"",-1)
    
        #reconstrcut the aes key
        aes_key=''
        shares=[]
        for idx in range(len(shares_of_key)):
            if idx==0:
                temp_share=shares_of_key[idx][1]
                # print("\n",temp_share)
                temp_share=inverseSub(temp_share)
                # print("\n",temp_share)
                temp_share=inverseDNA(temp_share)
                # print("\n",temp_share)
                shares.append((shares_of_key[idx][0],unhexlify(temp_share)))
            else:
                shares.append((shares_of_key[idx][0],unhexlify(shares_of_key[idx][1])))
        aes_key=Shamir.combine(shares)
      
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),default_backend())
        decryptor = cipher.decryptor()
        M = decryptor.update(C)+decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        M = unpadder.update(M) + unpadder.finalize()

        if debug==True:
            print("\nC0",aes_key)
            print("\nN1",N1)
            print("\np",p)
            print("\nN2",N2)
            print("\nM",M)


        group.EndBenchmark()
        t= t + group.GetBenchmark("RealTime") 

        return (True,M,t*1000)


def calc(Message,access_policy):

    s=timeit.default_timer()
    for user_no,user in enumerate(user_list):
        (msk,pk)=authority_setup(group,q,G)
        (Ru,GID)=registration_user_phase(user_no)
        (Cu,Pc,CP)=registration_CA(GID,Ru,user_no)
        registration_Complete(Cu,CP,Pc)

    Us=key_generation(msk,pk)
    Us=key_generation_user(Us)
    f=timeit.default_timer()
    key_generation_time=(f-s)*1000

    C,shares_of_key,abe_key,abe_hash,C1,C2,CH,Qd,shares,a,w,no_of_attributes,t1=encrypt_DO(Message,access_policy,pk)
    encryption_time=t1
    calculate_entropy(C)

    #write the encrypted image
    fin=open(encrypted_path,'wb')
    fin.write(C)
    fin.close()

  
    D,N1,N2,C,ok,t2=decryption_DUA(DU,C,shares_of_key,C1,C2,CH,Us[DU],shares,access_policy,a,w)
    ok,M,t3=decryption_DU(DU,N1,N2,C,shares_of_key,abe_key,abe_hash,CH,P[DU],Qd,ok) 

    if (ok==True):
        # print("\n same",M==Message)
        
        #write decrypted image
        fin=open(path_to_write,'wb')
        fin.write(M)
        fin.close()

        decryption_time=t2+t3
        return no_of_attributes,key_generation_time,encryption_time,decryption_time
    


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


path='/home/anika/Desktop/Thesis/Image_data/images_for_evaluation_resized/'
encrypted_path='/home/anika/Desktop/Thesis/images_for_evaluation_encrypted/'
path_to_write='/home/anika/Desktop/Thesis/images_for_evaluation_decrypted/'

path_of_attribute_list='/home/anika/Desktop/Thesis/Data/attribute_list.odt'
path_of_access_policies='/home/anika/Desktop/Thesis/Data/access_policies.ods'
path_of_possessed_attributes='/home/anika/Desktop/Thesis/Data/possessed_attribute.ods'
path_of_times = '/home/anika/Desktop/Thesis/Image_data/image_timings/new_model_times.csv'

attrs=load_attribute_list(path_of_attribute_list)
access_policies=load_access_policies(path_of_access_policies)
possessed_attribute=load_possessed_attributes(path_of_possessed_attributes)


#global symmtric key
key={}
iv = os.urandom(16)


if __name__=="__main__":

    key_generation_time=0
    encryption_time=0
    decryption_time=0
    total_rows=0

    for i in range(0,5):
        path='/home/anika/Desktop/Thesis/Image_data/images_for_evaluation_resized/'
        encrypted_path='/home/anika/Desktop/Thesis/Image_data/images_for_evaluation_encrypted/'
        path_to_write='/home/anika/Desktop/Thesis/Image_data/images_for_evaluation_decrypted/'

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

        no_of_attributes,k_t,e_t,d_t=calc(image,access_policies[DO][4])
        

        key_generation_time+=k_t
        encryption_time+=e_t
        decryption_time+=d_t
        total_rows+=1
    


 
    key_generation_time/=total_rows
    encryption_time/=total_rows
    decryption_time/=total_rows

    print("\nKey generation time in ms",key_generation_time)
    print("\nEncryption time",encryption_time)
    print("\nDecryption time",decryption_time)

    times=[no_of_attributes,key_generation_time,encryption_time,decryption_time]
    print("\n",times)
    write_time(path_of_times,times)

    

    
