from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc,Input,Output
from charm.toolbox.msp import MSP
import numpy as np
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import timeit
from Crypto.Util.number import getPrime
from charm.schemes.pkenc.pkenc_rsa import RSA_Enc, RSA_Sig
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

def authority_setup(group,q,G):

    #select yi,ki randoms from ZR as MSK
    yi=group.random(ZR)
    ki=group.random(ZR)

    msk=(yi,ki)

    #calculate PK as {yi.G,ki.G}
    pk=(yi*G,ki*G)


    return (msk,pk)

def registration_user_phase():
    #each DU selects a number Ku randomly from ZR 
    #and computes Ru=Ku*G
    Ku=group.random(ZR)
    Ru=Ku*G

    #then DU sends its general identity and Ru to the CA
    #to get registered
    return(Ru,GID)

def registration_CA(GID,Ru):
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
  

def key_generation(msk,pk):

    #Ai calculates partial user secret key Us for DU
    #and maintains list for it.

    #Usi=yi+H(GID)*ki
    attribute_of_user=possessed_attribute[GID]
    Us={}
    for attr in attribute_of_user:     
        Yi=msk[0]
        Ki=msk[1]
        Usi=Yi+Hash_gid*Ki
        Us[attr]=Usi

  
    #send it to DU
    if debug == True:
         print("\nUs",Us)

    return Us

def key_generation_user(Us):
    
 
    #DU selects a random integer p from ZR
    #Usi'=yi+H(G)*Ki+p

    p=group.random(ZR)
    for idx,val in enumerate(Us.keys()):
        temp=Us[val]
        temp+=p
        Us[val]=temp
 

    if debug == True:
        print("\nUs",Us)

    return Us,p


def encrypt(P,access_policy,msk):

    t=0
    group.InitBenchmark( )
    group.StartBenchmark(["RealTime"])

    policy_string=access_policy

    #add padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(P) + padder.finalize()

    #DO does performs a symmetric encryption on P message
    #using AES
    c=group.random(ZR)
    c=c*G
    c1 = os.urandom(32)
    key[c]=c1


    cipher = Cipher(algorithms.AES(key[c]), modes.CBC(iv),default_backend())
    encryptor = cipher.encryptor()
    C = encryptor.update(padded_data) + encryptor.finalize()
    
    #reencryption

    #add padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(C) + padder.finalize()

    cipher = Cipher(algorithms.AES(key[c]), modes.CBC(iv),default_backend())
    encryptor = cipher.encryptor()
    C = encryptor.update(padded_data) + encryptor.finalize()



    #Dd,Qd data owners secret key and public key
    D=group.random(ZR)
    Q=group.random(ZR)
     

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

    #C0=c+s*G
    C0=c+s*G

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

    yi=msk[0]
    ki=msk[1]
    for x in attr_list:
       temp=[]
       for idx,val in enumerate(a[x]):
           temp.append(a[x][idx]*G)
       C1[x]=np.sum(temp)+yi*G
     

    for x in attr_list:
        temp=[]
        for idx,val in enumerate(w[x]):
            temp.append(w[x][idx]*G)
        C2[x]=np.sum(temp)+ki*G

   

    group.EndBenchmark()
    t= t + group.GetBenchmark("RealTime") 
   

    if debug==True:
        print("\nkey",c1)
        print("\nc",c)
        print("\ct",C)
        print("\nA",A)
        print("\nShares",shares)
        print("\na",a)
        print("\nw",w)

        print("\nC1",C1)
        print("\nC2",C2)
        print("\nC0",C0)
 

    return (C0,C1,C2,c,shares,a,w,C,attr_list,no_of_attributes,t*1000)


def recoverSecret(shares,coeff,pruned_list):
        
        #take shares and attempt to recover secret by taking sum of coeff * share for all shares.
        #if user indeed has at least k of n shares, then secret will be recovered.
        list = shares.keys()

        # if self.verbose: print(list)
        # coeff = util.recoverCoefficients(list)

        secret = 0
        for attrs in pruned_list:
            attr=attrs.getAttribute()
            secret += (coeff[attr] * shares[attr])

        return secret



def decryption_DUA(C0,C1,C2,Us,c,shares,p,DU,access_policy,a,w,attr_list,msk):

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
        return(-1,-1,-1,-1,-1,-1,ok,-1)

    coeff = util.getCoefficients(policy)
  

    #recover secret any such cx from ZR which satisfies
    #sum(cx.Ax) over x is (1,0,0,0,0...)
    #and cx.ax=s
    s=recoverSecret(shares,coeff,pruned_list)

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
    # print("\nUs",Us)

    for attr in pruned_list:
        x=attr.getAttribute()
        D[x]=C1[x]-Us[x]*G+Hash_gid*C2[x]


    #######################################
    D1={}
    for attr in pruned_list:
        x=attr.getAttribute()
        D1[x]=np.sum(a[x])*G+Hash_gid*np.sum(w[x])*G-p*G


    ##################################
    #if d=d1 then the user have correct parameters
    if(D1==D):
        #N1=sum for all x(cx*Dx)= cx*ax*G+H_GID*cx*wx-p*g
        temp=0
        for attr in pruned_list:
            x=attr.getAttribute()
            for idx in range(len(a[x])):
                temp+=(a[x][idx]*cx[x][idx])
                idx+=1


        cx_mul_ax=temp
    
        temp=0
        for attr in pruned_list:
            x=attr.getAttribute()
            for idx in range(len(w[x])):
                temp+=(w[x][idx]*cx[x][idx]*Hash_gid)
                idx+=1
        cx_mul_wx=temp

        comp1=cx_mul_ax*G
        comp2=Hash_gid*cx_mul_wx*G
        comp3=0
        for attr in pruned_list:
            x=attr.getAttribute()
            comp3+=np.sum(cx[x])
        comp3*=G
        comp3*=p

        N1=comp1+comp2-comp3

        temp=0
        for attr in pruned_list:
            x=attr.getAttribute()
            temp+=(np.sum(cx[x]))

        temp*=G

        N2=temp
    else:
        ok=False
        return(-1,-1,-1,-1,-1,-1,ok,-1)
    

    
    group.EndBenchmark()
    t= t + group.GetBenchmark("RealTime") 

    return (D,N1,N2,cx,pruned_list,c,ok,t*1000)


def decryption(N1,N2,C0,C1,C2,p,C,ok):
    
    t=0
    group.InitBenchmark( )
    group.StartBenchmark(["RealTime"])

    if(ok==False):
        print("\nDecryption Failed")
        return(False,"",-1)
    else:

        #c'=C0-N1-p*N2
        c1=N1+p*N2
        c1=C0-c1

        #double decryption
        cipher = Cipher(algorithms.AES(key[c1]), modes.CBC(iv),default_backend())
        decryptor = cipher.decryptor()
        M = decryptor.update(C)+decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        M = unpadder.update(M) + unpadder.finalize()

        cipher = Cipher(algorithms.AES(key[c1]), modes.CBC(iv),default_backend())
        decryptor = cipher.decryptor()
        M = decryptor.update(M)+decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        M = unpadder.update(M) + unpadder.finalize()


        if debug==True:
            print("\nC0",C0)
            print("\nN1",N1)
            print("\np",p)
            print("\nN2",N2)

            print("\nc1",c1)
            print("\nc",key[c1])
            print("\nM",M)


        group.EndBenchmark()
        t= t + group.GetBenchmark("RealTime") 

        return (True,M,(t)*1000)


def calc(Message,access_policy):
    s=timeit.default_timer()
    (msk,pk)=authority_setup(group,q,G)
    (Ru,GID)=registration_user_phase()
    (Cu,Pc,CP)=registration_CA(GID,Ru)
    registration_Complete(Cu,CP,Pc)

    Us=key_generation(msk,pk)
    Us,p=key_generation_user(Us)
    f=timeit.default_timer()

    key_generation_time=(f-s)*1000

    C0,C1,C2,c,shares,a,w,C,attr_list,no_of_attributes,t3=encrypt(Message.encode('UTF-8'),access_policy,msk)
    encryption_time=t3

    D,N1,N2,cx,pruned_list,c,ok,t4=decryption_DUA(C0,C1,C2,Us,c,shares,p,DU,access_policy,a,w,attr_list,msk)
    ok,M,t5=decryption(N1,N2,C0,C1,C2,p,C,ok)   
    if ok==True:
        decryption_time=t4+t5
        return no_of_attributes,key_generation_time,encryption_time,decryption_time
    


global group,q,G,GID,a,key,Hash_gid,debug,Hash_g,attrs,possessed_attribute,no_of_attributes,access_policies
#defining an elliptic cruve group
group=PairingGroup('SS512')
#define a random prime 
bits=160
q=getPrime(bits)
#define G a random int from finite filed ZR
G=group.random(G1)
#genral identity
GID=DO='Alice'
DU='Bob'
debug=False

path_of_attribute_list='/home/anika/Desktop/Data/attribute_list.odt'
path_of_access_policies='/home/anika/Desktop/Data/access_policies.ods'
path_of_possessed_attributes='/home/anika/Desktop/Data/possessed_attribute.ods'
path_of_data='/home/anika/Desktop/Data/diabetes.ods'
path_of_times = '/home/anika/Desktop/Data/times_list_2.csv'

attrs=load_attribute_list(path_of_attribute_list)
access_policies=load_access_policies(path_of_access_policies)
possessed_attribute=load_possessed_attributes(path_of_possessed_attributes)


#global symmtric key
key={}
#hash of data owner
Hash_gid=group.hash(GID)
iv = os.urandom(16)


if __name__=="__main__":

    key_generation_time=0
    encryption_time=0
    decryption_time=0
    total_rows=0

    doc = ezodf.opendoc(path_of_data)
    sheet = doc.sheets[0]

    for row in sheet.rows():
        data_record=""
        for cell in row:
            data_record+=str(cell.value)
    

        no_of_attributes,k_t,e_t,d_t=calc(data_record,access_policies[DO][4])

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

    

    
