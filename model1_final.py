from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc,Input,Output
from charm.toolbox.msp import MSP
import numpy as np
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import timeit

from odf import text, teletype
from odf.opendocument import load
import ezodf
import csv

from odf import text, teletype
from odf.opendocument import OpenDocumentText
from pyexcel_ods3 import save_data,get_data
from collections import OrderedDict


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

        if debug==True:
            print("\nlist",list)
            print("\ncoeff",coeff)
            print("\nshares",shares)
            print("\nPruned",pruned_list)

        return secret


def authority_setup():
    #random number n from ZR as master secret key
    n=group.random(ZR)
    msk=n

    #publishes nG as public key
    mpk=n*G


    #for each attribute i in the system selecy ki from ZR 
    #and publish PKi=Ki*G as public key
    PK={}
    KI={}
    for attribute in attrs:
        Ki=group.random(ZR)
        KI[attribute]=Ki
        Ki*=G
        PK[attribute]=Ki
         

    #for each data user in the system authority maintains an
    #attrbiute list corresponding to its GID
    SK={}
    for user_gid,possessed_attributes in possessed_attribute.items():
        h_gid=group.hash(user_gid)
        temp={}
        for attribute in possessed_attributes:
            #secret key for each attribute i of an user
            #SK(i,GID)=ki+H(GID)*n
            SKi=KI[attribute] + h_gid *n
            temp[attribute]=SKi
        SK[user_gid]=temp

    return (msk,mpk,PK,SK)



def encrypt(plain_text,policy_str,PK):
    #map the plain text message to a point on the elliptic curve
    h_message=group.hash(plain_text)
    M=G*h_message
    s=group.random(ZR)

    #C0=M+s*G
    C0=M+s*G

    #take the access policy made by the data owner 
    #and output nxl access matrix A 
    policy = util.createPolicy(policy_str)
    attr_list = util.getAttributeList(policy)
    no_of_attributes=len(attr_list)


    #LSSS access policy generate
    shares = util.calculateSharesDict(s, policy)


    #v=[s,v1-----vm]
    #u=[0,u1---um]
    v=[]
    v.append(s)
    for _ in attr_list:
        v.append(group.random(ZR))

    u=[]
    u.append(0)

    for _ in attr_list:
        u.append(group.random(ZR))


    #c1_x=lamda_x*G+omega*PK[attribute_x]
    #c2=omega_x*G
    c1={}
    c2={}

    lamda_for_all_x={}
    omega_for_all_X={}

    #for every attrbiute in the users attribute list
    #lamda=Ax*V
    #omega=Ax*U

    for _,attr in enumerate(shares.keys()):
        temp=[]
        for idx,val in enumerate(v):
            temp.append(v[idx]*shares[attr])
        lamda_for_all_x[attr]=temp

    
    for _,attr in enumerate(shares.keys()):
        temp=[]
        for idx,val in enumerate(u):
            temp.append(u[idx]*shares[attr])
        omega_for_all_X[attr]=temp    

    #C1,x=lamda[x]*G+omega[x]*PK[x]
    #C2,x=omega[x]*G
                
 
    for _,attr in enumerate(shares.keys()):
    
        # comp1=lamda*G
        # comp2=omega*PK[attr]
        # c1.append(comp1+comp2)
        # comp3=omega*G
        # c2.append(comp3)
        comp1=[]
        comp2=[]
        comp3=[]

        for idx,val in enumerate(lamda_for_all_x[attr]):
            comp1.append(val*G)
        
        for idx,val in enumerate(omega_for_all_X[attr]):
            comp3.append(val*G)

        for idx , val in enumerate(omega_for_all_X[attr]):
            comp2.append(val*PK[attr])

        c2[attr]=comp3
        c1[attr]=[]
        for idx in range(len(comp1)):
            c1[attr].append(comp1[idx]+comp2[idx])
            idx+=1

   

    if debug==True:
        print("\nS:",s)
        print("\nM:",M)
        print("\nshares",shares)
        print("\nlamda",lamda_for_all_x)

    return (C0,c1,c2,shares,lamda_for_all_x,omega_for_all_X,M,no_of_attributes)



def decryption(C0,c1,c2,shares,access_policy,possesed_attriubte,SK,a,w):
   
    #whether the users who want to decrypt has enough attribute to decrypt
    policy = util.createPolicy(access_policy)
    pruned_list= util.prune(policy,possesed_attriubte)
    if pruned_list == False:
        return (False,-1,-1)
    
    coeff = util.getCoefficients(policy)
    s1=recoverSecret(shares,coeff,pruned_list)

    #get cx
    cx_ar={}
    l=len(pruned_list)
    sum=0
    l1=0
    for attr in pruned_list:
        x=attr.getAttribute()
        cx_ar[x]=[]
        for idx,val in enumerate(a[x]):
            if idx==0:
                if l1<l-1:
                    cx_ar[x].append(1)
                    sum+=(a[x][idx]*1)
                else:
                    cx_ar[x].append((s1-sum)/a[x][idx])

            else:
                sum+=(a[x][idx]*0)
                cx_ar[x].append(0)
        l1+=1

    ##################################
        

    #sum(C2_x * SK_x_GID)
    idx=0
    for attrs in pruned_list:
        attr=attrs.getAttribute()
        for idx in range(len(c2[attr])):
            c2[attr][idx]=c2[attr][idx]*SK[attr]
            idx+=1

    #sum c1-sum c2*Sk => Ax*G-Wx*H(GID)*nG
    c={}
    idx=0
    for attrs in pruned_list:
        attr=attrs.getAttribute()
        temp=[]
        for idx in range(len(c1[attr])):
            temp.append(c1[attr][idx]-c2[attr][idx])
            idx+=1
        c[attr]=temp


    s_comp=G-G
    for attr in pruned_list:
        x=attr.getAttribute()
        for idx in range(len(c[x])):
            if cx_ar[x][idx]!=0:
                s_comp+=(cx_ar[x][idx]*c[x][idx])
            idx+=1


    #C0=M+sG 
    M=C0-s_comp
    
    if debug==True:
        print("\npruned_list",pruned_list)
        print("\ncoeff",coeff)
        print("\ns_comp",s_comp)
    return (True,M)
   

def calc(message,access_policy):
    st1=timeit.default_timer()
    (msk,mpk,PK,SK)=authority_setup()
    ft1=timeit.default_timer()
    setup_time=(ft1-st1)*1000

    if debug==True:
        print("\nMaster secret key :",msk)
        print("\nMaster Public key:",mpk)
        print("\nPublic key of attributes:",PK)
        print("\nSecret key for attributes:",SK)


    st2=timeit.default_timer()
    C0,c1,c2,shares,lamda_for_all_x,omega_for_all_x,M,no_of_attributes=encrypt(message,access_policy,PK)
    ft2=timeit.default_timer()
    encryption_time=(ft2-st2)*1000

    if debug==True:
        print("\nC0:",C0)
        print("\nc1:",c1)
        print("\nc2:",c2)


    #alice wants to decrypt the message of bob
    st3=timeit.default_timer()
    ok,M1=decryption(C0,c1,c2,shares,access_policy,possessed_attribute[DU],SK[DU],lamda_for_all_x,omega_for_all_x)
    ft3=timeit.default_timer()
    decryption_time=(ft3-st3)*1000

    if ok==False:
        print("\nDecryption Failed\n")
    else:
        if M==M1:
            if debug==True:
                print("\nSuccessful Decryption!\n")
                print("\nM",M1)
                print('\nElapsed time for authority setup',(ft1-st1)*1000, "ms")
                print("\nElapsed time for encryption ",(ft2-st2)*1000,"ms")
                print("\nElapsed time for decryption",(ft3-st3)*1000,"ms")
            return (no_of_attributes,setup_time,encryption_time,decryption_time)
        else:
            print("\nFailed Decryption")
            return -1,-1,-1,-1



global group,G, util,debug,attrs,possessed_attribute,access_policies,no_of_attributes
group=PairingGroup('SS512')
util = SecretUtil(group)  
debug=False
DO='Alice'
DU='Bob'
G=group.random(G1)

path_of_attribute_list='/home/anika/Desktop/Thesis/Data/attribute_list.odt'
path_of_access_policies='/home/anika/Desktop/Thesis/Data/access_policies.ods'
path_of_possessed_attributes='/home/anika/Desktop/Thesis/Data/possessed_attribute.ods'
path_of_data='/home/anika/Desktop/Thesis/Data/diabetes.ods'
path_of_times = '/home/anika/Desktop/Thesis/Data/times_list_1.csv'

attrs=load_attribute_list(path_of_attribute_list)
access_policies=load_access_policies(path_of_access_policies)
possessed_attribute=load_possessed_attributes(path_of_possessed_attributes)


if __name__=='__main__':

        key_generation_time=0
        encryption_time=0
        decryption_time=0
        total_rows=0

        doc = ezodf.opendoc(path_of_data)
        sheet = doc.sheets[0]

        #get the avg value for every row of pima indian dataset
        for row in sheet.rows():
            data_record=""
            for cell in row:
                data_record+=str(cell.value)
        

            no_of_attributes,k_t,e_t,d_t=calc(data_record,access_policies[DO][3])

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







    


