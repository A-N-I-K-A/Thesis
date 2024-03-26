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
    G=group.random(G1)
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

    return (msk,mpk,PK,SK,G)



def encrypt(plain_text,G,policy_str,PK):
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
    c1=[]
    c2=[]
    lamda_for_all_x={}
    omega_for_all_X={}

    #for every attrbiute in the users attribute list
    for _,attr in enumerate(shares.keys()):
        #lamda=Ax*v
        for idx,val in enumerate(v):
            v[idx]*=shares[attr]

        lamda=v
        lamda_for_all_x[attr]=lamda

        #omega=Ax*u
        for idx,val in enumerate(u):
            u[idx]=u[idx]*shares[attr] 

        omega=u
        omega_for_all_X[attr]=omega

    
    # comp1=lamda*G
    # comp2=omega*PK[attr]
    # c1.append(comp1+comp2)
    # comp3=omega*G
    # c2.append(comp3)


    comp1=[]
    comp2=[]
    comp3=[]

    for idx,val in enumerate(lamda):
        comp1.append(lamda[idx]*G)
    
    for idx,val in enumerate(omega):
        comp3.append(omega[idx]*G)

    for idx , val in enumerate(omega):
        comp2.append(omega[idx]*PK[attr])

    for i in range(len(comp1)):
        c1.append(comp1[i]+comp2[i])

    for i in range(len(comp3)):
        c2.append(comp3[i])

    if debug==True:
        print("\nS:",s)
        print("\nM:",M)
        print("\nshares",shares)
        print("\nlamda",lamda_for_all_x)

    return (C0,c1,c2,lamda_for_all_x,omega_for_all_X,shares,G,M,no_of_attributes)



def decryption(C0,c1,c2,access_policy,possesed_attriubte,SK,shares,G,a,w,msk,DU):
   
    #whether the users who want to decrypt has enough attribute to decrypt
    policy = util.createPolicy(access_policy)
    pruned_list= util.prune(policy,possesed_attriubte)
    if pruned_list == False:
        return (False,-1,-1)
    
    coeff = util.getCoefficients(policy)

    #recover the secret S and calculate the s*G term
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
        
    print("\nsk",SK)
    print("\ncx",cx_ar)
    print("\nc1",c1)
    print("\nc2",c2)
  
    #sum(C2_x * SK_x_GID)
    idx=0
    for attrs in pruned_list:
        attr=attrs.getAttribute()
        c2[idx]=c2[idx]*SK[attr]
        idx+=1

    #sum c1-sum c2*Sk => Ax*G-Wx*H(GID)*nG
    c=[]
    idx=0
    for attrs in pruned_list:
        c.append(c1[idx]-c2[idx])
        idx+=1
    


    ############################
    #=> Ax*G-Wx*H(GID)*nG
    c_new=[]
    idx=0
    for attr in pruned_list:
        x=attr.getAttribute()
        c_new.append((np.sum(a[x])*G)-(np.sum(w[x])*group.hash(DU)*msk*G))
        idx+=1


    ###########################
    #continue only if C1,x-C2,x*Sk = Ax*G-Wx*n*G*H(GID)
    if(c!=c_new):
        #cx*(Ax*G-Wx*H(GID)*nG)
        cx_mul_ax=0
        for attr in pruned_list:
            x=attr.getAttribute()
            for idx in range(len(a[x])):
                cx_mul_ax+=(cx_ar[x][idx]*a[x][idx])
                idx+=1

        cx_mul_ax*=G

        cx_mul_wx=0
        for attr in pruned_list:
            x=attr.getAttribute()
            for idx in range(len(w[x])):
                cx_mul_wx+=(cx_ar[x][idx]*w[x][idx])
                idx+=1

        cx_mul_wx*=(G*msk*group.hash(DU))
      
        if ((cx_mul_wx)==False):
            return (False,-1)
        else:
            s_comp=cx_mul_ax

            #C0=M+sG
            M=C0-s_comp
            
            if debug==True:
                print("\npruned_list",pruned_list)
                print("\ncoeff",coeff)
                print("\nS1",s1)
                print("\ns_comp",s_comp)
            return (True,M)
    else:
        return (False,-1)


def calc(message,access_policy):
    st1=timeit.default_timer()
    (msk,mpk,PK,SK,G)=authority_setup()
    ft1=timeit.default_timer()
    setup_time=(ft1-st1)*1000

    if debug==True:
        print("\nMaster secret key :",msk)
        print("\nMaster Public key:",mpk)
        print("\nPublic key of attributes:",PK)
        print("\nSecret key for attributes:",SK)


    st2=timeit.default_timer()
    C0,c1,c2,lamda_for_all_x,omega_for_all_x,shares,G,M,no_of_attributes=encrypt(message,G,access_policy,PK)
    ft2=timeit.default_timer()
    encryption_time=(ft2-st2)*1000

    if debug==True:
        print("\nC0:",C0)
        print("\nc1:",c1)
        print("\nc2:",c2)


    #alice wants to decrypt the message of bob
    st3=timeit.default_timer()
    ok,M1=decryption(C0,c1,c2,access_policy,possessed_attribute[DU],SK[DU],shares,G,lamda_for_all_x,omega_for_all_x,msk,DU)
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



global group, util,debug,attrs,possessed_attribute,access_policies,no_of_attributes
group=PairingGroup('SS512')
util = SecretUtil(group)  
debug=False
DO='Alice'
DU='Bob'

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
        

            no_of_attributes,k_t,e_t,d_t=calc(data_record,access_policies[DO][0])

            key_generation_time+=k_t
            encryption_time+=e_t
            decryption_time+=d_t
            total_rows+=1
            break

        key_generation_time/=total_rows
        encryption_time/=total_rows
        decryption_time/=total_rows

        print("\nKey generation time in ms",key_generation_time)
        print("\nEncryption time",encryption_time)
        print("\nDecryption time",decryption_time)

        times=[no_of_attributes,key_generation_time,encryption_time,decryption_time]
        print("\n",times)
        write_time(path_of_times,times)







    


