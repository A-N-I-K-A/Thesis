from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc,Input,Output
from charm.toolbox.msp import MSP
import numpy as np
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import timeit


def recoverSecret(shares,coeff,pruned_list):
        
        #take shares and attempt to recover secret by taking sum of coeff * share for all shares.
        #if user indeed has at least k of n shares, then secret will be recovered.
        list = shares.keys()
        print("\nlist",list)

        # if self.verbose: print(list)
        # coeff = util.recoverCoefficients(list)

        print("\ncoeff",coeff)
        print("\nshares",shares)
        print("\nPruned",pruned_list)

        secret = 0
        for attrs in pruned_list:
            attr=attrs.getAttribute()
            secret += (coeff[attr] * shares[attr])

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
    for user_gid,possessed_attributes in user_list.items():
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

    print("\nS:",s)

    #C0=M+s*G
    C0=M+s*G

    print("\nM:",M)

    #take the access policy made by the data owner 
    #and output nxl access matrix A 
    policy = util.createPolicy(policy_str)
    attr_list = util.getAttributeList(policy)


    #LSSS access policy generate
    shares = util.calculateSharesDict(s, policy)

    print("\nshares",shares)


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


    print("\nlamda",lamda_for_all_x)

    return (C0,c1,c2,lamda_for_all_x,omega_for_all_X,shares,G,M)



def partial_decryption(C0,c1,c2,access_policy,possesed_attriubte,SK,shares,G):
   
    #whether the users who want to decrypt has enough attribute to decrypt
    policy = util.createPolicy(access_policy)
    pruned_list= util.prune(policy,possesed_attriubte)
    if pruned_list == False:
        return (False,-1,-1)
    
    coeff = util.getCoefficients(policy)
  

    print("\npruned_list",pruned_list)
    print("\ncoeff",coeff)

    #recover the secret S and calculate the s*G term
    s1=recoverSecret(shares,coeff,pruned_list)
    print("\nS1",s1)

    secret_comp=s1*G
    print("\ns*g",secret_comp)


    #sum(C2_x * SK_x_GID)
    idx=0
    for attrs in pruned_list:
        attr=attrs.getAttribute()
        c2[idx]=c2[idx]*SK[attr]
        idx+=1

    #sum c1-sum c2
    c=[]
    idx=0
    for attrs in pruned_list:
        c.append(c1[idx]-c2[idx])
        idx+=1
    
    #any cx such that cx*sum=s*G => cx=s*G/sum
    sum=np.sum(c)
    cx=secret_comp/sum
    print("\ncx",cx)


    return (True,c,cx)

def user_layer_decryption(C0,c,cx):

    sum=np.sum(c)

    #sum*cx=s*g
    s_g_and=sum*cx

    # M=C0-s*G
    M=C0-s_g_and
 
    print("\nM",M)


    return M


global group, util
group=PairingGroup('MNT224')
util = SecretUtil(group)  


#the attributes an user possess
attrs=['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN',
'ELEVEN', 'TWELVE', 'THIRTEEN', 'FOURTEEN', 'FIFTEEN', 'SIXTEEN', 'SEVENTEEN', 'EIGHTEEN', 'NINETEEN','TWENTY', 'TWENTY-ONE', 'TWENTY-TWO', 'TWENTY-THREE', 'TWENTY-FOUR', 'TWENTY-FIVE', 'TWENTY-SIX', 'TWENTY-SEVEN', 'TWENTY-EIGHT', 'TWENTY-NINE','THIRTY', 'THIRTY-ONE', 'THIRTY-TWO', 'THIRTY-THREE', 'THIRTY-FOUR', 'THIRTY-FIVE', 'THIRTY-SIX', 'THIRTY-SEVEN', 'THIRTY-EIGHT', 'THIRTY-NINE','FORTY', 'FORTY-ONE', 'FORTY-TWO', 'FORTY-THREE', 'FORTY-FOUR', 'FORTY-FIVE', 'FORTY-SIX', 'FORTY-SEVEN', 'FORTY-EIGHT', 'FORTY-NINE','FIFTY', 'FIFTY-ONE', 'FIFTY-TWO', 'FIFTY-THREE', 'FIFTY-FOUR', 'FIFTY-FIVE', 'FIFTY-SIX', 'FIFTY-SEVEN', 'FIFTY-EIGHT', 'FIFTY-NINE','SIXTY', 'SIXTY-ONE', 'SIXTY-TWO', 'SIXTY-THREE', 'SIXTY-FOUR', 'SIXTY-FIVE', 'SIXTY-SIX', 'SIXTY-SEVEN', 'SIXTY-EIGHT', 'SIXTY-NINE','SEVENTY', 'SEVENTY-ONE', 'SEVENTY-TWO', 'SEVENTY-THREE', 'SEVENTY-FOUR', 'SEVENTY-FIVE', 'SEVENTY-SIX', 'SEVENTY-SEVEN', 'SEVENTY-EIGHT', 'SEVENTY-NINE','EIGHTY', 'EIGHTY-ONE', 'EIGHTY-TWO', 'EIGHTY-THREE', 'EIGHTY-FOUR', 'EIGHTY-FIVE', 'EIGHTY-SIX', 'EIGHTY-SEVEN', 'EIGHTY-EIGHT', 'EIGHTY-NINE','NINETY', 'NINETY-ONE', 'NINETY-TWO', 'NINETY-THREE', 'NINETY-FOUR', 'NINETY-FIVE', 'NINETY-SIX', 'NINETY-SEVEN', 'NINETY-EIGHT', 'NINETY-NINE','ONE-HUNDRED']

#user general identity and attributes
attrs_of_alice = attrs[0:100]
attrs_of_bob=attrs[0:100]

user_list={'alice':attrs_of_alice,'bob':attrs_of_bob}

#the access policy A of bob
access_policy="(((twenty-one or thirty-one) and ((thirty-three or (thirty-two or forty-seven))) or (fifty-five and sixty-six)) and (eighty-nine or (ninety and (one-hundred)) or (seventy-eight and ninety-five))) or ((seventy and (eighty or (ninety or one-hundred))) and ((forty or fifty)))"

st1=timeit.default_timer()
(msk,mpk,PK,SK,G)=authority_setup()
ft1=timeit.default_timer()


print("\nMaster secret key :",msk)
print("\nMaster Public key:",mpk)
print("\nPublic key of attributes:",PK)
print("\nSecret key for attributes:",SK)

plain_text='Pregnancies=6,Glucose=7,BloodPressure=8,SkinThickness=9,Insulin=10.BMI=11,DiabetesPedigreeFunction=12,Age=13'
st2=timeit.default_timer()
C0,c1,c2,lamda_for_all_x,omega_for_all_x,shares,G,M=encrypt(plain_text,G,access_policy,PK)
ft2=timeit.default_timer()


print("\nC0:",C0)
print("\nc1:",c1)
print("\nc2:",c2)


#alice wants to decrypt the message of bob
st3=timeit.default_timer()
ok,c,cx=partial_decryption(C0,c1,c2,access_policy,user_list['alice'],SK['alice'],shares,G)
ft3=timeit.default_timer()

if ok==False:
   print("\nDecryption Failed\n")
else:
    M1=user_layer_decryption(C0,c,cx)
    if M==M1:
        print("\nSuccessful Decryption!\n")
        print('\nElapsed time for authority setup',(ft1-st1)*1000, "ms")
        print("\nElapsed time for encryption ",(ft2-st2)*1000,"ms")
        print("\nElapsed time for decryption",(ft3-st3)*1000,"ms")
    else:
        print("\nFailed Decryption")



    


