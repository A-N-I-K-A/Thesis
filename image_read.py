path=('/home/anika/Desktop/Thesis/Image_data/CXR1_1_IM-0001-3001.png')
path2=('/home/anika/Desktop/Thesis/image_try1.png')
fin=open(path,'rb')
image=fin.read()
fin.close()
print(image)

fin=open(path2,'wb')
fin.write(image)
fin.close()

