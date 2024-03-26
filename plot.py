import pandas as pd
import matplotlib.pyplot as plt

file_path1='/home/anika/Desktop/Thesis/Data/Final_timings_for_seminar2/times_list_1.csv'
file_path2='/home/anika/Desktop/Thesis/Data/Final_timings_for_seminar2/times_list_2.csv'
file_path3='/home/anika/Desktop/Thesis/Data/Final_timings_for_seminar2/times_list_improve_2.csv'
df1=pd.read_csv(file_path1,header=None)
print(df1)
df2=pd.read_csv(file_path2,header=None)
print(df2)
df3=pd.read_csv(file_path3,header=None)
print(df3)

no_of_attributes=df1[0]
encryption_time_1=df1[1]
encryption_time_2=df2[1]
encryption_time_3=df3[1]


