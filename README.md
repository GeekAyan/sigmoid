# sigmoid
This project is to calculate sigmoid function of an encrypted value homomorphically.

#FHE library used: TFHE
#Compile: cc alice.c -o alice.o -ltfhe-spqlios-fma
#Alice needs to be executed first to enter query data to be uploaded to cloud.
#Next, cloud executes sigmoid operation and stores the result in coud.
#To decrypt, run verif.
