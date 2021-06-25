# NISPractical

The following system sets up a two-way communication channel using TCP where certificates, certified by a trusted simulated certificate authority, are exchanged and validated. Thereafter, messages can be securely transmitted using the princples of PGP. Namely, a combination of asymmetric & symmetric encryption, hashing, and compression.

## Compilation

```bash
make clean #Cleans previous .class files
make #compiles (Warnings are displayed, please ignore)
```

## Usage

```bash
#navigate to out folder
cd out

#Runs the methods for the certificate authority.
#Generates files used storing the CA public and private keys. If testing on two separate machines, only run this command once and ensure both participants have the 
#same pairing key documents. 
java CertificateAuthority 

#Runs the server  
java Server [port number]

#Runs the client
java Client [IP address] [port number]

#A TCP connection is made between the client and server. 
#Users can send messages or files with captions. 
#To send a file type '-file' followed by the prompts.
#To end the session type '-quit' 

#Note: files must be either be located in CLIENT_HOME or SERVER_HOME 
#respectively before attempting file transfers. 
```

## Contributing
FRMGRE001
LRXAVI001
DCKNAB001
MPTSAN003
