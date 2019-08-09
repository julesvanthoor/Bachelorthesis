# Installing instructions

To run the code in this directory, the open-source TLS-Attacker framework from 
the Chair for Network and Data Security of the Ruhr University Bochum needs to 
be used:

`git clone https://github.com/RUB-NDS/TLS-Attacker.git`

Then, Mapper.java and ConnectorTransportHandler.java need to be placed in the
directory:

`/TLS-Core/src/main/java/de/rub/nds`

After StateLearner and a TLS 1.3 implementation (we tested OpenSSL and WolfSSL)
are set up, the user can run Mapper.java to derive the state machines.

In our project, we made use of the TLS-Attacker framework as it was on january 
16th 2018. So, to be sure to reproduce the exact same results as we did, we 
recommend downloading the repository from that date.

Also, we used the OpenSSL version from December 13th, 2017 and the latest 
WolfSSL version.