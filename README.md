# SID
Symmetric searchable encryption scheme implementation in python from https://eprint.iacr.org/2019/813

For testing, D184MB.zip from https://zenodo.org/record/3360392 was used

How to run:
I tested the code on a linux machine with python3 and nano installed. It contains os.system() commands which could be linux terminal speciffic. Install pycryptodome library for python3 (pip3 install pycryptodome). Run with: $ python3 SID.py

It will read the txt files from a specified folder (for example D184MB). Then it creates the dataowner database (words.db), two folders (CSP and TA) and create databases for the CSP and the TA. The CSP folder will contain the encrypted files from the specified folder and the CSP database. The TA folder will contain the In_TA database which is the same as words.db.

If the databases are aready created once answer n to the "[?] Is this the first time running the script? (y/n)" question as it will just use the already created databases.

The Experiments.pdf file contains some experiments I have done with a set of files.
