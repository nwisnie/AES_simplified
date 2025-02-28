An implementation of the Advanced Encryption Standard written for ECE 404 with Avinash Kak at Purdue<br />
The BitVector module is used for handling bitwise and modular operation <br />
<br />
To encrypt a file use the following command:<br />
Python AES.py -e message.txt key.txt encrypted.txt<br />
where message.txt is an ascii message / key.txt is a 265 bit ket in text (32 characters) / encrypted.txt is a file for the generated encrypted text to be written to.<br />
<br />
To decrypt a file use the following command:<br />
Python AES.py -d encrypted.txt key.txt decrypted.txt<br />
where encrypted.txt is a message encrypted with AES in ECB mode / key.txt is a 265 bit ket in text (32 characters) / decrypted.txt is a file for the generated plaintext to be written to.
