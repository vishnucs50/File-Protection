from random import randint
import hashlib
from Crypto.Hash import HMAC, SHA1
import ssl
import smtplib
from random import seed
import random
import os
import sys
import getpass
secret = b'123456789abcdef0123456789abcdef0'

def generateotp(secret):

    # Used to regulate number of trials
    counter = random.randint(1, 100)
    # counter = input("Enter the counter vaue: ")                     #Enter the counter value required
    HS = HMAC.new(secret, digestmod=SHA1)
    hashbyte = str.encode(str(counter))
    HS = HS.update(hashbyte)

    HS = HS.hexdigest()
    #print("The hash value is:", HS)  # Hash value

    offset = HS[39]
    offset = int(offset, 16)
    #print ("The offset value is:", offset)
    offset = offset * 2  # Position of offset for hex representation in 4 bits each

    snum = HS[offset: (offset + 8)]  # truncation of the hash message

    snumbin = bin(int(snum, 16))[2:].zfill(32)  # Transform the hexadecimal to binary
    Snumtruncate = snumbin[1:]  # Returns the last 31 bits value
    snumhex = hex(int(Snumtruncate, 2))  # Conversion of last 31 bits to Hexadecimal
    #print("The snum value is:", snumhex)
    digitvalue = int(Snumtruncate, 2)  # Generate a digit value in integer
    otp_value = digitvalue % (10 ** 6)  # Compute OTP value
    #print("The generated otp value is:", otp_value)
    return otp_value

def sendmail(otp_code, email):  # A function that sends OTP to an email
        smtp_server = "smtp.gmail.com"
        port = 465  # Port number for connection
        sender_email = raw_input("Enter the email address for dispatching the OTP to the user:")
        passkey = raw_input("Enter the password of the OTP dispatch email address:")
        #passkey = getpass.getpass(prompt='Password: ', stream=None)
        context = ssl.create_default_context()

        #sender_email = "sojiadvanced@gmail.com"
        #receiver_email = raw_input("Enter the recipient email address:")
        message = """\
        Subject: OTP ALERT
        \n
        \n
        OTP value is {}.""".format(otp_code)

        server = smtplib.SMTP_SSL(smtp_server, port)
        server.login(sender_email, passkey)
        server.sendmail(sender_email, email, message)
        server.quit()

def register():
    username = raw_input("Enter Username: ")

    file = open("new_example.txt","r")
    for line in file.readlines():              # read through the file to check if the username already exists.
        if username in line:
            print("Username already in use. Please select another")
            exit(0)                            # Exit program if the username is already in use
    file.close()
    file = open("new_example.txt", "a")
    file.write(username)                # Write u_name to the file. This will be used later on to check credentials for login sessions
    password = raw_input("Enter your password:")
    #password = getpass.getpass("Enter Password: ")
    salt = randint(0,9) #add the random number to the password which will later on be hashed
    #print("salt", salt)
    password = password + str(salt)
    password =  int(hashlib.sha256(password.encode('utf-8')).hexdigest(), 16) % 10**8   # hash password
    file.write(" ")
    file.write(str(password)) #store hashed password
    e_mail = raw_input("Enter mail ID: ")
    file.write(" ")
    file.write(e_mail)
    file.write(" ")
    file.write(str(salt)) # store Salt
    file.write("\n")
    file.close()
    login_promt = raw_input("would you like to login? 'Y' or 'N':  ") # If the user wants to login after registration, take them to the login screen.
    login_promt=login_promt.upper()
    if login_promt =='Y':
        if login():
            print("You are now logged in...")

        else:
            print("You are exiting now....")                # Exit program if user doesn't want to login
            exit(0)

def login():
    username = raw_input("Please enter your username:  ")
    password = raw_input('Please enter your password:')
    #password = getpass.getpass("Please enter your password:  ")
    for line in open("new_example.txt","r").readlines(): # Read the lines
        login_info = line.split() # Split on the space, and store the results in a list of two strings
        if username == login_info[0]:
            email = login_info[2] # extract mail from file
            password = password + (login_info[3]) # add the hash from file to the password
            password = int(hashlib.sha256(password.encode('utf-8')).hexdigest(), 16) % 10**8 # hash the password
            password = str(password) # convert to string and compare with the one in file
            if password == login_info[1]:
                otp_code = generateotp(secret)
                sendmail(otp_code, email)  # Function that sends an email
                checkvalue = raw_input("Enter the value of the received OTP:")

                if (int(checkvalue) == otp_code):
                    print("Your file will be opened right away")
                    os.startfile("C:\Users\Cyberfleet\sojiadvanced_Repo\Grad School\US Schools\MichiganTech\EE4723_NetworkSec\FinalProject\cybermortal-syek")

                else:
                    print("You do not have access to this file, contact your System Administrator")
                #print("Correct credentials!......Logging In\nEmail is: ",email)
                #print("salt: ", login_info[3])
                #return True
            else: # If password doesn't match
                print("Wrong Credentials. Please try again later")
                return False
    #print("Incorrect credentials.")
    return False



if __name__ == "__main__":
    U_input= raw_input("Are you a new user? Y or N:  ")
    U_input= U_input.upper()
    if U_input=='Y':
        register()
    elif U_input=='N':
        Login_req = raw_input("Do you want to proceed to Login? 'Y' or 'N:  ")
        Login_req= Login_req.upper()
        if Login_req =='Y':
            login()

        else:
            print("Please enter valid Response\nNow Exiting....")
            exit(0)
    else:
        print("Enter Valid Response.. Now exiting")
        exit(0)