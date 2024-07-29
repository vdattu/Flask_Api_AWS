from flask import Flask, request, redirect, render_template, url_for, flash,session,abort,jsonify,send_file,make_response
from flask_session import Session
from teamuniqueid import genteamid,adotp
import mysql.connector
import mysql.connector.pooling
import random
import base64
import io
from io import BytesIO
from key import secret_key, salt, salt2
from itsdangerous import URLSafeTimedSerializer
from stoken import token,token2
from cmail import sendmail,mail_with_atc
import os
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import hashlib
import zipfile
from datetime import datetime
import gspread
import pandas as pd
from oauth2client.service_account import ServiceAccountCredentials
from smtplib import SMTPRecipientsRefused
import requests
from urllib.parse import urlencode
from flask_cors import CORS



app = Flask(__name__)
app.secret_key = secret_key
app.config['SESSION_TYPE'] = 'filesystem'

Session(app)
# conn = mysql.connector.pooling.MySQLConnectionPool(host='localhost', user='root', password='admin', db='realtime',pool_name='DED',pool_size=25, pool_reset_session=True)
CORS(app, resources={r"/register": {"origins": "https://doctorsolympiad.com","supports_credentials": True}})
CORS(app, resources={r"/client_error": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/icici": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/icici/addon": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/checkout-addon-payc/.*": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/login": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/forgot_password": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/reset_password/.*": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/checkout-order-pay": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/buyaddon": {"origins": "https://doctorsolympiad.com"}})
CORS(app, resources={r"/registeron/.*": {"origins": "https://doctorsolympiad.com","supports_credentials": True}})




db= os.environ['RDS_DB_NAME']
user=os.environ['RDS_USERNAME']
password=os.environ['RDS_PASSWORD']
host=os.environ['RDS_HOSTNAME']
port=os.environ['RDS_PORT']
 
conn=mysql.connector.pooling.MySQLConnectionPool(host=host,user=user,password=password,db=db,pool_name='DED',pool_size=25, pool_reset_session=True)

bcrypt = Bcrypt(app)

class Eazypay:
    def __init__(self,return_url):
        self.merchant_id = '376890'
        self.encryption_key = b'3777003168901000'
        self.sub_merchant_id = '20'
        self.paymode = '9'
        self.return_url = return_url

    def get_payment_url(self, reference_no, amount,name,email, phone,optional_field=None):
        mandatory_field = self.get_mandatory_field(reference_no, amount,name,email,phone)
        optional_field = self.get_optional_field(optional_field)
        amount = self.get_encrypted_value(str(amount))
        reference_no = self.get_encrypted_value(str(reference_no))
        name = self.get_encrypted_value(name)
        email = self.get_encrypted_value(email)
        phone = self.get_encrypted_value(str(phone))

        payment_url = self.generate_payment_url(mandatory_field, optional_field, reference_no, amount)
        
        return payment_url

    def generate_payment_url(self, mandatory_field, optional_field, reference_no, amount):
        encrypted_url = (
            f"https://eazypay.icicibank.com/EazyPG?merchantid={self.merchant_id}"
            f"&mandatory fields={mandatory_field}&optional fields={optional_field}"
            f"&returnurl={self.get_return_url()}&Reference No={reference_no}"
            f"&submerchantid={self.get_sub_merchant_id()}&transaction amount={amount}"
            f"&paymode={self.get_paymode()}"
        )
        # decrypted_url = (
        #     f"https://eazypay.icicibank.com/EazyPG?merchantid={self.merchant_id}"
        #     f"&mandatory fields={mandatory_fields}&optional fields={optional_field}"
        #     f"&returnurl={return_urls}&Reference No={reference_nos}"
        #     f"&submerchantid={merchant_ids}&transaction amount={amounts}"
        #     f"&paymode={pay_modes}"
        # )
        # print(decrypted_url)
        # print(encrypted_url)

        return encrypted_url


    def get_mandatory_field(self, reference_no, amount,name,email,phone):
        data = f'{reference_no}|{self.sub_merchant_id}|{amount}|{name}|{email}|{phone}'
        return self.get_encrypted_value(data)

    def get_optional_field(self, optional_field=None):
        if optional_field is not None:
            return self.get_encrypted_value(optional_field)
        return ''


    def get_encrypted_value(self, data):
        cipher = AES.new(self.encryption_key, AES.MODE_ECB)
        padded_plaintext = pad(data.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        encrypted_base64 = base64.b64encode(ciphertext)
        return encrypted_base64.decode('utf-8')

    def decrypt(self, encrypted_data):
        cipher = AES.new(self.encryption_key, AES.MODE_ECB)
        encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        decrypted_data = cipher.decrypt(encrypted_data_bytes)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data.decode('utf-8')


    def get_return_url(self):
        return self.get_encrypted_value(self.return_url)

    def get_sub_merchant_id(self):
        return self.get_encrypted_value(self.sub_merchant_id)

    def get_paymode(self):
        return self.get_encrypted_value(self.paymode)

def payment_success_exec():    
    if request.method == 'POST' and 'Total Amount' in request.form and request.form.get('Response Code') == 'E000':
        res = request.form
        
        # Same encryption key that we gave for generating the URL
        aes_key_for_payment_success = '3777003168901000'  # Replace this with the actual key

        try:
            data = {
                'Response_Code': res['Response Code'],
                'Unique_Ref_Number': res['Unique Ref Number'],
                'Service_Tax_Amount': res['Service Tax Amount'],
                'Processing_Fee_Amount': res['Processing Fee Amount'],
                'Total_Amount': res['Total Amount'],
                'Transaction_Amount': res['Transaction Amount'],
                'Transaction_Date': res['Transaction Date'],
                'Interchange_Value': res['Interchange Value'],
                'TDR': res['TDR'],
                'Payment_Mode': res['Payment Mode'],
                'SubMerchantId': res['SubMerchantId'],
                'ReferenceNo': res['ReferenceNo'],
                'ID': res['ID'],
                'RS': res['RS'],
                'TPS': res['TPS'],
            }
        except Exception as e:
            return False
        else:
            verification_key = f"{data['ID']}|{data['Response_Code']}|{data['Unique_Ref_Number']}|" \
                            f"{data['Service_Tax_Amount']}|{data['Processing_Fee_Amount']}|" \
                            f"{data['Total_Amount']}|{data['Transaction_Amount']}|" \
                            f"{data['Transaction_Date']}|{data['Interchange_Value']}|" \
                            f"{data['TDR']}|{data['Payment_Mode']}|{data['SubMerchantId']}|" \
                            f"{data['ReferenceNo']}|{data['TPS']}|{aes_key_for_payment_success}"
            
            # print(verification_key)
            encrypted_message = hashlib.sha512(verification_key.encode()).hexdigest()
            # print(encrypted_message)
            if encrypted_message == data['RS']:
                return True
            else:
                return False
    else:
        return False

def get_response_message(code):
    rc = {
        'E000': 'Payment Successful.',
        'E001': 'Unauthorized Payment Mode',
        'E002': 'Unauthorized Key',
        'E003' :'Unauthorized Packet', 
        'E004' :'Unauthorized Merchant', 
        'E005' :'Unauthorized Return URL', 
        'E006' :'"Transaction Already Paid, Received Confirmation from the Bank, Yet to Settle the transaction with the Bank', 
        'E007' :'Transaction Failed', 
        'E008' :'Failure from Third Party due to Technical Error', 
        'E009' :'Bill Already Expired', 
        'E0031' :'Mandatory fields coming from merchant are empty', 
        'E0032' :'Mandatory fields coming from database are empty', 
        'E0033' :'Payment mode coming from merchant is empty', 
        'E0034' :'PG Reference number coming from merchant is empty', 
        'E0035' :'Sub merchant id coming from merchant is empty', 
        'E0036' :'Transaction amount coming from merchant is empty', 
        'E0037' :'Payment mode coming from merchant is other than 0 to 9', 
        'E0038' :'Transaction amount coming from merchant is more than 9 digit length', 
        'E0039' :'Mandatory value Email in wrong format', 
        'E00310' :'Mandatory value mobile number in wrong format', 
        'E00311' :'Mandatory value amount in wrong format', 
        'E00312' :'Mandatory value Pan card in wrong format', 
        'E00313' :'Mandatory value Date in wrong format', 
        'E00314' :'Mandatory value String in wrong format', 
        'E00315' :'Optional value Email in wrong format', 
        'E00316' :'Optional value mobile number in wrong format', 
        'E00317' :'Optional value amount in wrong format', 
        'E00318' :'Optional value pan card number in wrong format', 
        'E00319' :'Optional value date in wrong format', 
        'E00320' :'Optional value string in wrong format', 
        'E00321' :'Request packet mandatory columns is not equal to mandatory columns set in enrolment or optional columns are not equal to optional columns length set in enrolment', 
        'E00322' :'Reference Number Blank', 
        'E00323' :'Mandatory Columns are Blank', 
        'E00324' :'Merchant Reference Number and Mandatory Columns are Blank', 
        'E00325' :'Merchant Reference Number Duplicate', 
        'E00326' :'Sub merchant id coming from merchant is non numeric', 
        'E00327' :'Cash Challan Generated', 
        'E00328' :'Cheque Challan Generated', 
        'E00329' :'NEFT Challan Generated', 
        'E00330' :'Transaction Amount and Mandatory Transaction Amount mismatch in Request URL', 
        'E00331' :'UPI Transaction Initiated Please Accept or Reject the Transaction', 
        'E00332' :'Challan Already Generated, Please re-initiate with unique reference number', 
        'E00333' :'Referer value is null / invalid Referer', 
        'E00334' :'Value of Mandatory parameter Reference No and Request Reference No are not matched', 
        'E00335' :'Payment has been cancelled',
        'E0801' :'FAIL', 
        'E0802' :'User Dropped', 
        'E0803' :'Canceled by user', 
        'E0804' :'User Request arrived but card brand not supported', 
        'E0805' :'Checkout page rendered Card function not supported', 
        'E0806' :'Forwarded / Exceeds withdrawal amount limit', 
        'E0807' :'PG Fwd Fail / Issuer Authentication Server failure', 
        'E0808' :'Session expiry / Failed Initiate Check, Card BIN not present', 
        'E0809' :'Reversed / Expired Card', 
        'E0810' :'Unable to Authorize', 
        'E0811' :'Invalid Response Code or Guide received from Issuer', 
        'E0812' :'Do not honor', 
        'E0813' :'Invalid transaction', 
        'E0814' :'Not Matched with the entered amount', 
        'E0815' :'Not sufficient funds', 
        'E0816' :'No Match with the card number', 
        'E0817' :'General Error', 
        'E0818' :'Suspected fraud', 
        'E0819' :'User Inactive', 
        'E0820' :'ECI 1 and ECI6 Error for Debit Cards and Credit Cards', 
        'E0821' :'ECI 7 for Debit Cards and Credit Cards', 
        'E0822' :'System error. Could not process transaction', 
        'E0823' :'Invalid 3D Secure values', 
        'E0824' :'Bad Track Data', 
        'E0825' :'Transaction not permitted to cardholder', 
        'E0826' :'Rupay timeout from issuing bank', 
        'E0827' :'OCEAN for Debit Cards and Credit Cards', 
        'E0828' :'E-commerce decline', 
        'E0829' :'This transaction is already in process or already processed', 
        'E0830' :'Issuer or switch is inoperative', 
        'E0831' :'Exceeds withdrawal frequency limit', 
        'E0832' :'Restricted card', 
        'E0833' :'Lost card', 
        'E0834' :'Communication Error with NPCI', 
        'E0835' :'The order already exists in the database', 
        'E0836' :'General Error Rejected by NPCI', 
        'E0837' :'Invalid credit card number', 
        'E0838' :'Invalid amount', 
        'E0839' :'Duplicate Data Posted', 
        'E0840' :'Format error', 
        'E0841' :'SYSTEM ERROR', 
        'E0842' :'Invalid expiration date', 
        'E0843' :'Session expired for this transaction', 
        'E0844' :'FRAUD - Purchase limit exceeded', 
        'E0845' :'Verification decline', 
        'E0846' :'Compliance error code for issuer', 
        'E0847' :'Caught ERROR of type:[ System.Xml.XmlException ] . strXML is not a valid XML string', 
        'E0848' :'Incorrect personal identification number', 
        'E0849' :'Stolen card', 
        'E0850' :'Transaction timed out, please retry', 
        'E0851' :'Failed in Authorize - PE', 
        'E0852' :'Cardholder did not return from Rupay', 
        'E0853' :'Missing Mandatory Field(s)The field card_number has exceeded the maximum length of', 
        'E0854' :'Exception in CheckEnrollmentStatus: Data at the root level is invalid. Line 1, position 1.', 
        'E0855' :'CAF status = 0 or 9', 
        'E0856' :'412', 
        'E0857' :'Allowable number of PIN tries exceeded', 
        'E0858' :'No such issuer', 
        'E0859' :'Invalid Data Posted', 
        'E0860' :'PREVIOUSLY AUTHORIZED', 
        'E0861' :'Cardholder did not return from ACS', 
        'E0862' :'Duplicate transmission', 
        'E0863' :'Wrong transaction state', 
        'E0864' :'Card acceptor contact acquirer',
    }

    return rc.get(code, 'Unknown Error')

@app.route('/')
def home():
    return render_template('index.html')
@app.route('/national_committee')
def national_committee():
    return render_template('national-committe.html')


@app.route('/ima_ap_state_committee')
def ima_ap_state_committee():
    return render_template('ima-ap-state-committe.html')

@app.route('/organising_committee')
def organising_committee():
    return render_template('organising-committee.html')


@app.route('/mission_statement')
def mission_statement():
    return render_template('mission-statement.html')



@app.route('/rules_nav')
def rules_nav():
    return render_template('rules.html')



@app.route('/contact')
def contact():
    return render_template('contact.html')



@app.route('/venue_sports_schedule')
def venue_sports_schedule():
    return render_template('schedule.html')



@app.route('/games_subgames')
def games_subgames():
    return render_template('games.html')

@app.route('/accomodation')
def accomodation():
    return render_template('accomodation.html')

@app.route('/terms_conditions')
def terms_conditions():
    return render_template('terms_conditions.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy-policy.html')


@app.route('/refund_returns')
def refund_returns():
    return render_template('refund-returns.html')

@app.route('/register')
def register():
    return render_template('suspend.html')

# @app.route('/login')
# def login():
#     return render_template('suspends.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         try:
#             fname = request.form['fname']
#             lname = request.form['lname']
#             email = request.form['email']
#             password = request.form['password']
#             mobile = request.form['mobile']
#             age = request.form['age']
#             gender = request.form['gender']
#             dob_year = request.form['dob_year']
#             dob_month=request.form['dob_month']
#             dob_day=request.form['dob_day']
#             city = request.form['city']
#             address = request.form['address']
#             state = request.form['state']
#             country = request.form['country']
#             degree = request.form['degree']
#             mci = request.form['mci']
#             game = request.form['game']
#             shirtsize = request.form['shirtsize']
#             otp=request.form['otp']
#             food_preference=request.form['food']
#             council=request.form['council']
#         except Exception as e:
#             message="Please fill all the fields"
#             return jsonify({'message':message})
#         dob=f"{dob_year}-{dob_month}-{dob_day}"
#         try:
#             mydb=conn.get_connection()
#             cursor = mydb.cursor(buffered=True)
#             # cursor.execute('SELECT COUNT(*) FROM register WHERE CONCAT(FirstName, " ", LastName) = %s', [full_name])
#             # count = cursor.fetchone()[0]
#             cursor.execute('SELECT COUNT(*) FROM register WHERE Email = %s', [email])
#             count1 = cursor.fetchone()[0]
#             cursor.execute('SELECT COUNT(*) FROM register WHERE mobileno = %s', [mobile])
#             count2 = cursor.fetchone()[0]
#             cursor.close()
#         except Exception as e:
#             print(e)
#             return jsonify({'message': 'Difficulty in checking the records for duplicate mail id try again later'})
#         finally:
#             if mydb.is_connected():
#                 mydb.close()
#         if count2 == 1:
#             message='Mobile number already exists.'
#             return jsonify({'message':message})
#         if count1 == 1:
#             message='Email already in use'
#             return jsonify({'message':message})
#         cond=True if session.get('email') else False
#         if cond!=True:
#             message='Please verify your email'
#             return jsonify({'message':message})
#         if session['otp']!=otp:
#             message='Invalid OTP'
#             return jsonify({'message':message})
#         if session.get('email')!=request.form['email']:
#             message='Email address changed verify otp again'
#             return jsonify({'message':message})

#         if gender=='Male' and game in ['KHO KHO','THROW BALL','WOMEN BOX CRICKET']:
#                 message=f'{game} can only be played by Female players.'
#                 return jsonify({'message':message})
#         if gender=='Female' and game in ['FOOTBALL','HARD TENNIS CRICKET','CRICKET WHITE BALL']:
#             message=f'{game} can only be played by Male players.'
#             return jsonify({'message':message})
#         # Get the uploaded certificate and photo files
#         certificate_file = request.files['certificate']
#         photo_file = request.files['photo']
#         c_file_data=certificate_file.read()
#         p_file_data=photo_file.read()
#         c_ext=certificate_file.filename.split(".")[-1]
#         p_ext=photo_file.filename.split(".")[-1]

#         # Generate unique filenames for certificate and photo using UUID
#         certificate_filename = f'{mobile}.{certificate_file.filename.split(".")[-1]}'
#         photo_filename = f'{mobile}.{photo_file.filename.split(".")[-1]}'


        
#         amount=4500 if food_preference=='Yes' else 3500

        
#         # Hash the password using bcrypt
#         hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        

#         data = {
#             'fname': fname, 'lname': lname, 'email': email, 'password': hashed_password, 'mobile': mobile,
#             'age': age, 'gender': gender, 'dob': dob, 'city': city.lower().strip(), 'address': address.strip(), 'state': state,
#             'country': country, 'degree': degree, 'mci': mci, 'game': game,
#             'amount': amount,'shirtsize': shirtsize,
#             'food_preference':food_preference,'council':council,'c_data':c_file_data,'p_data':p_file_data,
#             'p_ext':p_ext,'c_ext':c_ext
#         }
#         try:
#             mydb=conn.get_connection()
#             cursor=mydb.cursor(buffered=True)
#             cursor.execute('INSERT INTO temporary(FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', [data['fname'], data['lname'], data['email'], data['password'], data['mobile'], data['age'], data['gender'], data['dob'], data['city'], data['address'], data['state'], data['country'], data['degree'], data['mci'],data['shirtsize'], data['food_preference'],data['council'],data['c_data'],data['c_ext'],data['p_data'],data['p_ext']])
#             mydb.commit()
#             cursor.execute('SELECT id FROM temporary WHERE Email = %s AND mobileno = %s ORDER BY id DESC LIMIT 1',[data['email'], data['mobile']])
#             eid=cursor.fetchone()[0]

#             #cursor.execute('select ID,Concat(FirstName," ",LastName),Email,concat("91","",mobileno) AS mobile,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council from temporary where id=%s',[eid])
#             #deta=cursor.fetchone()+(game,)

#             #updated code------------------------- --------------------------------
#             #cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [eid,data['game'],data['amount']])
#             #print(game)
            
#             cursor.close()
#         except Exception as e:
#             print(e)
#             message='Please try after some time:Difficulty in storing data'
#             return  jsonify({'message':message})
#         else:
#             session.pop('otp')
#             session.pop('email')
#             game=data['game']
#             # scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
#             # credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
#             # client = gspread.authorize(credentials)
#             # spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
#             # worksheet = spreadsheet.get_worksheet(1)
#             # deta_str = [str(item) for item in deta]  # Convert all items to strings
#             # worksheet.append_row(deta_str)

#             #flash ('Registration successful! Complete the payment process.')
#             #subject='IMA Doctors Olympiad Registration'
#             #body=f'Thanks for the registration your unique for future reference is {eid}'
#             #sendmail(to=email, subject=subject, body=body)
#             #---------------------------------------------------------------
#             link=url_for('payment',eid=eid,game=data['game'],amount=amount,_external=True)
#             return jsonify({'message':'success','link':link})
#         finally:
#             if mydb.is_connected():
#                 mydb.close()
#     response = make_response(render_template('register.html'))
#     response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
#     response.headers['Pragma'] = 'no-cache'
#     response.headers['Expires'] = '-1'
#     return response

@app.route('/individual/<game>')
def individual(game):
    if session.get('user'):
        eid=session.get('user')
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT game,category FROM sub_games WHERE id=%s and game=%s",[eid,game])
            data1 = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        finally:
            if mydb.is_connected():
                mydb.close()
        # print(data)
        return render_template('Individualgames.html',data=data1,game=game)
    else:
        return redirect(url_for('login'))

def check_individual(gender,input_value,game,category):
    if input_value.isdigit():
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from register where id=%s',[input_value])
            data=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            message='Please try again later difficulty in fetching data from database'
            return message
        finally:
            if mydb.is_connected():
                print('case0')
                mydb.close()
        if data==0:
            message="Id not found"
            return message
        else:
            cond=True
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute("SELECT count(*) from individual_teams where id=%s and game=%s and category =%s and status=%s",[input_value,game,category,'Accepted'])
                count=cursor.fetchone()[0]
                cursor.execute("select count(*) from sub_games where id=%s and game=%s and category=%s",[input_value,game,category])
                count2=cursor.fetchone()[0]
                cursor.execute("SELECT gender from register where id=%s",[input_value])
                check_gender=cursor.fetchone()[0]
                cursor.execute('SELECT age from register  where id=%s',[input_value])
                age=cursor.fetchone()[0]
                cursor.execute('SELECT age from register where id=%s',[session.get('user')])
                lead_age=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                message='Please try again later.difficulty in fetching data from database'
                return message
            finally:
                if mydb.is_connected():
                    print('case 1')
                    mydb.close()
            if int(input_value)==session.get('user'):
                cond=False
                message='You cannot add yourself.'
                return message
            if count>0:
                cond=False
                message='User Registered to other team'
                return message
            if count2>0:
                cond=False
                message='User Registered to other team'
                return message
            if category!="Mixed Doubles":
                if check_gender!=gender:
                    cond=False
                    message='Cannot add other gender in team'
                    return message
            if category=="Mixed Doubles":
                if check_gender==gender:
                    cond=False
                    message='Cannot add same gender in team'
                    return message
            
            if game in ('CARROMS','TENNIKOIT'):
                if age>=50:
                    if lead_age<50:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                if age<50:
                    if lead_age>50:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
            if game  =='BADMINTON':
                if age<35:
                    if lead_age>35:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=35 and age<=45:
                    if not (lead_age>=35 and lead_age<=45):
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=46 and age<=55:
                    if not (lead_age>=46 and lead_age<=55):
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>55:
                    if lead_age<55:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
            
            if game == 'LAWN TENNIS':
                if category!="Mixed Doubles":
                    if age<35:
                        if lead_age>35:
                            cond=False
                            message="User doesn't belong to your age group"
                            return message
                    elif age>=35 and age<=45:
                        if not (lead_age>=35 and lead_age<=45):
                            cond=False
                            message="User doesn't belong to your age group"
                            return message
                    elif age>=46 and age<=55:
                        if not (lead_age>=46 and lead_age<=55):
                            cond=False
                            message="User doesn't belong to your age group"
                            return message
                    elif age>55:
                        if lead_age<55:
                            cond=False
                            message="User doesn't belong to your age group"
                            return message

            if game  =='TABLE TENNIS':
                if age<=39:
                    if lead_age>=40:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=40 and age<=54:
                    if not (lead_age>=40 and lead_age<=54):
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=55:
                    if lead_age<55:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message

            if cond==True:
                try:
                    mydb=conn.get_connection()
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute("SELECT concat_ws(' ',FirstName,LastName) as fullname from register where id=%s",[input_value])
                    message=cursor.fetchone()[0]
                    cursor.close()
                except Exception as e:
                    print(e)
                    message='Please try again later difficulty in fetching data from database'
                    return message
                else:
                    return message
                finally:
                    if mydb.is_connected():
                        print('case 11')
                        mydb.close()
    else:
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from register where email=%s',[input_value])
            data=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            message='Please try again later difficulty in fetching data from database'
            return message
        finally:
            if mydb.is_connected():
                print('case01')
                mydb.close()
        if data==0:
            message="Invite on submit User not found"
            return message
        else:
            cond=True
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id from register where Email=%s',[input_value])
                eid=cursor.fetchone()[0]
                cursor.execute("SELECT count(*) from individual_teams where id=%s and game=%s and category =%s and status=%s",[eid,game,category,'Accepted'])
                count=cursor.fetchone()[0]
                cursor.execute("select count(*) from sub_games where id=%s and game=%s and category=%s",[eid,game,category])
                count2=cursor.fetchone()[0]
                cursor.execute("SELECT gender from register where id=%s",[eid])
                check_gender=cursor.fetchone()[0]
                cursor.execute('SELECT age from register  where id=%s',[eid])
                age=cursor.fetchone()[0]
                cursor.execute('SELECT age from register  where id=%s',[session.get('user')])
                lead_age=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                message='Please try again later.difficulty in fetching data from database'
                return message
            finally:
                if mydb.is_connected():
                    print('case2')
                    mydb.close()
            if eid ==session.get('user'):
                cond=False
                message='You cannot add yourself.'
                return message
            if count>0:
                cond=False
                message='User Registered to other team'
                return message
            
            if count2>0:
                cond=False
                message='User Registered to other team'
                return message
            if category!="Mixed Doubles":
                if check_gender!=gender:
                    cond=False
                    message='Cannot add other gender in team'
                    return message
            if category=="Mixed Doubles":
                if check_gender==gender:
                    cond=False
                    message='Cannot add same gender in team'
                    return message
            
            if game in ('CARROMS','TENNIKOIT'):
                if age>=50:
                    if lead_age<50:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                if age<50:
                    if lead_age>50:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
            if game == 'BADMINTON':
                if age<35:
                    if lead_age>35:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=35 and age<=45:
                    if not (lead_age>=35 and lead_age<=45):
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=46 and age<=55:
                    if not (lead_age>=46 and lead_age<=55):
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>55:
                    if lead_age<55:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
            if game == 'LAWN TENNIS':
                if category!="Mixed Doubles":
                    if age<35:
                        if lead_age>35:
                            cond=False
                            message="User doesn't belong to your age group"
                            return message
                    elif age>=35 and age<=45:
                        if not (lead_age>=35 and lead_age<=45):
                            cond=False
                            message="User doesn't belong to your age group"
                            return message
                    elif age>=46 and age<=55:
                        if not (lead_age>=46 and lead_age<=55):
                            cond=False
                            message="User doesn't belong to your age group"
                            return message
                    elif age>55:
                        if lead_age<55:
                            cond=False
                            message="User doesn't belong to your age group"
                            return message
            if game =='TABLE TENNIS':
                if age<=39:
                    if lead_age>=40:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=40 and age<=54:
                    if not (lead_age>=40 and lead_age<=54):
                        cond=False
                        message="User doesn't belong to your age group"
                        return message
                elif age>=55:
                    if lead_age<55:
                        cond=False
                        message="User doesn't belong to your age group"
                        return message

            if cond==True:
                try:
                    mydb=conn.get_connection()
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute("SELECT concat_ws(' ',FirstName,LastName) as fullname from register where id=%s",[eid])
                    message=cursor.fetchone()[0]
                    cursor.close()
                except Exception as e:
                    print(e)
                    message='Please try again later difficulty in fetching data from database'
                    return message
                else:
                    return message
                finally:
                    if mydb.is_connected():
                        print('case21')
                        mydb.close()



@app.route('/registeronteam/<game>')
def registeronteam(game):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT count(*) FROM teams WHERE id=%s and game=%s",[session.get('user'),game])
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            if count==0:  
                flash("You Cannot Create a Team.Contact team lead to add you")
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('see_details',game=game))
        finally:
            if mydb.is_connected():
                mydb.close()

    else:
        return redirect(url_for('login'))



@app.route('/details/<game>')
def see_details(game):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            eid = session.get('user')
            cursor.execute("SELECT teamid, game, status FROM teams WHERE id=%s and game=%s", [eid,game])
            teamid, game, status = cursor.fetchone()
            cursor.execute("SELECT * FROM teams WHERE teamid=%s", [teamid])
            data = cursor.fetchall()
            cursor.execute("SELECT id FROM sub_games WHERE team_number=%s", [teamid])
            id = cursor.fetchone()[0]
            cursor.execute("SELECT concat_ws(' ',FirstName,LastName) as fullname FROM register WHERE id=%s", [id])
            name = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:

            games = {}
            for item in data:
                game_name = item[5]
                if game_name not in games:
                    games[game_name] = []
                games[game_name].append(item)

            return render_template('see_details.html', games=games, game=game, status=status, id=id, name=name)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login')) 
         
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('SELECT id,email,password FROM register WHERE Email = %s', [email])
            user = cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            flash('Please try again later difficulty in fetching data from database')
        else:

            if user:
                if bcrypt.check_password_hash(user[2], password):
                    session['user'] = user[0]
                    if session.get('user')==231000:
                        return redirect(url_for('admin'))
                    else:
                        return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password! Please try again.', 'error')
            else:
                flash('User not found! Please check your email and try again.', 'error')
        finally:
            if mydb.is_connected():
                mydb.close()

    return render_template('login.html')


@app.route('/logout')
def logout():
    if session.get('user'):
        session.pop('user')
        return redirect(url_for('home'))
    else:
        flash("already logged out")
        return redirect(url_for('login'))


@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    # Handle the form data and generate OTP
    data = request.form
    email = data['email']
    name = data['fullName']
    try:
        mydb=conn.get_connection()
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select count(*) from register where email=%s',[email])
        count=cursor.fetchone()[0]
        cursor.close()
    except Exception as e:
        print(e)
        return jsonify({'message': 'Difficulty in checking the records for duplicate mail id try again later'})
    else:
        if count==0:
            #address = data['address']
            # Generate a random OTP (For simplicity, using a 6-digit OTP)
            otp = ''.join(random.choices('0123456789', k=6))
            print(otp)
            if 'email' in session:
                session.pop('email')
                session.pop('otp')
                session['email']=email
                session['otp']=otp
            else:
                session['email']=email
                session['otp']=otp
            # subject = 'Email Confirmation'
            # body = f"Your One Time Password for Registring for IMA Doctors Olympiad is: {otp}\n\nThanks & Regards\nIMA Doctors Olympiad"
            html = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Registration Confirmation</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            margin: 0 auto;
                            max-width: 600px;
                            padding: 20px;
                            background-color: rgba(206, 238, 255, 0.5);
                        }}
                        h1 {{
                            text-align: center;
                        }}
                        img {{
                            display: block;
                            margin: 0 auto;
                            max-width: 100%;
                        }}
                        .otp {{
                            color: #323596;
                            font-weight: bold;
                            font-size: 30px;
                        }}
                    </style>
                </head>
                <body>
                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" />
                    <h1>Welcome to  IMA National Sports Meet - Doctors Olympiad 2023</h1>
                    <p>Dear {name},</p>
                    <p>Greetings from Doctors Olympiad 2023 team! and IMA Andhra Pradesh branch! We are thrilled to have received your
                        registration for this exciting event. Get ready to showcase your sportsmanship and camaraderie on the field!</p>
                    <p>Your One-Time Password (OTP) for registration is:<span class="otp"><strong> {otp} </strong></span></p>
                    <p>If you have any questions or require assistance, feel free to reach out to our dedicated team at
                        info@doctorsolympiad.com or 9759434567.</p>
                    <p>Thank you for registering for the IMA National Sports Meet: Doctors Olympiad 2023. We look forward to seeing you
                        at the event!</p><br>
                    
                    <p>IMA National Sports Meet - Doctors Olympiad 2023</p>
                </body>
                </html>
                """
                
            subject = 'Your One Time Password for Doctors Olympiad 2023'

            # Create a message and send the email
            
            try:
                # sendmail(to=email, subject=subject, body=body)
                mail_with_atc(to=email, subject=subject, html=html)
            except SMTPRecipientsRefused:
                return jsonify({'message': 'Please eneter a valid email address.'})
            else:
                return jsonify({'message': 'OTP has been sent to your email.OTP expires in 15 minutes.'})
        else:
            return jsonify({'message': 'Email already in use'})
    finally:
        if mydb.is_connected():
            mydb.close()

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('SELECT COUNT(*) FROM register WHERE Email=%s', [email])
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            flash('Please try again later difficulty in fetching data from database')
            return render_template('forgot_password.html')
        else:

            if count == 0:
                flash('Email not found. Please enter a def accep email.')
                return render_template('forgot_password.html')

            # Generate a one-time token for password reset
            serializer = URLSafeTimedSerializer(secret_key)
            token = serializer.dumps(email, salt=salt2)

            # Send the reset link to the user's email
            # subject = 'Password Reset Link'
            # body = f"Please follow this link to reset your password: {url_for('reset_password', token=token, _external=True)}"
            # sendmail(to=email, subject=subject, body=body)

            html = f"""
                <!DOCTYPE html>
                <html lang="en">

                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Password Reset</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            margin: 0 auto;
                            max-width: 600px;
                            padding: 20px;
                            background-color: #f4f4f4;
                        }}

                        h1 {{
                            text-align: center;
                            color: #333;
                        }}

                        p {{
                            color: #555;
                        }}

                        /* Center the image horizontally */
                        .image-container {{
                            text-align: center;
                        }}

                        /* Left-align the button */
                        .button-container {{
                            text-align: left;
                            margin-top: 20px;
                        }}

                        .button {{
                            display: inline-block;
                            background-color: #007BFF;
                            color: #fff;
                            padding: 10px 20px;
                            text-decoration: none;
                            border-radius: 5px;
                            font-weight: bold; /* Make the button text bold */
                        }}

                        .button:hover {{
                            background-color: #0056b3;
                        }}
                        
                        .reset-link {{
                            text-decoration: none;
                            color: white;
                            font-weight: bold;
                            font-size: 20px;
                        }}
                    </style>
                </head>

                <body>
                    <!-- Replace the image URL below with your own image URL -->
                    <div class="image-container">
                        <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />
                    </div>

                    <h1>Password Reset</h1>
                    <p>Hello,</p>
                    <p>We received a request to reset your password. Please click on the link below to reset your password:</p>

                    <div class="button-container">
                        <a href="{url_for('reset_password', token=token, _external=True)}" class="button"><span class="reset-link">Reset Password</span></a>
                    </div>

                    <p>If you did not request this password reset, you can ignore this email.</p>
                    <p>If you have any questions or need assistance, please do not hesitate to contact us.</p>

                    <p>Best regards,</p>
                    <p>Doctors Olympiad 2023</p>
                </body>

                </html>

            """
            
            subject = f'Password Reset Request for Doctors Olympiad 2023'

            # Create a message and send the email
            mail_with_atc(to=email, subject=subject, html=html)

            flash('Password reset link sent to your email.')
            return redirect(url_for('login'))
        finally:
            if mydb.is_connected():
                mydb.close()

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        serializer = URLSafeTimedSerializer(secret_key)
        email = serializer.loads(token, salt=salt2, max_age=180)
    except Exception as e:
        flash('Invalid or expired token. Please request a new password reset.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        # Validate and update the new password
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return render_template('reset_password.html', token=token)

        # Hash the new password using bcrypt
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('UPDATE register SET password=%s WHERE Email=%s', [hashed_password, email])
            mydb.commit()
            cursor.close()
        except Exception as e:
            print(e)
            flash('Please try again later difficulty in fetching data from database')
            return render_template('reset_password.html', token=token)
        else:

            flash('Password reset successful. You can now log in with your new password.')
            return redirect(url_for('login'))
        finally:
            if mydb.is_connected():
                mydb.close()

    return render_template('reset_password.html', token=token)


@app.route('/checkout-order-pay/<eid>/<game>/<amount>', methods=['GET', 'POST'])
def payment(eid,game,amount):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo,MCI_ID FROM temporary WHERE id=%s", [eid])
        data1 = cursor.fetchall()
        cursor.execute('SELECT email from temporary where id=%s',[eid])
        email=cursor.fetchone()[0]
        cursor.execute("select CONCAT(FirstName, ' ', LastName) AS FullName from temporary where id=%s",[eid])
        name=cursor.fetchone()[0]
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later..difficulty in fetching data from database'}
    finally:
        if mydb.is_connected():
            mydb.close()
    # print(payment_url)
    if request.method=='POST':
        ref=random.randint(1000000,99999999)
        eazypay_integration = Eazypay(url_for('success',_external=True))
        payment_url=eazypay_integration.get_payment_url(ref,amount,name,email,data1[0][3])
        try:
            mydb=conn.get_connection()
            cursor  = mydb.cursor(buffered=True)
            cursor.execute('select count(*) from games where game_name=%s',[game])
            cursor.execute('insert into payments (ordid,id,game,amount) values(%s,%s,%s,%s)',[ref,eid,game,amount])
            mydb.commit()
            cursor.close()
        except Exception as e:
            print(e)
            return jsonify({'status':'failed','message':'Please try again later difficulty in fetching data from database'})
        else:
            return jsonify({'status':'success','payment_url':payment_url})
        finally:
            if mydb.is_connected():
                mydb.close()
    return render_template('payment.html', data1=data1,game=game,amount=amount,eid=eid,name=name,email=email)



@app.route('/success',methods=['POST'])
def success():
    response = request.form.to_dict()
    response_code_value = response.get('Response Code','na')
    print(response_code_value)
    if response_code_value != 'na':
        if payment_success_exec():
            ref = int(response['ReferenceNo'])
            amount = float(response['Total Amount'])
            transaction_id = int(response['Unique Ref Number'])
            date=str(response['Transaction Date'])
            try:
                mydb=conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game from payments where ordid=%s',[ref])
                eid,game=cursor.fetchone()
                cursor.execute('select gender,email,mobileno from temporary where id=%s',[eid])
                gender,email,mobileno=cursor.fetchone()
                cursor.execute('insert into register (FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext) select FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext from temporary where id=%s',[eid])
                mydb.commit()
                cursor.execute('SELECT id from register where email=%s',[email])
                uid=cursor.fetchone()[0]
                cursor.execute('SELECT concat(FirstName," ",LastName) as name from register where email=%s',[email])
                name=cursor.fetchone()[0]
                cursor.execute('UPDATE  payments SET status=%s,amount=%s,id=%s,transactionid=%s WHERE ordid=%s',['Successfull',amount,uid,transaction_id,ref])
                cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [uid,game,amount])
                cursor.execute('DELETE FROM temporary where id=%s or email=%s or mobileno=%s',[eid,email,mobileno])
                mydb.commit()
                cursor.execute('SELECT count(*) from teams where email=%s',[email])
                t_count=cursor.fetchone()[0]
                cursor.execute('SELECT count(*) from individual_teams where email=%s',[email])
                i_count=cursor.fetchone()[0]
                if t_count!=0:
                    cursor.execute("UPDATE teams SET id=%s,fullname=%s where email=%s",[uid,name,email])
                    mydb.commit()
                if i_count!=0:
                    cursor.execute("UPDATE individual_teams SET id=%s, fullname=%s where email=%s",[uid,name,email])
                    mydb.commit()
                if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                    category="Men's singles" if gender=='Male' else "Women's singles"
                    cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,uid,category])
                    mydb.commit()
                    #  print(details)
                cursor.execute('select ID,Concat(FirstName," ",LastName),Email,concat("91","",mobileno) AS mobile,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council from register where id=%s',[uid])
                deta=cursor.fetchone()+(game,)
                cursor.close()
            except Exception as e:
                print(e)
                return jsonify({'status':'failed','message':'Please try again later difficulty in fetching data from database'})
            else:
                session['user']=uid
                try:
                    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
                    credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
                    client = gspread.authorize(credentials)
                    spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
                    worksheet = spreadsheet.get_worksheet(0)
                    deta_str = [str(item) for item in deta]  # Convert all items to strings
                    worksheet.append_row(deta_str)
                except Exception as e:
                    print('Error in sending whatsapp message!',e)

                html = f"""
                <!DOCTYPE html>
                <html lang="en">

                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Registration Confirmation</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            margin: 0 auto;
                            max-width: 600px;
                            padding: 20px;
                            background-color: rgba(206,238,255,0.5);
                        }}

                        h1 {{
                            text-align: center;
                        }}

                        img {{
                            display: block;
                            margin: 0 auto;
                            max-width: 100%;
                        }}

                        table {{
                            width: 100%;
                            border-collapse: collapse;
                            margin-top: 20px;
                        }}

                        th,
                        td {{
                            border: 1px solid black;
                            padding: 10px;
                            text-align: left;
                        }}

                        th {{
                            background-color: #f2f2f2;
                        }}

                        ul {{
                            list-style-type: none;
                            padding: 0;
                        }}

                        ul li {{
                            margin-bottom: 10px;
                        }}
                    </style>
                </head>

                <body>
                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" />
                    <h1>Welcome to Doctors Olympiad 2023</h1>
                    <p>Dear {name},</p>
                    <p>Greetings from the IMA National Sports Meet: Doctors Olympiad 2023 team! We are thrilled to have received your
                        registration for this exciting event. Get ready to showcase your sportsmanship and camaraderie on the field!</p>

                    <h2>Registration Details:</h2>
                    <table>
                        <tr>
                            <th>Event:</th>
                            <td>IMA National Sports Meet: Doctors Olympiad 2023</td>
                        </tr>
                        <tr>
                            <th>Participant's Name:</th>
                            <td>{name}</td>
                        </tr>
                        <tr>
                            <th>Registered Game:</th>
                            <td>{game}</td>
                        </tr>
                        <tr>
                            <th>Registration Date:</th>
                            <td>{date}</td>
                        </tr>
                        <tr>
                            <th>Unique ID:</th>
                            <td>{uid}</td>
                        </tr>
                        <tr>
                            <th>Transaction ID</th>
                            <td>{transaction_id}</td>
                        </tr>
                        <tr>
                            <th>Amount</th>
                            <td>&#8377; {amount} /-</td>
                        </tr>
                    </table>

                    <p>Your enthusiasm and commitment to joining us for this event are truly appreciated. We can't wait to see you in
                        action, competing in {game} and being part of this fantastic celebration of sports and
                        unity within the medical community.</p>

                 <!--   <h2>Event Details:</h2>
                    <table>
                        <tr>
                            <th>Date:</th>
                            <td>22nd November 2023</td>
                        </tr>
                        <tr>
                            <th>Time:</th>
                            <td>2 PM Onwards Tentative</td>
                        </tr>
                        <tr>
                            <th>Venue:</th>
                            <td>DOCTORS SPORTS ACADEMY GROUNDS</td>
                        </tr>
                    </table> -->

                    <p>Stay tuned for forthcoming updates and crucial information as we approach the event date. Furthermore, please make it a point to regularly check both your email and WhatsApp for important notices and updates.
                        Should you have any questions or require assistance, feel free to reach out to our dedicated team at <a href="mailto:info@doctorsolympiad.com"
                            style="text-decoration: none;">info@doctorsolympiad.com</a>
                or <a href="tel:9759434567"
                        style="text-decoration: none;">9759434567</a>.</p>

                    <p>Once again, thank you for registering for the IMA National Sports Meet: Doctors Olympiad 2023. Your participation
                        contributes to the success of this event and the spirit of camaraderie among medical professionals.</p>

                    <p>Warm regards,</p>
                    <p>Doctors Olympiad 2023<br><a href="mailto:info@doctorsolympiad.com"
                        style="text-decoration: none;">info@doctorsolympiad.com</a><br><a href="tel:9759434567" style="text-decoration: none;">9759434567</a></p>

                </body>

                </html>
                """
                subject='Registration Successful for Doctors Olympiad 2023'
                mail_with_atc(to=email, subject=subject, html=html)
                #aws
                # subject = 'Payment Successful! From Doctors Olympiad 2023'
                # mail_with_atc(email,subject,html)
                # subject='Registration Successful for Doctors Olympiad 2023'
                # # body=f'Hi {name},\n\nThanks for registering to {game} in Doctors Olympiad 2023\n\n\n\nunique reference id:{uid}\nName: {name}\n accept game: {game}\nTransaction id: {transaction_id}\n\n\n\n\nThanks and Regards\nDoctors Olympiad 2023\n\n\nContact:+91 9759634567'
                # mail_with_atc(to=email, subject=subject, html=html)
                
                flash('Payment Successful')
                if session.get('user')==231001:
                    return redirect(url_for('decor'))
                    # Log the user in by setting the 'user' in the session
                else:
                    return redirect(url_for('dashboard'))
            finally:
                if mydb.is_connected():
                    mydb.close()
        else:
            # Payment failed, show failure message
            response_msg = get_response_message(response.get('Response Code'))
            print(response_msg)
            return f"<h1>Transaction failed. Error: {response_msg} if money deducted..please contact us to info@doctorsolympiad.com with your payment screenshot and payment confirmation message from icici eazy pay</h1>"
    else:
        # 'Response_Code' key is missing in the response
        return "<h1>Invalid response received from payment gateway.if money deducted.. please contact us to info@doctorsolympiad.com with your payment screenshot and payment confirmation message from icici eazy pay</h1>"

""""
@app.route('/sport/<game>',methods=['GET','POST'])
def sport(game):
    if session.get('user'):
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select count(*) from game where game=%s and id=%s',[game,session.get('user')])
        count = cursor.fetchone()[0]
        cursor.execute('select gender from register where id=%s',[session.get('user')])
        gender=cursor.fetchone()[0]
        cursor.execute('select email from register where id=%s',[session.get('user')])
        email_id=cursor.fetchone()[0]
        cursor.close()
        if count==0:
            return redirect(url_for('payment',eid=session.get('user'),game=game))
        else:
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
            count=cursor.fetchone()[0]
            cursor.close()
            if count==0:
                if game in ('ATHLETICS','ARCHERY','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER_SKATING','FENCING','SHOOTING'):
                    if request.method=='POST':
                        cursor = mydb.cursor(buffered=True)
                        for i in request.form:
                            cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                        mydb.commit()
                        cursor.close()
                        subject='Doctors Olympiad Games registration'
                        body=f'You are successfully accept to {" ".join(request.form.values())}\n\nThanks and regards\nDoctors Olympiad 2023'
                        sendmail(email_id,subject,body)
                        return redirect(url_for('dashboard'))
                    return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
                else:
                    if request.method=='POST':
                        return '<h1>Updates are on the way see you soon</h1>'

                    return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender)
                    #pass




            elif count>=1:
                if game in ('ATHLETICS','ARCHERY','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER_SKATING','FENCING','SHOOTING'):
                    flash('You already accepted for this game')
                    return redirect(url_for('individual'))
                else:
                    return game
    else:
        return redirect(url_for('login'))
"""
@app.route('/dashboard')
def dashboard():
    if session.get('user'):
        if session.get('user')==231000:
            return redirect(url_for('admin'))
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            query1="""
            SELECT game_name,amount 
            FROM games 
            WHERE game_name NOT IN (
                SELECT game FROM game WHERE id = %s
            ) AND game_name IN (
                'ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON',
                'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING',
                'TABLE TENNIS', 'LAWN TENNIS'
            )"""
            cursor.execute(query1,[session.get('user')])
            add_individual_games=cursor.fetchall()
            query2 = """select gender from register where id=%s"""
            cursor.execute(query2,[session.get('user')])
            gender=cursor.fetchone()[0]
            query3 = """
            SELECT game_name 
            FROM games 
            WHERE game_name NOT IN (
                SELECT game FROM game WHERE id = %s) AND game_name not IN (
                'ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON',
                'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING',
                'TABLE TENNIS', 'LAWN TENNIS')"""
            if gender=='Male':
                cursor.execute(query3,[session.get('user')])
                m1={'THROW BALL','WOMEN BOX CRICKET','KHO KHO'}
                add_others_games=set([i[0] for i in cursor.fetchall()]).difference(m1)
            else:
                cursor.execute(query3,[session.get('user')])
                f1={'HARD TENNIS CRICKET','CRICKET WHITE BALL','FOOTBALL'}
                add_others_games=set([i[0] for i in cursor.fetchall()]).difference(f1)
            cursor.execute('SELECT game,amount from game where id=%s',[session.get('user')])
            games=cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'error':'Please try again later difficulty in fetching data from database'}
        else:
            '''cursor.execute('select count(*) from game where game=%s and id=%s',[game,session.get('user')])
            count = cursor.fetchone()[0]
            cursor.execute('select gender from register where id=%s',[session.get('user')])
            gender=cursor.fetchone()[0]
            cursor.execute('select email from register where id=%s',[session.get('user')])
            email_id=cursor.fetchone()[0]
            cursor.close()'''
            ivs=['ATHLETICS', 'BADMINTON', 'CARROMS', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'THROW', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS']
            sls=['ARCHERY','CYCLOTHON','CHESS','FENCING','ROWING','ROLLER SKATING']
            tms=['BALL BADMINTON','BASKETBALL','CRICKET WHITE BALL','FOOTBALL','HARD TENNIS CRICKET','KABADDI','KHO KHO','THROW BALL','TUG OF WAR','VOLLEY BALL','WOMEN BOX CRICKET']
            franchise=set()
            if gender=='Male':
                for i in tms:
                    for k,j in games:
                        if i==k:
                            if j<5000:
                                franchise.add(i)
                total_franchise=franchise.union(add_others_games.difference(franchise))
            else:
                total_franchise=add_others_games
            return render_template('my-account.html',games=games,add_individual_games=add_individual_games,add_teams_games=total_franchise,ivs=ivs,tms=tms,sls=sls,gender=gender)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/edit',methods=['GET','POST'])
def edit_profile():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            eid=session.get('user')
            cursor.execute("select id,firstname,lastname,email,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,c_data,p_data,p_ext,council from register where id =%s",[eid])
            data=cursor.fetchone()
            cursor.execute("select mobileno from register where id =%s",[eid])
            mobile=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return {'error':'Please try again later difficulty in fetching data from database'}
        finally:
            if mydb.is_connected():
                mydb.close()
        args={}
        if data[18]!=None:
            p_ext=data[18]
            base64_image = base64.b64encode(data[17]).decode('utf-8')
            args={'p_ext':p_ext,'base64_image':base64_image}
        
        if request.method=='POST':
            firstname=request.form['fname']
            # print(firstname)
            lastname=request.form['lname']
            email=request.form['email']
            mobile=request.form['mobile']
            gender=request.form['gender']
            city=request.form['city']
            address=request.form['address']
            state=request.form['state']
            country=request.form['country']
            shirtsize=request.form['shirtsize']
            mci_id=request.form['mci']
            food_preference=request.form['food_preference']
            certificate=request.files['certificate']
            council=request.form['council']
            photo=request.files['photo']
            try:
                mydb=conn.get_connection()
                if certificate.filename!='':
                    c_ext=certificate.filename.split('.')[-1]
                    c_data=certificate.read()
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute("update register set c_data=%s,c_ext=%s where id=%s",[c_data,c_ext,eid])
                    mydb.commit()
                    cursor.close()
                if photo.filename!='':
                    p_ext=photo.filename.split('.')[-1]
                    p_data=photo.read()
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute("update register set p_data=%s,p_ext=%s where id=%s",[p_data,p_ext,eid])
                    mydb.commit()
                    cursor.close()

                cursor=mydb.cursor(buffered=True)
                cursor.execute('update register set FirstName=%s,LastName=%s,city=%s,address=%s,state=%s,country=%s,SHIRT_SIZE=%s,mci_id=%s,council=%s where id=%s',[firstname,lastname,city,address,state,country,shirtsize,mci_id,council,session.get('user')])
                mydb.commit()
                cursor.close()
                cursor=mydb.cursor(buffered=True)
                eid=session.get('user')
                cursor.execute("select id,firstname,lastname,email,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,c_data,p_data,p_ext,council from register where id =%s",[eid])
                data=cursor.fetchone()
                cursor.close()
            except Exception as e:
                print(e)
                return {'error':'Please try again later difficulty in fetching data from database'}
            else:
                args={}
                if data[18]!=None:
                    p_ext=data[18]
                    base64_image = base64.b64encode(data[17]).decode('utf-8')
                    args={'p_ext':p_ext,'base64_image':base64_image}
                    flash('Profile updated')
            finally:
                if mydb.is_connected():
                    mydb.close()
        return render_template('edits.html',data=data,**args)
    else:
        return redirect(url_for('login'))


@app.route('/all payments')
def payment_orders():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            eid=session.get('user')
            cursor.execute('select * from payments where id = %s and status="Successfull"',[eid])
            payment = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'error':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('Payments.html',payment = payment)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


@app.route('/individualupdate/<game>',methods=['POST'])
def individual_update(game): 
    if session.get('user'):
        input_value = request.form["inputValue"]
        category=request.form['category']
        # print(category)
        gender=request.form['gender']
        message=check_individual(gender,input_value,game,category)
        response = {'outputValue': message}
        return jsonify(response)
    else:
        return redirect(url_for('login'))


@app.route('/team')
def team():
    if session.get('user'):
        eid=session.get('user')
        a=['BALL BADMINTON','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEYBALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR','BASKET BALL']
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT * FROM sub_games WHERE id=%s",[eid])
            data1 = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'error':'Please try again later difficulty in fetching data from database'}
        else:
            data=[]
            for i in data1:
                if i[0] in a:
                    data.append(i)
            print(data)
            return render_template('teams.html',data=data)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/buyaddon/', methods=['GET', 'POST'])
def buyaddon():
    if session.get('user'):
        selected_games = request.get_json()  # Get the selected games from the request JSON
        total_amount = 0
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)

            for game in selected_games:
                cursor.execute("SELECT amount from games where game_name=%s", [game])
                amount = cursor.fetchone()[0]
                total_amount += amount

            cursor.close()
        except Exception as e:
            print(e)
            return {'error':'Please try again later difficulty in fetching data from database'}
        else:

            eid = session.get('user')  # Assuming eid is already an integer in the session
            game_names = ','.join(selected_games)
            print(game_names)
            return jsonify({
                "eid": eid,
                "game_names": list(game_names),
                "amount": total_amount
            })
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))



'''@app.route('/buyaddons/<game>')
def buyaddons(game):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute("""SELECT COUNT(*) FROM game WHERE id = %s AND game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS')""", (session.get('user'),))
            count4=cursor.fetchone()[0]
            cursor.execute('SELECT gender from register where id=%s',[session.get('user')])
            gender=cursor.fetchone()[0]
            cursor.execute('SELECT count(*) from teams where id=%s and game=%s and status="Accepted"',[session.get('user'),game])
            count5=cursor.fetchone()[0]
            cursor.execute('SELECT count(*) from game where id=%s and game=%s',[session.get('user'),game])
            count6=cursor.fetchone()[0]
            cursor.execute("SELECT count(*) from game where id=%s and game in ('CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET')",[session.get('user')])
            count7=cursor.fetchone()[0]
            cursor.close()

            if count5>0:
                flash('You are already a team member in this game.')
                return redirect(url_for('dashboard'))
            if count7>0:
                cursor=mydb.cursor(buffered=True)
                cursor.execute("select game,amount from game where game in ('CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET')")
                cric_data=cursor.fetchone()
                cursor.close()
                games=['CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET']
                games.remove(cric_data[0])
                if game in games:
                    flash('You are already in a cricket team')
                    return redirect(url_for('dashboard'))
            if gender!='Female':
                if count4>=2:
                    flash('You are already in two teams')
                    return redirect(url_for('dashboard'))
            if gender=='Male' and game in ['KHO KHO','THROW BALL','WOMEN BOX CRICKET']:
                flash(f'{game} can only be played by Female players.')
                return redirect(url_for('dashboard'))
            if gender=='Female' and game in ['FOOTBALL']:
                flash(f'{game} can only be played by Male players.')
                return redirect(url_for('dashboard'))
            
            cursor=mydb.cursor(buffered=True)
            cursor.execute("SELECT amount from games where game_name=%s",[game])
            amount=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return {'error':'Please try again later difficulty in fetching data from database'}
        else:
            return redirect(url_for('addonpayment',eid=session.get('user'),game=game,amount=amount))
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))
@app.route('/addonpayment/<eid>/<game>/<amount>',methods=['GET','POST'])
def addonpayment(eid,game,amount):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, MCI_ID FROM register WHERE id=%s", [eid])
        data1 = cursor.fetchall()
        cursor.execute('SELECT email from register where id=%s',[eid])
        email=cursor.fetchone()[0]
        cursor.execute("select CONCAT(FirstName, ' ', LastName) AS FullName from register where id=%s",[eid])
        name=cursor.fetchone()[0]
        cursor.close()
    except Exception as e:
        print(e)
        return {'error':'Please try again later difficulty in fetching data from database'}
    finally:
        if mydb.is_connected():
            mydb.close()
    # print(payment_url)
    if request.method=='POST':
        ref=random.randint(1000000,99999999)
        game_list = game.split(',')
        amount_per_game = int(amount) / len(game_list)
        #print(url_for('addonsuccess',eid=eid,game=game,_external=True))
        return_url=url_for('addonsuccess',eid=eid,game=game,_external=True)
        eazypay_integration = Eazypay(return_url)
        payment_url=eazypay_integration.get_payment_url(ref,amount,name,email,data1[0][3])
        try:
            mydb=conn.get_connection()
            cursor  = mydb.cursor(buffered=True)
            
            # print("Game Length:", len(game))
            for game in game_list:
                if game in ('ATHLETICS','ARCHERY','BADMINTON','BASKETBALL','BALL BADMINTON','CARROMS','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNIKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS','CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET','VOLLEY BALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG OF WAR'):
                    # print("Game:", game)
                    cursor.execute('insert into payments (ordid, id, game, amount) values (%s, %s, %s, %s)', [ref, eid, game, amount_per_game])

            mydb.commit()
            cursor.close()
        except Exception as e:
            print(e)
            return {'error':'Please try again later difficulty in fetching data from database'}
        else:
            return jsonify({'status':'success','payment_url':payment_url})
        finally:
            if mydb.is_connected():
                mydb.close()
    return render_template('pays.html', data1=data1,game=game,amount=amount,eid=eid,name=name,email=email)
'''

@app.route('/addonsuccess/<eid>/<game>',methods=['POST'])
def addonsuccess(eid,game):
    uid=eid
    response = request.form.to_dict()
    # print(response)
    response_code_value = response.get('Response Code','na')
    # print(response_code_value)
    if response_code_value != 'na':
        if payment_success_exec():
            ref = int(response['ReferenceNo'])
            amount = float(response['Total Amount'])
            transaction_id = int(response['Unique Ref Number'])
            try:
                mydb=conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute('select gender,email from register where id=%s',[uid])
                gender,email=cursor.fetchone()
                cursor.execute('SELECT concat(FirstName," ",LastName) as name from register where id=%s',[uid])
                name=cursor.fetchone()[0]
                cursor.execute('SELECT game FROM payments WHERE ordid = %s', [ref])
                games_list = cursor.fetchall()
                cursor.execute('SELECT count(*) from game where id=%s and game=%s',[eid,game])
                noofgamesinthiscategory=cursor.fetchone()[0]
                amount_per_game = int(amount) / len(games_list)
                for game_record in games_list:
                    game = game_record[0]
                    cursor.execute('UPDATE payments SET status = %s, amount = %s, id = %s, transactionid = %s WHERE ordid = %s AND game = %s', ['Successfull', amount_per_game, uid, transaction_id, ref, game])
                    if noofgamesinthiscategory==0:
                        cursor.execute('INSERT INTO game (id, game, amount) VALUES (%s, %s, %s)', [uid, game, amount_per_game])
                    else:
                        cursor.execute('update game set amount=amount+%s where game=%s and id=%s',[amount,game,eid])
                    if game in ('CHESS', 'ROWING', 'FENCING', 'CYCLOTHON', 'ARCHERY', 'ROLLER SKATING'):
                        category = "Men's singles" if gender == 'Male' else "Women's singles"
                        cursor.execute('INSERT INTO sub_games (game, id, category) VALUES (%s, %s, %s)', [game, uid, category])
                    elif game in ['TABLE TENNIS','LAWN TENNIS','CARROMS','BADMINTON','TENNIKOIT']:
                        category='Womens Single' if gender=='Female' else "Mens Single"
                        cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,uid,category])

                mydb.commit()
                cursor.close()
            except Exception as e:
                print(e)
                return {'error':'Please try again later difficulty in fetching data from database'}
            else:

            
                html = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Registration Confirmation</title>
                    <style>
                        table {{
                            margin: auto;
                        }}
                        img {{
                            margin-left: 30%;
                        }}
                        h1 {{
                            text-align: center;
                        }}
                        table, tr, th, td {{
                            border: 1px solid black;
                            border-collapse: collapse;
                        }}
                        th {{
                            text-align: left;
                        }}
                        td {{
                            width: 60%;
                        }}
                    </style>
                </head>
                <body>
                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%"/>
                    <h1>>Hi {name},<br><br>Thanks for registering to {game} in Doctors Olympiad 2023.<br><br>Your Payment details</h1>
                    <table cellpadding="10">
                        <tr>
                            <th>UNIQUE REFERENCE ID</th>
                            <td>{uid}</td>
                        </tr>
                        <tr>
                            <th>Name</th>
                            <td>{name}</td>
                        </tr>
                        <tr>
                            <th>email</th>
                            <td>{email}</td>
                        </tr>
                        <tr>
                            <th>Game</th>
                            <td>{game}</td>
                        </tr>
                        <tr>
                            <th>Transaction ID</th>
                            <td>{transaction_id}</td>
                        </tr>
                        <tr>
                            <th>Payment</th>
                            <td>{amount}</td>
                        </tr>
                    </table>
                </body>
                </html>
                """
                session['user']=uid
                subject='Registration Successful for Doctors Olympiad 2023'
                mail_with_atc(to=email, subject=subject, html=html)
                
                flash('Payment Successful')
                return redirect(url_for('dashboard'))
            finally:
                if mydb.is_connected():
                    mydb.close()
        else:
            response_msg = get_response_message(response['Response Code'])
            return f"<h1>Transaction failed. Error: {response_msg}</h1>"
    else:
        return "Invalid response received from payment gateway."
 

@app.route('/registeredgame/<game>',methods=['GET','POST'])
def registeredgame(game):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select concat(FirstName," ",LastName),gender from register where id=%s',[session.get('user')])
            fname,gender=cursor.fetchone()
            cursor.execute('select email from register where id=%s',[session.get('user')])
            email_id=cursor.fetchone()[0]
            cursor.close()
            if game in ('ARCHERY','CHESS','CYCLOTHON','ROWING','ROLLER SKATING','FENCING'):
                return redirect(url_for('individual',game=game))
            elif game in ['SHOOTING']:
                cursor = mydb.cursor(buffered=True)
                cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
                count = cursor.fetchone()[0]
                cursor.close()
                args={}
                if count>0:
                    s_category='Mens Air Rifle Singles' if gender=="Male" else 'Womens Air rifle singles'
                    p_category='Mens Air pistol Singles' if gender=="Male" else 'Womens Air pistol singles'

                    cursor = mydb.cursor(buffered=True)
                    cursor.execute('select count(*) from sub_games where game=%s and category= %s and id=%s',[game,s_category,session.get('user')])
                    rifle=cursor.fetchone()[0]
                    cursor.execute('select count(*) from sub_games where game=%s and category=%s and id=%s',[game,p_category,session.get('user')])
                    pistol=cursor.fetchone()[0]
                    cursor.close()
                    if rifle>0:
                        args['rifle']=rifle
                    if pistol>0:
                        args['pistol']=pistol
                print(args)
                    #return redirect(url_for('individual',game=game))
                if request.method=='POST':
                    if len(request.form)==0:
                        return jsonify({'message':'Please select atleast one category'})
                    else:
                        cursor = mydb.cursor(buffered=True)
                        for i in request.form:
                            cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),request.form[i]])
                            mydb.commit()
                        cursor.close()
                        r_games=",".join(request.form.values())
                        # subject='Doctors Olympiad Games registration'
                        # body = f"Hello {fname},\n\nYour registration for the {r_games} in {game} is confirmed.\n\nWe're excited to have you join Doctors Olympiad 2023. If you have any questions, feel free to reach out.\n\nBest regards,\nDoctors Olympiad 2023"
                        # sendmail(email_id,subject,body)

                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Registration Confirmation</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}
                                    
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Registration Confirmation</h1>
                                <p>Dear { fname },</p>
                                <p>We are pleased to confirm your registration for the game <strong>{ game } </strong> in <strong>{ r_games } </strong>Category at Doctors Olympiad 2023.</p>
                                <p>Your participation is greatly appreciated, and we look forward to seeing you at the event.</p>
                                <p>If you have any questions or require further assistance, please do not hesitate to contact us. Our team is here to support you.</p>

                                <p>Best regards,</p>
                                <p>The Doctors Olympiad Team</p>
                            </body>

                            </html>
                        """
        
                        subject = f'Registration Confirmation for the game { game }'

                        # Create a message and send the email
                        #mail_with_atc(to=email_id, subject=subject, html=html)

                        return jsonify({'message':'success','f1':'Registration Success!'})
                return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender,game=game,**args)
            elif game=='SWIMMING':
                cursor = mydb.cursor(buffered=True)
                cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
                count = cursor.fetchone()[0]
                cursor.close()
                if count>=1:
                    return redirect(url_for('individual',game=game))
                if request.method=='POST':
                    print(request.form)
                    s_styles={'Butterfly Stroke','Breaststroke','Backstroke','Freestyle'}
                    b_tracks={'50m Butterfly Stroke','100m Butterfly Stroke','200m Butterfly Stroke'}
                    s_tracks={'50m Breaststroke','100m Breaststroke','200m Breaststroke'}
                    t_tracks= {'50m Backstroke','100m Backstroke','200m Backstroke'}
                    f_tracks={'50m Freestyle','100m Freestyle','200m Freestyle'}

                    styles={i for i in request.form.keys() if i in s_styles}
                    if len(styles)==0:
                        return jsonify({'message':'Select a category'})
                    values=set(request.form.values())
                    form_values=values.difference(s_styles)
                    for i in styles:
                        if i=='Butterfly Stroke':
                            result1=b_tracks.difference(form_values)
                            if len(result1)==3:
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Breaststroke':
                            result2=s_tracks.difference(form_values)
                            if len(result2)==3:
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Freestyle':
                            result3=f_tracks.difference(form_values)
                            if len(result3)==3:
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Backstroke':
                            result4=t_tracks.difference(form_values)
                            if len(result4)==3:
                                return jsonify({'message':'Select atleast one of the sub category'})
                    else:
                        cursor = mydb.cursor(buffered=True)
                        for i in form_values:
                            cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                            mydb.commit()
                        cursor.close()
                        message='success'
                        fi='Registeration Successfull'

                        # subject='Doctors Olympiad Games registration'
                        # body=f'You are successfully registered to {",".join(form_values)}\n\nThanks and regards\nDoctors Olympiad 2023'
                        # sendmail(email_id,subject,body)
                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Registration Confirmation</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}
                                    
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Registration Confirmation</h1>
                                <p>Dear { fname },</p>
                                <p>We are pleased to confirm your registration for the games <strong>{",".join(form_values)} </strong> at Doctors Olympiad 2023.</p>
                                <p>Your participation is greatly appreciated, and we look forward to seeing you at the event.</p>
                                <p>If you have any questions or require further assistance, please do not hesitate to contact us. Our team is here to support you.</p>

                                <p>Best regards,</p>
                                <p>The Doctors Olympiad Team</p>
                            </body>

                            </html>
                        """
        
                        subject = f'Registration Confirmation for the game { game }'

                        # Create a message and send the email
                        mail_with_atc(to=email_id, subject=subject, html=html)
                        return jsonify({'message':message,'fi':fi})
                return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender,game=game)

            elif game=='ATHLETICS':
                cursor = mydb.cursor(buffered=True)
                cursor.execute('select count(*) from sub_games where game=%s and id=%s',[game,session.get('user')])
                count = cursor.fetchone()[0]
                cursor.execute('select gender from register where id=%s',[session.get('user')])
                gender=cursor.fetchone()[0]
                cursor.close()
                if count>=1:
                    return redirect(url_for('individual',game=game))
                if request.method=='POST':
                    a_styles={'Sprint', 'Special Events', 'Walkathon','Marathon','Throw','Jumps'}
                    styles={i for i in request.form.keys() if i in a_styles}
                    values=set(request.form.values())
                    form_values=values.difference(a_styles)
                    s_styles={'100m Sprint','200m Sprint', '400m Sprint', '800m Sprint'}
                    p_styles={'110 m Hurdles', '4 x 100 m Relay','Pole Vault'}
                    d_styles={"Mens 10 km Walkathon","Womens 10 km Walkathon"}
                    f_styles={"Mens 10 km Marathon", "Mens 21 km Marathon","Womens 10 km Marathon", "Womens 21 km Marathon"}
                    t_styles={"Javelin Throw", "Discus Throw", "ShotPut Throw"}
                    j_styles={"Long Jump", "High Jump","Triple Jump"}
                    if len(styles)==0:
                        return jsonify({'message':'Select a category'})
                    for i in styles:
                        if i=='Sprint':
                            result1=s_styles.difference(form_values)
                            if len(result1)==len(s_styles):
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Special Events':
                            result2=p_styles.difference(form_values)
                            if len(result2)==len(p_styles):
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Walkathon':
                            result3=d_styles.difference(form_values)
                            if len(result3)==len(d_styles):
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Marathon':
                            result4=f_styles.difference(form_values)
                            if len(result4)==len(f_styles):
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Jumps':
                            result5=j_styles.difference(form_values)
                            if len(result5)==len(j_styles):
                                return jsonify({'message':'Select atleast one of the sub category'})
                        elif i=='Throw':
                            result6=t_styles.difference(form_values)
                            if len(result6)==len(t_styles):
                                return jsonify({'message':'Select atleast one of the sub category'})
                    else:
                        cursor = mydb.cursor(buffered=True)
                        for i in form_values:
                            cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),i])
                            mydb.commit()
                        cursor.close()
                        message='success'
                        r_games=",".join(form_values)
                        fi='Registeration Successfull'
                        # subject='Doctors Olympiad Games registration'
                        # body = f"Hello {fname},\n\nYour registration for the {r_games} in {game} is confirmed.\n\nWe're excited to have you join Doctors Olympiad 2023. If you have any questions, feel free to reach out.\n\nBest regards,\nDoctors Olympiad 2023"
                        # sendmail(email_id,subject,body)
                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Registration Confirmation</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}
                                    
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Registration Confirmation</h1>
                                <p>Dear { fname },</p>
                                <p>We are pleased to confirm your registration for the game <strong>{ game } </strong> in <strong>{ r_games } </strong>Category at Doctors Olympiad 2023.</p>
                                <p>Your participation is greatly appreciated, and we look forward to seeing you at the event.</p>
                                <p>If you have any questions or require further assistance, please do not hesitate to contact us. Our team is here to support you.</p>

                                <p>Best regards,</p>
                                <p>The Doctors Olympiad Team</p>
                            </body>

                            </html>
                        """
        
                        subject = f'Registration Confirmation for the game { game }'

                        # Create a message and send the email
                        mail_with_atc(to=email_id, subject=subject, html=html)
                        return jsonify({'message':message,'fi':fi})
                return render_template(f'/games-individual-team/Individual/{game}.html',gender=gender,game=game)

            elif game in ('BADMINTON','TABLE TENNIS','LAWN TENNIS','CARROMS','TENNIKOIT'):
                ds="Mens Doubles" if gender=="Male" else "Womens Doubles"
                bs="Mens Single" if gender=="Male" else "Womens Single"
                dic={}
                cursor = mydb.cursor(buffered=True)
                cursor.execute('SELECT CONCAT(FirstName," ",LastName),email FROM register WHERE id=%s',[session.get('user')])
                name,email_id=cursor.fetchone()
                cursor.execute("SELECT count(*) from sub_games where id=%s and  game=%s and category=%s",[session.get('user'),game,bs])
                c=cursor.fetchone()[0]
                if c!=0:
                    dic['c1']=True
                cursor.execute('SELECT count(*) from sub_games where category=%s and game=%s and id=%s',[ds,game,session.get('user')])
                d_count=cursor.fetchone()[0]
                cursor.execute('SELECT count(*) from sub_games where category=%s and game=%s and id=%s',['Mixed Doubles',game,session.get('user')])
                m_count=cursor.fetchone()[0]
                if d_count==0:
                    cursor.execute('Select count(*) from individual_teams where id=%s and game=%s and category=%s and status="Accepted"',[session.get('user'),game,ds])
                    sub_count=cursor.fetchone()[0]
                    if sub_count!=0:
                        cursor.execute('Select teamid from individual_teams where id=%s and game=%s and category=%s and status="Accepted"',[session.get('user'),game,ds])
                        did=cursor.fetchone()[0]
                        cursor.execute('Select id from sub_games where team_number=%s',[did])
                        teid=cursor.fetchone()[0]
                        cursor.execute('SELECT id,concat(FirstName," ",LastName),email from register where id=%s',[teid])
                        deeta=cursor.fetchone()
                        dic['c2']=deeta
                else:
                    cursor.execute('SELECT team_number from sub_games where category=%s and game=%s and id=%s',[ds,game,session.get('user')])
                    tid=cursor.fetchone()[0]
                    cursor.execute("select * from individual_teams where teamid=%s",[tid])
                    deeta2=cursor.fetchone()
                    dic['c3']=deeta2
                if m_count==0:
                    cursor.execute('Select count(*) from individual_teams where id=%s and game=%s and category=%s and status="Accepted"',[session.get('user'),game,'Mixed Doubles'])
                    sub_count=cursor.fetchone()[0]
                    if sub_count!=0:
                        cursor.execute('Select teamid from individual_teams where id=%s and game=%s and category=%s and status="Accepted"',[session.get('user'),game,'Mixed Doubles'])
                        did=cursor.fetchone()[0]
                        cursor.execute('Select id from sub_games where team_number=%s',[did])
                        teid=cursor.fetchone()[0]
                        cursor.execute('SELECT id,concat(FirstName," ",LastName),email from register where id=%s',[teid])
                        deeta11=cursor.fetchone()
                        dic['c4']=deeta11
                else:
                    cursor.execute('SELECT team_number from sub_games where category=%s and game=%s and id=%s',['Mixed Doubles',game,session.get('user')])
                    tid=cursor.fetchone()[0]
                    cursor.execute("select * from individual_teams where teamid=%s",[tid])
                    deeta22=cursor.fetchone()
                    dic['c5']=deeta22
                cursor.close()
                if request.method=='POST':
                    cursor = mydb.cursor(buffered=True)
                    if request.form['input']=='Mens Single' or request.form['input']=='Womens Single':
                        cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,session.get('user'),request.form['input']])
                        mydb.commit()
                        cursor.close()
                        # subject='Doctors Olympiad Games registration'
                        # body=f'Hi {name},\n\nYou are successfully registered to {request.form["input"]} in {game}\n\n\nThanks and regards\nDoctors Olympiad 2023'
                        # sendmail(email_id,subject,body)
                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Registration Confirmation</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}
                                    
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Registration Confirmation</h1>
                                <p>Dear { fname },</p>
                                <p>We are pleased to confirm your registration for the game <strong>{ game } </strong> in <strong>{request.form["input"]} </strong>Category at Doctors Olympiad 2023.</p>
                                <p>Your participation is greatly appreciated, and we look forward to seeing you at the event.</p>
                                <p>If you have any questions or require further assistance, please do not hesitate to contact us. Our team is here to support you.</p>

                                <p>Best regards,</p>
                                <p>The Doctors Olympiad Team</p>
                            </body>

                            </html>
                        """
        
                        subject = f'Registration Confirmation for the { game }'

                        # Create a message and send the email
                        mail_with_atc(to=email_id, subject=subject, html=html)
                        return jsonify({'message':'Registration Success!'})
                    else:
                        category=request.form['category']
                        cursor.execute("SELECT count(*) from sub_games where id=%s and game=%s and category=%s",[session.get('user'),game,category])
                        count1=cursor.fetchone()[0]
                        if count1==0:
                            team_id=genteamid()
                            cursor.execute('INSERT INTO sub_games (game,id,team_number,category) values(%s,%s,%s,%s)',[game,session.get('user'),team_id,category])            
                            mydb.commit()
                        else:
                            cursor.execute('SELECT team_number from sub_games where id=%s and game=%s and category=%s',[session.get('user'),game,category])
                            team_id=cursor.fetchone()[0]
                        if request.form['input'].isdigit():
                            uid=request.form['input']
                            cursor.execute('SELECT concat(FirstName," ",LastName),email,mobileno from register where id=%s',[uid])
                            uname,uemail,umobile=cursor.fetchone()
                            requestid=adotp()
                            cursor.execute("insert into individual_teams (reqid,teamid,id,fullname,email,game,category) values(%s,%s,%s,%s,%s,%s,%s)",[requestid,team_id,uid,uname,uemail,game,category])
                            mydb.commit()
                            cursor.close()
                            one_time_token=token2(team_id,requestid,salt=salt2)
                            link=url_for('individual_accept',token=one_time_token,_external=True)
                            # subject=f'Team Request for {category} in {game} from {name}'
                            # body=f"Hello,{uname}\n\nYou can join my {category} team in {game} by using the below url.\n\n click on this link to join -{link}"
                            # sendmail(uemail,subject=subject,body=body)
                            html = f"""
                                <!DOCTYPE html>
                                <html lang="en">

                                <head>
                                    <meta charset="UTF-8">
                                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                    <title>Invitation to Join Our Doctors Olympiad Team</title>
                                    <style>
                                        body {{
                                            font-family: Arial, sans-serif;
                                            margin: 0 auto;
                                            max-width: 600px;
                                            padding: 20px;
                                            background-color: #f4f4f4;
                                        }}

                                        h1 {{
                                            text-align: center;
                                            color: #333;
                                        }}

                                        p {{
                                            color: #555;
                                        }}

                                        /* Center the image horizontally */
                                        .image-container {{
                                            text-align: center;
                                        }}

                                        /* Left-align the button */
                                        .button-container {{
                                            text-align: left;
                                            margin-top: 20px;
                                        }}

                                        .button {{
                                            display: inline-block;
                                            background-color: #007BFF;
                                            color: #fff;
                                            padding: 10px 20px;
                                            text-decoration: none;
                                            border-radius: 5px;
                                            font-weight: bold; /* Make the button text bold */
                                        }}

                                        .button:hover {{
                                            background-color: #0056b3;
                                        }}
                                        .acc{{
                                            text-decoration: none;
                                            color: white;
                                            font-weight: bold;
                                            font-size: 20px;
                                        }}
                                    </style>
                                </head>

                                <body>
                                    <!-- Replace the image URL below with your Doctors Olympiad image URL -->
                                    <div class="image-container">
                                        <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Doctors Olympiad Image" />
                                    </div>

                                    <h1>Invitation to Join Our Doctors Olympiad Team</h1>
                                    <p>Hello, {uname}</p>
                                    <p>I invite you to join my team for the game {game} in the {category} category at Doctors Olympiad 2023! This is your opportunity to showcase your medical expertise and sportsmanship.</p>
                                    <p>Please click on the link below to accept my invitation and become a part of my team:</p>

                                    <div class="button-container">
                                        <a href="{link}" class="button" style="text-decoration: none;"><span class="acc">Accept Invitation</span></a>
                                    </div>

                                    <p>If you have any questions or need further information, please do not hesitate to contact us.</p>
                                    <p>I look forward to your participation in the Doctors Olympiad 2023!</p>

                                    <p>Best regards,</p>
                                    <p>{name}</p>
                                </body>

                                </html>
                            """
                            
                            subject = f'Individual Request Invitation for the {category} in {game} from {name}'
                            mail_with_atc(to=uemail, subject=subject, html=html)
                            scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
                            credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
                            client = gspread.authorize(credentials)
                            spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
                            worksheet = spreadsheet.get_worksheet(2)
                            deta_str = [f'91{umobile}',uname,f'{game} {category}',link,name]  # Convert all items to strings
                            worksheet.append_row(deta_str)
                            
                            return jsonify({'message':'Invitation Sent!'})
                        else:
                            cursor.execute("SELECT count(*) from register where email=%s",[request.form['input']])
                            count=cursor.fetchone()[0]
                            if count!=0:
                                cursor.execute("SELECT id,concat(FirstName,' ',LastName),email,mobileno from register where email=%s",[request.form['input']])
                                uid,uname,uemail,umobile=cursor.fetchone()
                                requestid=adotp()
                                cursor.execute("insert into individual_teams (reqid,teamid,id,fullname,email,game,category) values(%s,%s,%s,%s,%s,%s,%s)",[requestid,team_id,uid,uname,uemail,game,category])
                                mydb.commit()
                                cursor.close()
                                one_time_token=token2(team_id,requestid,salt=salt2)
                                link=url_for('individual_accept',token=one_time_token,_external=True)
                                # subject=f'Team Request for {category} in {game} from {name}'
                                # body=f"Hello {uname},\n\nYou can join my {category} team in {game} by using the below url.\n\n click on this link to join -{link}"
                                # sendmail(request.form['input'],subject=subject,body=body)
                                html = f"""
                                    <!DOCTYPE html>
                                    <html lang="en">

                                    <head>
                                        <meta charset="UTF-8">
                                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                        <title>Invitation to Join Our Doctors Olympiad Team</title>
                                        <style>
                                            body {{
                                                font-family: Arial, sans-serif;
                                                margin: 0 auto;
                                                max-width: 600px;
                                                padding: 20px;
                                                background-color: #f4f4f4;
                                            }}

                                            h1 {{
                                                text-align: center;
                                                color: #333;
                                            }}

                                            p {{
                                                color: #555;
                                            }}

                                            /* Center the image horizontally */
                                            .image-container {{
                                                text-align: center;
                                            }}

                                            /* Left-align the button */
                                            .button-container {{
                                                text-align: left;
                                                margin-top: 20px;
                                            }}

                                            .button {{
                                                display: inline-block;
                                                background-color: #007BFF;
                                                color: #fff;
                                                padding: 10px 20px;
                                                text-decoration: none;
                                                border-radius: 5px;
                                                font-weight: bold; /* Make the button text bold */
                                            }}

                                            .button:hover {{
                                                background-color: #0056b3;
                                            }}
                                            .acc{{
                                                text-decoration: none;
                                                color: white;
                                                font-weight: bold;
                                                font-size: 20px;
                                            }}
                                        </style>
                                    </head>

                                    <body>
                                        <!-- Replace the image URL below with your Doctors Olympiad image URL -->
                                        <div class="image-container">
                                            <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Doctors Olympiad Image" />
                                        </div>

                                        <h1>Invitation to Join Our Doctors Olympiad Team</h1>
                                        <p>Hello, {uname}</p>
                                        <p>I invite you to join my team for the game {game} in the {category} category at Doctors Olympiad 2023! This is your opportunity to showcase your medical expertise and sportsmanship.</p>
                                        <p>Please click on the link below to accept my invitation and become a part of my team:</p>

                                        <div class="button-container">
                                            <a href="{link}" class="button" style="text-decoration: none;"><span class="acc">Accept Invitation</span></a>
                                        </div>

                                        <p>If you have any questions or need further information, please do not hesitate to contact us.</p>
                                        <p>I look forward to your participation in the Doctors Olympiad 2023!</p>

                                        <p>Best regards,</p>
                                        <p>{name}</p>
                                    </body>

                                    </html>
                                """
                                
                                subject = f'Individual Request Invitation for the {category} in {game} from {name}'

                                # Create a message and send the email
                                mail_with_atc(to=request.form['input'], subject=subject, html=html)
                                scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
                                credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
                                client = gspread.authorize(credentials)
                                spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
                                worksheet = spreadsheet.get_worksheet(2)
                                deta_str = [f'91{umobile}',uname,f'{game} {category}',link,name]  # Convert all items to strings
                                worksheet.append_row(deta_str)
                                return jsonify({'message':'Invitation Sent!'})
                            else:
                                requestid=adotp()
                                cursor.execute("insert into individual_teams (reqid,teamid,email,game,category) values(%s,%s,%s,%s,%s)",[requestid,team_id,request.form['input'],game,category])
                                mydb.commit()
                                cursor.close()
                                one_time_token=token2(team_id,requestid,salt=salt2,email=request.form['input'])
                                link=url_for('individual_accept',token=one_time_token,_external=True)
                                # subject=f'Team Request for {category} in {game} from {name}'
                                # body=f"Hello!,\n\nRegister to Doctors olympiad 2023 and join my {category} team in {game} by using this using the below url.\nPlease click on this link to join -{link}"
                                # sendmail(request.form['input'],subject=subject,body=body)
                                html = f"""
                                    <!DOCTYPE html>
                                    <html lang="en">

                                    <head>
                                        <meta charset="UTF-8">
                                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                        <title>Join My Team</title>
                                        <style>
                                            body {{
                                                font-family: Arial, sans-serif;
                                                margin: 0 auto;
                                                max-width: 600px;
                                                padding: 20px;
                                                background-color: #f4f4f4;
                                            }}

                                            h1 {{
                                                text-align: center;
                                                color: #333;
                                            }}

                                            p {{
                                                color: #555;
                                                font-size: 16px;
                                                margin-bottom: 20px;
                                            }}

                                            .logo {{
                                                text-align: center;
                                            }}

                                            .logo img {{
                                                max-width: 150px;
                                            }}

                                            .button-container {{
                                                margin-top: 20px;
                                            }}

                                            .button {{
                                                display: inline-block;
                                                background-color: #007BFF;
                                                color: #fff;
                                                padding: 10px 20px;
                                                text-decoration: none;
                                                border-radius: 5px;
                                                font-weight: bold;
                                            }}

                                            .button:hover {{
                                                background-color: #0056b3;
                                            }}
                                            .cen {{
                                                text-decoration: none;
                                                color: white;
                                                font-weight: bold;
                                                font-size: 20px;
                                            }}
                                        </style>
                                    </head>

                                    <body>
                                        <div class="logo">
                                            <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" alt="Your Logo" />
                                        </div>

                                        <h1>Join My Team</h1>
                                        <p>Dear Sir/Madam,</p>
                                        <p>I invite you to join my team for the game {game} in the {category} category at Doctors Olympiad 2023! This is your opportunity to showcase your medical expertise and sportsmanship.</p>
                                        <p>Your participation would be greatly appreciated, and we look forward to working together towards success.</p>
                                        
                                        <div class="button-container">
                                            <a href="{ link }" class="button"><span class="cen">Join Now</span></a>
                                        </div>

                                        <p>If you have any questions or require further information, please do not hesitate to reach out. I am here to assist you.</p>

                                        <p>Best regards,</p>
                                        <p>{name}</p>
                                    </body>

                                </html>

                                """
                                
                                subject = f'Individual Request Invitation for the {category} in {game} from {name}!'

                                # Create a message and send the email
                                mail_with_atc(to=request.form['input'], subject=subject, html=html)
                                return jsonify({'message':'Invitation Sent!'})
                return render_template('individualdubles.html',gender=gender,game=game,ds=ds,bs=bs,**dic)

            elif game in ('BALL BADMINTON','BASKETBALL','CRICKET WHITE BALL','FOOTBALL','HARD TENNIS CRICKET','KABADDI','KHO KHO','THROW BALL','TUG OF WAR','VOLLEY BALL','WOMEN BOX CRICKET'):
                cursor=mydb.cursor(buffered=True)
                cursor.execute("SELECT count(*) from sub_games where id=%s and game=%s",[session.get('user'),game])
                count=cursor.fetchone()[0]
                cursor.execute("SELECT concat(Firstname,' ',LastName) from register  where id=%s",[session.get('user')])
                fullname=cursor.fetchone()[0]
                cursor.execute("SELECT team_count from games where game_name=%s",[game])
                amountp=cursor.fetchone()[0]
                if count==0:
                    team_id=genteamid()
                    cursor.execute('INSERT INTO sub_games (game,id,team_number) values(%s,%s,%s)',[game,session.get('user'),team_id])            
                    mydb.commit()
                else:
                    cursor.execute('SELECT team_number from sub_games where id=%s and game=%s',[session.get('user'),game])
                    team_id=cursor.fetchone()[0]
                cursor.execute('SELECT * from teams where teamid=%s',[team_id])
                participants_data=cursor.fetchall()
                cursor.execute('SELECT team_name from sub_games where team_number=%s',[team_id])
                franchise=cursor.fetchone()[0]
                cursor.execute('select sum(addonplayer) from payments where id=%s and addonplayer is not NULL and status!="pending" and game=%s',[session.get('user'),game])
                addonplayers=cursor.fetchone()[0]
                cursor.close()
                args={}
                totalinputs=[]
                p_count=1
                for i in range(0,len(participants_data)):
                    totalinputs.append(f'input{p_count}')
                    args[f'input{p_count}']=participants_data[i]
                    p_count+=1
                addoncount=amountp+(int(addonplayers)) if addonplayers!=None else amountp
                if request.method=='POST':
                    cursor=mydb.cursor(buffered=True)
                    if request.form['input'].isdigit(): 
                        uid=request.form['input']
                        cursor.execute('SELECT count(*) from teams where id=%s and game=%s and teamid=%s',[uid,game,team_id])
                        u_count=cursor.fetchone()[0]
                        if u_count==0 :
                            requestid=adotp()
                            cursor.execute("SELECT email,concat(FirstName,' ',LastName),mobileno from register where id=%s",[uid])
                            r_email,name,umobile=cursor.fetchone()
                            cursor.execute("insert into teams (reqid,teamid,id,fullname,email,game) values(%s,%s,%s,%s,%s,%s)",[requestid,team_id,uid,name,r_email,game])
                            mydb.commit()
                            cursor.close()
                            one_time_token=token2(team_id,requestid,salt=salt2)
                            link=url_for('accept',token=one_time_token,_external=True)
                            # subject=f'Team Request for {game} from {fullname}'
                            # body=f"Hello {name},\n\nYou can join our team by using the below url.\nPlease click on this link to join -{link}"
                            # sendmail(r_email,subject=subject,body=body)
                            html = f"""
                                <!DOCTYPE html>
                                <html lang="en">

                                <head>
                                    <meta charset="UTF-8">
                                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                    <title>Invitation to Join Our Doctors Olympiad Team</title>
                                    <style>
                                        body {{
                                            font-family: Arial, sans-serif;
                                            margin: 0 auto;
                                            max-width: 600px;
                                            padding: 20px;
                                            background-color: #f4f4f4;
                                        }}

                                        h1 {{
                                            text-align: center;
                                            color: #333;
                                        }}

                                        p {{
                                            color: #555;
                                        }}

                                        /* Center the image horizontally */
                                        .image-container {{
                                            text-align: center;
                                        }}

                                        /* Left-align the button */
                                        .button-container {{
                                            text-align: left;
                                            margin-top: 20px;
                                        }}

                                        .button {{
                                            display: inline-block;
                                            background-color: #007BFF;
                                            color: #fff;
                                            padding: 10px 20px;
                                            text-decoration: none;
                                            border-radius: 5px;
                                            font-weight: bold; /* Make the button text bold */
                                        }}

                                        .button:hover {{
                                            background-color: #0056b3;
                                        }}
                                        .acc{{
                                            text-decoration: none;
                                            color: white;
                                            font-weight: bold;
                                            font-size: 20px;
                                        }}
                                    </style>
                                </head>

                                <body>
                                    <!-- Replace the image URL below with your Doctors Olympiad image URL -->
                                    <div class="image-container">
                                        <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Doctors Olympiad Image" />
                                    </div>

                                    <h1>Invitation to Join Our Doctors Olympiad Team</h1>
                                    <p>Hello, {name}</p>
                                    <p>I invite you to join our team for the {game} at Doctors Olympiad 2023! This is your opportunity to showcase your medical expertise and sportsmanship.</p>
                                    <p>Please click on the link below to accept our invitation and become a part of our team:</p>

                                    <div class="button-container">
                                        <a href="{link}" class="button" style="text-decoration: none;"><span class="acc">Accept Invitation</span></a>
                                    </div>

                                    <p>If you have any questions or need further information, please do not hesitate to contact us.</p>
                                    <p>We look forward to your participation in the Doctors Olympiad 2023!</p>

                                    <p>Best regards,</p>
                                    <p>{fullname}</p>
                                </body>

                                </html>
                            """
                            team_name=franchise if franchise !=None else fullname
                            subject = f'Team Request Invitation for the {game} from {team_name}'
                            mail_with_atc(to=r_email, subject=subject, html=html)
                            scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
                            credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
                            client = gspread.authorize(credentials)
                            spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
                            worksheet = spreadsheet.get_worksheet(2)
                            deta_str = [f'91{umobile}',name,game,link,team_name]  # Convert all items to strings
                            worksheet.append_row(deta_str)
                            
                        else:
                            cursor.close()
                            return jsonify({'message':f'{uid} already exist in team'})
                    else:
                        cursor.execute("SELECT count(*) from register where email=%s",[request.form['input']])
                        count=cursor.fetchone()[0]
                        if count!=0:
                            cursor.execute("SELECT id,concat(FirstName,' ',LastName),mobileno from register where email=%s",[request.form['input']])
                            uid,name,umobile=cursor.fetchone()
                            cursor.execute('SELECT count(*) from teams where id=%s and game=%s and teamid=%s',[uid,game,team_id])
                            u_count=cursor.fetchone()[0]
                            if u_count==0 :
                                requestid=adotp()
                                cursor.execute("insert into teams (reqid,teamid,id,fullname,email,game) values(%s,%s,%s,%s,%s,%s)",[requestid,team_id,uid,name,request.form['input'],game])
                                mydb.commit()
                                cursor.close()
                                one_time_token=token2(team_id,requestid,salt=salt2)
                                link=url_for('accept',token=one_time_token,_external=True)
                                # subject=f'Team Request for {game} from {fullname}'
                                # body=f"Hello {name},\n\n You can join our team by using the below url.\nPlease click on this link to join -{link}"
                                # sendmail(request.form['input'],subject=subject,body=body)
                                html = f"""
                                    <!DOCTYPE html>
                                    <html lang="en">

                                    <head>
                                        <meta charset="UTF-8">
                                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                        <title>Invitation to Join Our Doctors Olympiad Team</title>
                                        <style>
                                            body {{
                                                font-family: Arial, sans-serif;
                                                margin: 0 auto;
                                                max-width: 600px;
                                                padding: 20px;
                                                background-color: #f4f4f4;
                                            }}

                                            h1 {{
                                                text-align: center;
                                                color: #333;
                                            }}

                                            p {{
                                                color: #555;
                                            }}

                                            /* Center the image horizontally */
                                            .image-container {{
                                                text-align: center;
                                            }}

                                            /* Left-align the button */
                                            .button-container {{
                                                text-align: left;
                                                margin-top: 20px;
                                            }}

                                            .button {{
                                                display: inline-block;
                                                background-color: #007BFF;
                                                color: #fff;
                                                padding: 10px 20px;
                                                text-decoration: none;
                                                border-radius: 5px;
                                                font-weight: bold; /* Make the button text bold */
                                            }}

                                            .button:hover {{
                                                background-color: #0056b3;
                                            }}
                                            .acc{{
                                                text-decoration: none;
                                                color: white;
                                                font-weight: bold;
                                                font-size: 20px;
                                            }}
                                        </style>
                                    </head>

                                    <body>
                                        <!-- Replace the image URL below with your Doctors Olympiad image URL -->
                                        <div class="image-container">
                                            <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Doctors Olympiad Image" />
                                        </div>

                                        <h1>Invitation to Join Our Doctors Olympiad Team</h1>
                                        <p>Hello, {name}</p>
                                        <p>I invite you to join our team for the {game} at Doctors Olympiad 2023! This is your opportunity to showcase your medical expertise and sportsmanship.</p>
                                        <p>Please click on the link below to accept our invitation and become a part of our team:</p>

                                        <div class="button-container">
                                            <a href="{link}" class="button" style="text-decoration: none;"><span class="acc">Accept Invitation</span></a>
                                        </div>

                                        <p>If you have any questions or need further information, please do not hesitate to contact us.</p>
                                        <p>We look forward to your participation in the Doctors Olympiad 2023!</p>

                                        <p>Best regards,</p>
                                        <p>{fullname}</p>
                                    </body>

                                    </html>
                                """
                                team_name=franchise if franchise !=None else fullname
                                subject = f'Team Request Invitation for the {game} from {team_name}'
                                scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
                                credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
                                client = gspread.authorize(credentials)
                                spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
                                worksheet = spreadsheet.get_worksheet(2)
                                deta_str = [f'91{umobile}',name,game,link,team_name]  # Convert all items to strings
                                worksheet.append_row(deta_str)
                                # Create a message and send the email
                                mail_with_atc(to=request.form['input'], subject=subject, html=html)
                            else:
                                cursor.close()
                                return jsonify({'message':f'{uid} already in team'})
                        else:
                            requestid=adotp()
                            cursor.execute("insert into teams (reqid,teamid,email,game) values(%s,%s,%s,%s)",[requestid,team_id,request.form['input'],game])
                            mydb.commit()
                            cursor.close()
                            one_time_token=token2(team_id,requestid,salt=salt2,email=request.form['input'])
                            link=url_for('accept',token=one_time_token,_external=True)
                            # subject=f'Team Request for {game} from {fullname}'
                            # body=f"Hello!,\n\n Register to doctors olympiad and join our team by using this using the below url.\nPlease click on this link to join -{link}"
                            # sendmail(request.form['input'],subject=subject,body=body)
                            html = f"""
                                    <!DOCTYPE html>
                                    <html lang="en">

                                    <head>
                                        <meta charset="UTF-8">
                                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                        <title>Join My Team</title>
                                        <style>
                                            body {{
                                                font-family: Arial, sans-serif;
                                                margin: 0 auto;
                                                max-width: 600px;
                                                padding: 20px;
                                                background-color: #f4f4f4;
                                            }}

                                            h1 {{
                                                text-align: center;
                                                color: #333;
                                            }}

                                            p {{
                                                color: #555;
                                                font-size: 16px;
                                                margin-bottom: 20px;
                                            }}

                                            .logo {{
                                                text-align: center;
                                            }}

                                            .logo img {{
                                                max-width: 150px;
                                            }}

                                            .button-container {{
                                                margin-top: 20px;
                                            }}

                                            .button {{
                                                display: inline-block;
                                                background-color: #007BFF;
                                                color: #fff;
                                                padding: 10px 20px;
                                                text-decoration: none;
                                                border-radius: 5px;
                                                font-weight: bold;
                                            }}

                                            .button:hover {{
                                                background-color: #0056b3;
                                            }}
                                            .cen {{
                                                text-decoration: none;
                                                color: white;
                                                font-weight: bold;
                                                font-size: 20px;
                                            }}
                                        </style>
                                    </head>

                                    <body>
                                        <div class="logo">
                                            <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" alt="Your Logo" />
                                        </div>

                                        <h1>Join My Team</h1>
                                        <p>Dear Sir/Madam,</p>
                                        <p>I invite you to join our team for the {game} at Doctors Olympiad 2023! This is your opportunity to showcase your medical expertise and sportsmanship.</p>
                                        <p>Your participation would be greatly appreciated, and we look forward to working together towards success.</p>
                                        
                                        <div class="button-container">
                                            <a href="{ link }" class="button"><span class="cen">Join Now</span></a>
                                        </div>

                                        <p>If you have any questions or require further information, please do not hesitate to reach out. I am here to assist you.</p>

                                        <p>Best regards,</p>
                                        <p>{fullname}</p>
                                    </body>

                                </html>

                                """
                                
                            subject = f'Team Request Invitation for the {game} from {fullname}!'

                                # Create a message and send the email
                            mail_with_atc(to=request.form['input'], subject=subject, html=html)
                    
                    return jsonify({'message':'Success','url':url_for('registeredgame',game=game,_external=True)})
                return render_template(f'/games-individual-team/Team/teams.html',gender=gender,game=game,fullname=fullname,count=count,addoncount=addoncount,franchise=franchise,totalinputs=totalinputs,args=args)        
            else:
                abort(404,'Page Not found')
        
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong! Write a mail to "info@doctorsolympiad.com"'}
        
        finally:
            if mydb.is_connected():
                mydb.close()
    
    
    else:
        return redirect(url_for('login'))


@app.route('/addfranchisename/<game>',methods=['POST'])
def addfranchisename(game):
    if session.get('user'):
        try:
            mydb = conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute("SELECT team_name from sub_games where id=%s and game=%s",[session.get('user'),game])
            t_name=cursor.fetchone()[0]
            team_name=request.form['franchise']
            if t_name==None:
                cursor.execute("SELECT team_number from sub_games where id=%s and game=%s",[session.get('user'),game])
                team_id=cursor.fetchone()[0]
                cursor.execute('update  sub_games set team_name=%s where team_number=%s',[team_name,team_id])            
                mydb.commit()
                cursor.close()
                return jsonify({'message':'success'})
            else:
                cursor.execute("SELECT team_number from sub_games where id=%s and game=%s",[session.get('user'),game])
                team_id=cursor.fetchone()[0]
                cursor.execute('update  sub_games set team_name=%s where team_number=%s',[team_name,team_id])            
                mydb.commit()
                cursor.close()
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong! Write a mail to "info@doctorsolympiad.com"'}
        else:
            return jsonify({'message':'updated'})
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))



@app.route('/remove/<rid>/<game>')
def remove(rid,game):
    if session.get('user'):
        eid=session['user']
        try:
            mydb = conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('SELECT status from teams where reqid=%s',[rid])
            status=cursor.fetchone()[0]
            if status=='pending':
                cursor.execute('delete from teams where reqid=%s',[rid])
                mydb.commit()
            else:
                cursor.execute('SELECT id from teams where reqid=%s',[rid])
                uid=cursor.fetchone()[0]
                cursor.execute('SELECT amount from game where game=%s and id=%s',[game,uid])
                amount=cursor.fetchone()[0]
                if amount==0:
                    cursor.execute('delete from teams where reqid=%s',[rid])
                    cursor.execute('delete from game where id=%s and game=%s',[uid,game])
                    mydb.commit()
                else:
                    cursor.execute('delete from teams where reqid=%s',[rid])
                    mydb.commit()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong! Write a mail to "info@doctorsolympiad.com"'}
        else:
            return redirect(url_for('registeredgame',game=game))
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


def check_teams(eid,game,tid,gender):
    cond=True
    message=''
    try:
        mydb = conn.get_connection()
        cursor=mydb.cursor(buffered=True)
        cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[eid,game,'Accepted'])
        count=cursor.fetchone()[0]
        cursor.execute('SELECT id from sub_games where team_number=%s',[tid])
        lead_id=cursor.fetchone()[0]
        cursor.execute('SELECT gender from register where id=%s',[lead_id])
        lead_gender=cursor.fetchone()[0]
        cursor.execute("""
        SELECT COUNT(*)
        FROM game
        WHERE id = %s
        AND game NOT IN (
            'ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 
            'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 
            'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS')""", (eid,))
        count4=cursor.fetchone()[0]
        cursor.execute("SELECT count(*) from sub_games where id=%s and game=%s",[eid,game])
        count3=cursor.fetchone()[0]
        cursor.execute("SELECT count(*) from teams where id=%s and game in ('CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET') and status=%s",[eid,'Accepted'])
        count2=cursor.fetchone()[0]
        cursor.close()
    except Exception as e:
        print(e)
        return {'message': 'Something went wrong! Write a mail to "info@doctorsolympiad.com"'}
    else:
        if lead_gender!=gender:
            cond=False
            message='Cannot add other gender in team'
            return {'cond':cond,'message':message}
        if count>0:
            message='You are already in other team'
            cond=False
            return {'cond':cond,'message':message}
        if gender!='Female':
            if count4>=2:
                if count!=0:
                    cond=False
                    message='You are already in two teams'
                    return {'cond':cond,'message':message}
        if count3!=0:
            message='You are already in other team'
            cond=False
            return {'cond':cond,'message':message}
        if game in ['CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET']:
            if count2!=0:
                message='You are already in other Cricket team'
                cond=False
                return {'cond':cond,'message':message}
        return {'cond':cond,'message':message}
    finally:
        if mydb.is_connected():
            mydb.close()

# @app.route('/registeron/<token>',methods=['GET','POST'])
# def registeron(token):
#     data=link_validator(token)
#     if data=='link expired':
#         flash('link expired!')
#         return render_template('register.html',message='')
#     else:
#         rid=data.get('rid')
#         tid=data.get('teamid')
#         email=data.get('email')
#         if request.method == 'POST':
#             try:
#                 fname = request.form['fname']
#                 lname = request.form['lname']
#                 email = request.form['email']
#                 password = request.form['password']
#                 mobile = request.form['mobile']
#                 age = request.form['age']
#                 gender = request.form['gender']
#                 dob_year = request.form['dob_year']
#                 dob_month=request.form['dob_month']
#                 dob_day=request.form['dob_day']
#                 city = request.form['city']
#                 address = request.form['address']
#                 state = request.form['state']
#                 country = request.form['country']
#                 degree = request.form['degree']
#                 mci = request.form['mci']
#                 game = request.form['game']
#                 shirtsize = request.form['shirtsize']
#                 otp=request.form['otp']
#                 food_preference=request.form['food']
#                 council=request.form['council']
#             except Exception as e:
#                 message="Please fill all the fields"
#                 return jsonify({'message':message})
#             dob=f"{dob_year}-{dob_month}-{dob_day}"
#             try:
#                 mydb = conn.get_connection()
#                 cursor = mydb.cursor(buffered=True)
#                 # cursor.execute('SELECT COUNT(*) FROM register WHERE CONCAT(FirstName, " ", LastName) = %s', [full_name])
#                 # count = cursor.fetchone()[0]
#                 cursor.execute('SELECT COUNT(*) FROM register WHERE Email = %s', [email])
#                 count1 = cursor.fetchone()[0]
#                 cursor.execute('SELECT COUNT(*) FROM register WHERE mobileno = %s', [mobile])
#                 count2 = cursor.fetchone()[0]
#                 cursor.close()
#                 if count2 == 1:
#                     message='Mobile number already exists.'
#                     return jsonify({'message':message})
#                 if count1 == 1:
#                     message='Email already in use'
#                     return jsonify({'message':message})
#                 cond=True if session.get('email') else False
#                 if cond!=True:
#                     message='Please verify your email'
#                     return jsonify({'message':message})
#                 if session['otp']!=otp:
#                     message='Invalid OTP'
#                     return jsonify({'message':message})
#                 if session.get('email')!=request.form['email']:
#                     message='Email address changed verify otp again'
#                     return jsonify({'message':message})

#                 if gender=='Male' and game in ['KHO KHO','THROW BALL','WOMEN BOX CRICKET']:
#                     message=f'{game} can only be played by Female players.'
#                     return jsonify({'message':message})
#                 if gender=='Female' and game in ['FOOTBALL','HARD TENNIS CRICKET','CRICKET WHITE BALL']:
#                     message=f'{game} can only be played by Male players.'
#                     return jsonify({'message':message})
#                 # Get the uploaded certificate and photo files
#                 certificate_file = request.files['certificate']
#                 photo_file = request.files['photo']
#                 c_file_data=certificate_file.read()
#                 p_file_data=photo_file.read()
#                 c_ext=certificate_file.filename.split(".")[-1]
#                 p_ext=photo_file.filename.split(".")[-1]

#                 # Generate unique filenames for certificate and photo using UUID
#                 certificate_filename = f'{mobile}.{certificate_file.filename.split(".")[-1]}'
#                 photo_filename = f'{mobile}.{photo_file.filename.split(".")[-1]}'


                

                
#                 amount=4500 if food_preference=='Yes' else 3500
                
#                 # Hash the password using bcrypt
#                 hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
#                 data = {
#                 'fname': fname, 'lname': lname, 'email': email, 'password': hashed_password, 'mobile': mobile,
#                 'age': age, 'gender': gender, 'dob': dob, 'city': city.lower().strip(), 'address': address.strip(), 'state': state,
#                 'country': country, 'degree': degree, 'mci': mci, 'game': game,
#                 'amount': amount,'shirtsize': shirtsize,
#                 'food_preference':food_preference,'council':council,'c_data':c_file_data,'p_data':p_file_data,
#                 'p_ext':p_ext,'c_ext':c_ext}
#                 cursor=mydb.cursor(buffered=True)
#                 cursor.execute('INSERT INTO temporary(FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', [data['fname'], data['lname'], data['email'], data['password'], data['mobile'], data['age'], data['gender'], data['dob'], data['city'], data['address'], data['state'], data['country'], data['degree'], data['mci'],data['shirtsize'], data['food_preference'],data['council'],data['c_data'],data['c_ext'],data['p_data'],data['p_ext']])
#                 mydb.commit()
#                 cursor.execute('SELECT id FROM temporary WHERE Email = %s AND mobileno = %s ORDER BY id DESC LIMIT 1',[data['email'], data['mobile']])

#                 eid=cursor.fetchall()[-1][0]

#                 #updated code------------------------- --------------------------------
#                 #cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [eid,data['game'],data['amount']])
#                 #print(game)
                
#                 cursor.close()
#             except Exception as e:
#                 print(e)
#                 return {'message':"Something went wrong! Write a mail to 'info@doctorsolympiad.com'"}
#             else:

#                 session.pop('otp')
#                 session.pop('email')
#                 link=url_for('payment_add_on_c',eid=eid,game=data['game'],amount=amount,rid=rid,_external=True)
                
                
#                 return jsonify({'message':'success','link':link})
#             finally:
#                 if mydb.is_connected():
#                     mydb.close()
#         response=make_response(render_template('register_referal.html',rid=rid,email=email,tid=tid,token=token))
#         response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
#         response.headers['Pragma'] = 'no-cache'
#         response.headers['Expires'] = '-1'
#         return response
@app.route('/registeron/<token>',methods=['GET','POST'])
def registeron(token):
    return render_template('suspend.html')
def link_validator(token):
    today_date=datetime.now()
    expiry_date = datetime.strptime('21/11/23 23:59:59', "%d/%m/%y %H:%M:%S")
    d=int((expiry_date-today_date).total_seconds())
    try:
        serializer = URLSafeTimedSerializer(secret_key)
        data = serializer.loads(token, salt=salt2, max_age=d)
    except Exception as e:
        return 'link expired'
    else:
        return data
                    
@app.route('/checkout-addon-payc/<eid>/<game>/<amount>/<rid>', methods=['GET', 'POST'])
def payment_add_on_c(eid,game,amount,rid):
    try:
        mydb = conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, MCI_ID FROM temporary WHERE id=%s", [eid])
        data1 = cursor.fetchall()
        cursor.execute('SELECT email from temporary where id=%s',[eid])
        email=cursor.fetchone()[0]
        cursor.execute("select CONCAT(FirstName, ' ', LastName) AS FullName from temporary where id=%s",[eid])
        name=cursor.fetchone()[0]
        cursor.close()
    except Exception as e:
        print(e)
        return {'message': 'Something went wrong! Write a mail to "info@doctorsolympiad.com"'}
    finally:
        if mydb.is_connected():
            mydb.close()
    if request.method=='POST':
        ref=random.randint(1000000,99999999)
        eazypay_integration = Eazypay(url_for('success_c',rid=rid,_external=True))
        payment_url=eazypay_integration.get_payment_url(ref,amount,name,email,data1[0][3])
        try:
            mydb=conn.get_connection()
            cursor  = mydb.cursor(buffered=True)
            cursor.execute('insert into payments (ordid,id,game,amount) values(%s,%s,%s,%s)',[ref,eid,game,amount])
            mydb.commit()
            cursor.close()
        except Exception as e:
            print(e)
            return jsonify({'status':'failed','message':'Please try again later difficulty in fetching data from database'})
        else:
            return jsonify({'status':'success','payment_url':payment_url})
        finally:
            if mydb.is_connected():
                mydb.close()
    return render_template('pt.html', data1=data1,game=game,amount=amount,eid=eid,name=name,email=email,rid=rid)


@app.route('/success_c/<rid>',methods=['POST'])
def success_c(rid):
    response = request.form.to_dict()
    response_code_value = response.get('Response Code','na')
    if response_code_value != 'na':
        if payment_success_exec():
            ref = int(response['ReferenceNo'])
            amount = float(response['Total Amount'])
            transaction_id = int(response['Unique Ref Number'])
            date=str(response['Transaction Date'])
            try:
                mydb = conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game from payments where ordid=%s',[ref])
                eid,game=cursor.fetchone()
                #cursor.execute('SELECT status from register WHERE id=%s', [eid])
                #status=cursor.fetchone()[0]
                cursor.execute('select gender,email,mobileno from temporary where id=%s',[eid])
                gender,email,mobile=cursor.fetchone()
                cursor.execute('insert into register (FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext) select FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext from temporary where id=%s',[eid])
                mydb.commit()
                cursor.execute('SELECT id from register where email=%s',[email])
                uid=cursor.fetchone()[0]
                cursor.execute('SELECT concat(FirstName," ",LastName) as name from register where email=%s',[email])
                name=cursor.fetchone()[0]
                cursor.execute('UPDATE  payments SET status=%s,amount=%s,id=%s,transactionid=%s WHERE ordid=%s',['Successfull',amount,uid,transaction_id,ref])
                cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [uid,game,amount])
                cursor.execute('DELETE FROM temporary where id=%s or email=%s or mobileno=%s',[eid,email,mobile])
                mydb.commit()
                cursor.execute('SELECT count(*) from teams where reqid=%s',[rid])
                t_count=cursor.fetchone()[0]
                cursor.execute('SELECT count(*) from individual_teams where reqid=%s',[rid])
                i_count=cursor.fetchone()[0]
                message=''
                if t_count!=0:
                    cursor.execute("UPDATE teams SET id=%s,fullname=%s,email=%s where reqid=%s",[uid,name,email,rid])
                    mydb.commit()
                elif i_count!=0:
                    cursor.execute("UPDATE individual_teams SET id=%s, fullname=%s,email=%s where reqid=%s",[uid,name,email,rid])
                    mydb.commit()
                
                cursor.execute('select ID,CONCAT(FirstName," ",LastName),Email,concat("91","",mobileno) AS mobile,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council from register where id=%s',[uid])
                deta=cursor.fetchone()+(game,)
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':"Something went wrong! Write a mail to 'info@doctorsolympiad.com'"}
            else:

                session['user']=uid
                scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
                credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
                client = gspread.authorize(credentials)
                spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
                worksheet = spreadsheet.get_worksheet(0)
                deta_str = [str(item) for item in deta]  # Convert all items to strings
                worksheet.append_row(deta_str)
                html = f"""
                <!DOCTYPE html>
                <html lang="en">

                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Registration Confirmation</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            margin: 0 auto;
                            max-width: 600px;
                            padding: 20px;
                            background-color: rgba(206,238,255,0.5);
                        }}

                        h1 {{
                            text-align: center;
                        }}

                        img {{
                            display: block;
                            margin: 0 auto;
                            max-width: 100%;
                        }}

                        table {{
                            width: 100%;
                            border-collapse: collapse;
                            margin-top: 20px;
                        }}

                        th,
                        td {{
                            border: 1px solid black;
                            padding: 10px;
                            text-align: left;
                        }}

                        th {{
                            background-color: #f2f2f2;
                        }}

                        ul {{
                            list-style-type: none;
                            padding: 0;
                        }}

                        ul li {{
                            margin-bottom: 10px;
                        }}
                    </style>
                </head>

                <body>
                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" />
                    <h1>Welcome to Doctors Olympiad 2023</h1>
                    <p>Dear {name},</p>
                    <p>Greetings from the IMA National Sports Meet: Doctors Olympiad 2023 team! We are thrilled to have received your
                        registration for this exciting event. Get ready to showcase your sportsmanship and camaraderie on the field!</p>

                    <h2>Registration Details:</h2>
                    <table>
                        <tr>
                            <th>Event:</th>
                            <td>IMA National Sports Meet: Doctors Olympiad 2023</td>
                        </tr>
                        <tr>
                            <th>Participant's Name:</th>
                            <td>{name}</td>
                        </tr>
                        <tr>
                            <th>Registered Game:</th>
                            <td>{game}</td>
                        </tr>
                        <tr>
                            <th>Registration Date:</th>
                            <td>{date}</td>
                        </tr>
                        <tr>
                            <th>Unique ID:</th>
                            <td>{uid}</td>
                        </tr>
                        <tr>
                            <th>Transaction ID</th>
                            <td>{transaction_id}</td>
                        </tr>
                        <tr>
                            <th>Amount</th>
                            <td>&#8377; {amount} /-</td>
                        </tr>
                    </table>

                    <p>Your enthusiasm and commitment to joining us for this event are truly appreciated. We can't wait to see you in
                        action, competing in {game} and being part of this fantastic celebration of sports and
                        unity within the medical community.</p>

                  <!--  <h2>Event Details:</h2>
                    <table>
                        <tr>
                            <th>Date:</th>
                            <td>22nd November 2023</td>
                        </tr>
                        <tr>
                            <th>Time:</th>
                            <td>2 PM Onwards Tentative</td>
                        </tr>
                        <tr>
                            <th>Venue:</th>
                            <td>DOCTORS SPORTS ACADEMY GROUNDS</td>
                        </tr>
                    </table> -->

                    <p>Stay tuned for forthcoming updates and crucial information as we approach the event date. Furthermore, please make it a point to regularly check both your email and WhatsApp for important notices and updates.
                        Should you have any questions or require assistance, feel free to reach out to our dedicated team at <a href="mailto:info@doctorsolympiad.com"
                            style="text-decoration: none;">info@doctorsolympiad.com</a>
                or <a href="tel:9759434567"
                        style="text-decoration: none;">9759434567</a>.</p>

                    <p>Once again, thank you for registering for the IMA National Sports Meet: Doctors Olympiad 2023. Your participation
                        contributes to the success of this event and the spirit of camaraderie among medical professionals.</p>

                    <p>Warm regards,</p>
                    <p>Doctors Olympiad 2023<br><a href="mailto:info@doctorsolympiad.com"
                        style="text-decoration: none;">info@doctorsolympiad.com</a><br><a href="tel:9759434567" style="text-decoration: none;">9759434567</a></p>

                </body>

                </html>
                """
                subject='Registration Successful for Doctors Olympiad 2023'
                mail_with_atc(to=email, subject=subject, html=html)
                
                # subject = 'Payment Successful! From Doctors Olympiad 2023'
                # mail_with_atc(email,subject,html)
                # subject='Registration Successful for Doctors Olympiad 2023'
                # body=f'Hi {name},\n\nThanks for registering to {game} in Doctors Olympiad 2023\n\n\n\nunique reference id:{uid}\nName: {name}\ndef accept game: {game}\nTransaction id: {transaction_id}\n\n\n\n\nThanks and Regards\nDoctors Olympiad 2023\n\n\nContact:+91 9759634567'
                # mail_with_atc(to=email, subject=subject, html=html)
                
                flash('Payment Successful'+message)
                return redirect(url_for('dashboard'))
                # print(response)
                # Payment is successful
                # return render_template('thank-you.html')
            finally:
                if mydb.is_connected():
                    mydb.close()
        else:
            # Payment failed, show failure message
            response_msg = get_response_message(response['Response Code'])
            print(response_msg)
            return f"<h1>Transaction failed. Error: {response_msg}</h1>"
    else:
        # 'Response_Code' key is missing in the response
        return "Invalid response received from payment gateway."



def update_teams(input_value,game,add_gender):
    if input_value.isdigit():
        try:
            mydb = conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from register where id=%s',[input_value])
            data=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            message='Please try again later difficulty in fetching data from database'
            return message
        finally:
            if mydb.is_connected():
                mydb.close()
        if data==0:
            cond=False
            message="Id not found"
            return message
        
        else:
            cond=True
            try:
                mydb = conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[input_value,game,'Accepted'])
                count=cursor.fetchone()[0]
                cursor.execute('SELECT gender from register where id=%s',[input_value])
                gend=cursor.fetchone()[0]
                cursor.execute("""SELECT COUNT(*) FROM game WHERE id = %s AND game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS')""", (input_value,))
                count4=cursor.fetchone()[0]
                cursor.execute("SELECT count(*) from sub_games where id=%s and game=%s",[input_value,game])
                count3=cursor.fetchone()[0]
                cursor.execute("SELECT count(*) from teams where id=%s and game in ('CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET') and status=%s",[input_value,'Accepted'])
                count2=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                message='Please try again later difficulty in fetching data from database'
                return message
            else:
                if int(input_value)==session.get('user'):
                    cond=False
                    message='You cannot add yourself.'
                    return message
                if gend!=add_gender:
                    cond=False
                    message='User Gender does not match'
                    return message
                if count>0:
                    cond=False
                    message='User registered to other team'
                    return message
                if gend!='Female':
                    if count4>=2:
                        if count!=0:
                            cond=False
                            message='User already in two teams'
                            return message
                if count3!=0:
                    cond=False
                    message='User registered to other team'
                    return message
                if game in ['CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET']:
                    if count2!=0:
                        cond=False
                        message='User registered to other cricket team'
                        return message
                if cond==True:
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute("SELECT concat_ws(' ',FirstName,LastName)  from register where id=%s",[input_value])
                    message=cursor.fetchone()[0]
                    cursor.close()
                    return message
            finally:
                if mydb.is_connected():
                    mydb.close()
        
    else:
        try:
            mydb = conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from register where email=%s',[input_value])
            data=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            message='Please try again later difficulty in fetching data from database'
            return message
        finally:
            if mydb.is_connected():
                mydb.close()
        if data==0:
            message="User not found with this email id"
            return message
        
        else:
            cond=True
            try:
                mydb = conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id from register where Email=%s',[input_value])
                eid=cursor.fetchone()[0]
                cursor.execute('SELECT gender from register where id=%s',[eid])
                gend=cursor.fetchone()[0]
                cursor.execute("SELECT count(*) from teams where id=%s and game=%s and status=%s",[eid,game,'Accepted'])
                count=cursor.fetchone()[0]
                cursor.execute("""SELECT COUNT(*) FROM game WHERE id = %s AND game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS')""", (eid,))
                count4=cursor.fetchone()[0]
                cursor.execute("SELECT count(*) from sub_games where id=%s and game=%s",[eid,game])
                count3=cursor.fetchone()[0]
                cursor.execute("SELECT count(*) from teams where id=%s and game in ('CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET') and status=%s",[eid,'Accepted'])
                count2=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                message='Please try again later difficulty in fetching data from database'
                return message
            else:
                if eid ==session.get('user'):
                    cond=False
                    message='You cannot add yourself.'
                    return message
                if gend!=add_gender:
                    cond=False
                    message='User Gender does not match'
                    return message
                if count>0:
                    cond=False
                    message='User registered to other team'
                    return message
                if count4>=2:
                    cond=False
                    message='User already in two teams'
                    return message
                if count3!=0:
                    cond=False
                    message='User registered to other team'
                    return message
                if game in ['CRICKET WHITE BALL','HARD TENNIS CRICKET','WOMEN BOX CRICKET']:
                    if count2!=0:
                        cond=False
                        message='User registered to other cricket team'
                        return message
                if cond==True:
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute("SELECT concat_ws(' ',FirstName,LastName)  from register where id=%s",[eid])
                    message=cursor.fetchone()[0]
                    cursor.close()
                    return message
            finally:
                if mydb.is_connected():
                    mydb.close()
                
@app.route('/acceptrequest/<token>')
def accept(token):
    data=link_validator(token)
    print(type(data))
    print(data)
    if data=='link expired':
         return '<h1>Link Expired</h1>'
    else:
        if data.get('email','NA')=='NA':
            rid=data.get('rid')
            tid=data.get('teamid')
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT count(*) from teams where reqid=%s',[rid])
                t_count=cursor.fetchone()[0]
                cursor.close()
                if t_count==0:
                    flash('Team request revoked by Captain..Contact Other lead')
                    return redirect(url_for('dashboard'))
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game,status from teams where reqid=%s',[rid])
                eid,game,status=cursor.fetchone()
                cursor.execute('SELECT id from sub_games where team_number=%s',[tid])
                leadid=cursor.fetchone()[0]
                cursor.execute('SELECT email,concat(FirstName," ",LastName) from register where id=%s',[leadid])
                email,name=cursor.fetchone()
                cursor.execute('SELECT concat(FirstName," ",LastName),gender from register where id=%s',[eid])
                participant,gender=cursor.fetchone()
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            finally:
                if mydb.is_connected():
                    mydb.close()
            if status=='Accepted':
                flash('Request already Accepted!')
                return redirect(url_for('dashboard'))
            else:
                criteria=check_teams(eid,game,tid,gender)
                if criteria['cond']:
                    try:
                        mydb=conn.get_connection()
                        cursor=mydb.cursor(buffered=True)
                        cursor.execute("SELECT concat(FirstName,' ',LastName),email from register where id=%s",[eid])
                        full_name,user_email=cursor.fetchone()
                        cursor.execute('update teams set fullname=%s,email=%s,status="Accepted" where reqid=%s',[full_name,user_email,rid])
                        mydb.commit()
                        cursor.execute('select count(*) from game where id=%s and game=%s',[eid,game])
                        count=cursor.fetchone()[0]
                        if count==0:
                            cursor.execute('insert into game(id,game,amount) values(%s,%s,%s)',[eid,game,0])
                            mydb.commit()
                        cursor.close()
                    except Exception as e:
                        print(e)
                        return {'message':'Please try again later difficulty in fetching data from database'}
                    else:

                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Team Request Accepted</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                        font-size: 16px;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}

                                    .button-container {{
                                        
                                        margin-top: 20px;
                                    }}

                                    .button {{
                                        display: inline-block;
                                        background-color: #007BFF;
                                        color: #fff;
                                        padding: 10px 20px;
                                        text-decoration: none;
                                        border-radius: 5px;
                                        font-weight: bold;
                                    }}

                                    .button:hover {{
                                        background-color: #0056b3;
                                    }}
                                    .cen {{
                                        text-decoration: none;
                                        color: white;
                                        font-weight: bold;
                                        font-size: 20px;
                                    }}
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Team Request Accepted</h1>
                                <p>Hi { name },</p>
                                <p>{ participant } has just accepted your team request for the <strong>{ game }</strong>.</p>
                                <p>You can now view the status of your team and other details in your dashboard.</p>
                                
                                <div class="button-container">
                                    <a href="{url_for('dashboard',_external=True)}" class="button"><span class="cen">Go to Dashboard</span></a>
                                </div>

                                <p>If you have any questions or need assistance, please feel free to contact us. We're here to help!</p>

                                <p>Best regards,</p>
                                <p>Doctors Olympiad 2023</p>
                            </body>

                            </html>

                        """

                        subject = f'{participant} has just Accepted your Team Request for the game { game }'

                        # Create a message and send the email
                        mail_with_atc(to=email, subject=subject, html=html)
                        flash('Request Accepted')
                        return redirect(url_for('dashboard'))
                    finally:
                        if mydb.is_connected():
                            mydb.close()
                else:
                    flash(f"{criteria['message']}")
                    return redirect(url_for('dashboard'))
        else:
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                email=data.get('email')
                cursor.execute('SELECT count(*) from register where email=%s',[email])
                e_count=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            else:    
                if e_count==0:
                    return redirect(url_for('registeron',token=token))
                else:
                    flash('Already Registered!')
                    return redirect(url_for('login'))
            finally:
                if mydb.is_connected():
                    mydb.close()

@app.route('/update/<game>', methods=['POST'])
def update(game):
    if session.get('user'):
        input_value = request.form['inputValue']
        add_gender=request.form['gender']
        message=update_teams(input_value,game,add_gender)
        # Here, you can perform any necessary processing with the input data.
        # For simplicity, we'll just return the input value as the response.
        response = {'outputValue': message}
        return jsonify(response)
    else:
        return redirect(url_for('login'))


@app.route('/request')
def send_request():
    return render_template('requests.html')

@app.route('/ir')
def ir():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            eid = session.get('user')
            cursor.execute("select f.reqid,g.team_number,f.game,f.category,concat(r.firstname,' ',lastname) as requested_by,f.status from individual_teams as f inner join sub_games as g on g.team_number=f.teamid inner join register as r on r.id=g.id where f.id=%s", [eid])
            data = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('ir.html', data=data)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/tr')
def tr():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            eid=session.get('user')
            cursor.execute("select f.reqid,g.team_number,f.game,concat(r.firstname,' ',lastname) as requested_by,f.status from teams as f inner join sub_games as g on g.team_number=f.teamid inner join register as r on r.id=g.id where f.id=%s",[eid])
            data = cursor.fetchall()
            # print(data)
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('tr.html',data=data)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))
@app.route('/invitations')
def invitations():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            eid=session.get('user')
            cursor.execute("SELECT * FROM teams WHERE id=%s",[eid])
            data = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('teaminvitations.html',data=data)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/individual_accept/<token>')
def individual_accept(token):
    data=link_validator(token)
    if data=='link expired':
        return '<h1>Link Expired</h1>'
    else:
        if data.get('email','NA')=='NA':
            rid=data.get('rid')
            tid=data.get('teamid')
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT count(*) from individual_teams where reqid=%s',[rid])
                i_count=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            finally:
                if mydb.is_connected():
                    mydb.close()
            if i_count==0:
                flash('Team request revoked by co-player')
                return redirect(url_for('dashboard'))
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game,status,category,teamid from individual_teams where reqid=%s',[rid])
                eid,game,status,category,tid=cursor.fetchone()
                cursor.execute('SELECT count(*) from game where id=%s and game=%s',[eid,game])
                add_p=cursor.fetchone()[0]
                cursor.execute('SELECT id from sub_games where team_number=%s',[tid])
                leadid=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            finally:
                if mydb.is_connected():
                    mydb.close()
            if status=='Accepted':
                flash("Request already Accepted")
                return redirect(url_for('dashboard'))
            criteria=individual_doubles_check_t(eid,game,category,leadid)
            if not criteria['cond']:
                flash(criteria['message'])
                return redirect(url_for('dashboard'))
            if add_p!=0:
                try:
                    mydb=conn.get_connection()
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute('SELECT id from sub_games where team_number=%s',[tid])
                    leadid=cursor.fetchone()[0]
                    cursor.execute('SELECT email,concat(FirstName," ",LastName) from register where id=%s',[leadid])
                    email,name=cursor.fetchone()
                    cursor.execute('SELECT concat(FirstName," ",LastName) from register where id=%s',[eid])
                    participant=cursor.fetchone()[0]
                    cursor.execute('SELECT count(*) from individual_teams where reqid=%s',[rid])
                    i_count=cursor.fetchone()[0]
                    cursor.close()
                except Exception as e:
                    print(e)
                    return {'message':'Please try again later difficulty in fetching data from database'}
                finally:
                    if mydb.is_connected():
                        mydb.close()
                if i_count!=0:
                    try:
                        mydb=conn.get_connection()
                        cursor=mydb.cursor(buffered=True)
                        cursor.execute("UPDATE individual_teams SET status='Accepted' where reqid=%s",[rid])
                        mydb.commit()
                        cursor.close()
                    except Exception as e:
                        print(e)
                        return {'message':'Please try again later difficulty in fetching data from database'}
                    else:
                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Team Request Accepted</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                        font-size: 16px;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}

                                    .button-container {{
                                        
                                        margin-top: 20px;
                                    }}

                                    .button {{
                                        display: inline-block;
                                        background-color: #007BFF;
                                        color: #fff;
                                        padding: 10px 20px;
                                        text-decoration: none;
                                        border-radius: 5px;
                                        font-weight: bold;
                                    }}

                                    .button:hover {{
                                        background-color: #0056b3;
                                    }}
                                    .cen {{
                                        text-decoration: none;
                                        color: white;
                                        font-weight: bold;
                                        font-size: 20px;
                                    }}
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Team Request Accepted</h1>
                                <p>Hi { name },</p>
                                <p>{ participant } has just accepted your team request for the game <strong>{ game }</strong> Category <strong>{category}</strong>.</p>
                                <p>You can now view the status of your team and other details in your dashboard.</p>
                                
                                <div class="button-container">
                                    <a href="{url_for('dashboard',_external=True)}" class="button"><span class="cen">Go to Dashboard</span></a>
                                </div>

                                <p>If you have any questions or need assistance, please feel free to contact us. We're here to help!</p>

                                <p>Best regards,</p>
                                <p>Doctors olympiad 2023.</p>
                            </body>

                            </html>

                        """
                        
                        subject = f'{participant} has just Accepted your Individual Request for the game { game } Category {category}'

                        # Create a message and send the email
                        mail_with_atc(to=email, subject=subject, html=html)
                        flash('Request Accepted')
                        return(redirect(url_for('dashboard')))
                    finally:
                        if mydb.is_connected():
                            mydb.close()
                else:
                    flash('Team request revoked by the co player')
                    return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('addondoubles',rid=rid,eid=eid,game=game))
        else:
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                email=data.get('email')
                cursor.execute('SELECT count(*) from register where email=%s',[email])
                e_count=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            else:
                if e_count==0:
                    return redirect(url_for('registeron',token=token))
                else:
                    flash('Already Registered!')
                    return redirect(url_for('login'))
            finally:
                if mydb.is_connected():
                    mydb.close()

@app.route('/i_accept/<rid>')
def i_accept(rid):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('SELECT count(*) from individual_teams where reqid=%s',[rid])
            i_count=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        finally:
            if mydb.is_connected():
                mydb.close()

        if i_count==0:
            flash('Team request revoked by co-player')
            return redirect(url_for('ir'))
        else:
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game,status,category,teamid from individual_teams where reqid=%s',[rid])
                eid,game,status,category,tid=cursor.fetchone()
                cursor.execute('SELECT count(*) from game where id=%s and game=%s',[eid,game])
                add_p=cursor.fetchone()[0]
                cursor.execute('SELECT id from sub_games where team_number=%s',[tid])
                leadid=cursor.fetchone()[0]
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            finally:
                if mydb.is_connected():
                    mydb.close()
            if status=='Accepted':
                flash("Request already Accepted")
                return redirect(url_for('dashboard'))
            criteria=individual_doubles_check_t(eid,game,category,leadid)
            if not criteria['cond']:
                flash(criteria['message'])
                return redirect(url_for('dashboard'))
            if add_p!=0:
                try:
                    mydb=conn.get_connection()
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute('SELECT id from sub_games where team_number=%s',[tid])
                    leadid=cursor.fetchone()[0]
                    cursor.execute('SELECT email,concat(FirstName," ",LastName) from register where id=%s',[leadid])
                    email,name=cursor.fetchone()
                    cursor.execute('SELECT concat(FirstName," ",LastName) from register where id=%s',[eid])
                    participant=cursor.fetchone()[0]
                    cursor.execute('SELECT count(*) from individual_teams where reqid=%s',[rid])
                    i_count=cursor.fetchone()[0]
                    cursor.close()
                except Exception as e:
                    print(e)
                    return {'message':'Please try again later difficulty in fetching data from database'}
                finally:
                    if mydb.is_connected():
                        mydb.close()
                if i_count!=0:
                    try:
                        mydb=conn.get_connection()
                        cursor=mydb.cursor(buffered=True)
                        cursor.execute("UPDATE individual_teams SET status='Accepted' where reqid=%s",[rid])
                        mydb.commit()
                        cursor.close()
                    except Exception as e:
                        print(e)
                        return {'message':'Please try again later difficulty in fetching data from database'}
                    else:

                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Team Request Accepted</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                        font-size: 16px;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}

                                    .button-container {{
                                        
                                        margin-top: 20px;
                                    }}

                                    .button {{
                                        display: inline-block;
                                        background-color: #007BFF;
                                        color: #fff;
                                        padding: 10px 20px;
                                        text-decoration: none;
                                        border-radius: 5px;
                                        font-weight: bold;
                                    }}

                                    .button:hover {{
                                        background-color: #0056b3;
                                    }}
                                    .cen {{
                                        text-decoration: none;
                                        color: white;
                                        font-weight: bold;
                                        font-size: 20px;
                                    }}
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Team Request Accepted</h1>
                                <p>Hi { name },</p>
                                <p>{ participant } has just accepted your team request for the game <strong>{ game }</strong> Category <strong>{category}</strong>.</p>
                                <p>You can now view the status of your team and other details in your dashboard.</p>
                                
                                <div class="button-container">
                                    <a href="{url_for('dashboard',_external=True)}" class="button"><span class="cen">Go to Dashboard</span></a>
                                </div>

                                <p>If you have any questions or need assistance, please feel free to contact us. We're here to help!</p>

                                <p>Best regards,</p>
                                <p>Doctors olympiad 2023.</p>
                            </body>

                            </html>

                        """
                        
                        subject = f'{participant} has just Accepted your Individual Request for the game { game } Category {category}'

                        # Create a message and send the email
                        mail_with_atc(to=email, subject=subject, html=html)
                        flash('Request Accepted')

                        return(redirect(url_for('ir')))
                    finally:
                        if mydb.is_connected():
                            mydb.close()
                else:
                    flash('Team request revoked by the co player')
                    return redirect(url_for('ir'))
            else:
                return redirect(url_for('addondoubles',rid=rid,eid=eid,game=game))
    else:
        return redirect(url_for('login'))

@app.route('/t_accept/<rid>')
def t_accept(rid):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('SELECT count(*) from teams where reqid=%s',[rid])
            i_count=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        finally:
            if mydb.is_connected():
                mydb.close()

        if i_count==0:
            flash('Team request revoked by Captain')
            return redirect(url_for('tr'))
        else:
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game,status,teamid from teams where reqid=%s',[rid])
                eid,game,status,tid=cursor.fetchone()
                cursor.execute('SELECT id from sub_games where team_number=%s',[tid])
                leadid=cursor.fetchone()[0]
                cursor.execute('SELECT email,concat(FirstName," ",LastName) from register where id=%s',[leadid])
                email,name=cursor.fetchone()
                cursor.execute('SELECT concat(FirstName," ",LastName),gender from register where id=%s',[eid])
                participant,gender=cursor.fetchone()
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            finally:
                if mydb.is_connected():
                    mydb.close()
            if status=='Accepted':
                flash('Request already Accepted!')
                return redirect(url_for('dashboard'))
            else:
                criteria=check_teams(eid,game,tid,gender)
                if criteria['cond']:
                    try:
                        mydb=conn.get_connection()
                        cursor=mydb.cursor(buffered=True)
                        cursor.execute("SELECT concat(FirstName,' ',LastName),email from register where id=%s",[eid])
                        full_name,user_email=cursor.fetchone()
                        cursor.execute('update teams set fullname=%s,email=%s,status="Accepted" where reqid=%s',[full_name,user_email,rid])
                        mydb.commit()
                        cursor.execute('select count(*) from game where id=%s and game=%s',[eid,game])
                        count=cursor.fetchone()[0]
                        if count==0:
                            cursor.execute('insert into game(id,game,amount) values(%s,%s,%s)',[eid,game,0])
                            mydb.commit()
                        cursor.close()
                    except Exception as e:
                        print(e)
                        return {'message':'Please try again later difficulty in fetching data from database'}
                    else:
                        html = f"""
                            <!DOCTYPE html>
                            <html lang="en">

                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Team Request Accepted</title>
                                <style>
                                    body {{
                                        font-family: Arial, sans-serif;
                                        margin: 0 auto;
                                        max-width: 600px;
                                        padding: 20px;
                                        background-color: #f4f4f4;
                                    }}

                                    h1 {{
                                        text-align: center;
                                        color: #333;
                                    }}

                                    p {{
                                        color: #555;
                                        font-size: 16px;
                                    }}

                                    .logo {{
                                        text-align: center;
                                        margin-bottom: 20px;
                                    }}

                                    .logo img {{
                                        max-width: 150px;
                                    }}

                                    .button-container {{
                                        
                                        margin-top: 20px;
                                    }}

                                    .button {{
                                        display: inline-block;
                                        background-color: #007BFF;
                                        color: #fff;
                                        padding: 10px 20px;
                                        text-decoration: none;
                                        border-radius: 5px;
                                        font-weight: bold;
                                    }}

                                    .button:hover {{
                                        background-color: #0056b3;
                                    }}
                                    .cen {{
                                        text-decoration: none;
                                        color: white;
                                        font-weight: bold;
                                        font-size: 20px;
                                    }}
                                </style>
                            </head>

                            <body>
                                <div class="logo">
                                <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" alt="Password Reset Image" />

                                </div>

                                <h1>Team Request Accepted</h1>
                                <p>Hi { name },</p>
                                <p>{ participant } has just accepted your team request for the <strong>{ game }</strong>.</p>
                                <p>You can now view the status of your team and other details in your dashboard.</p>
                                
                                <div class="button-container">
                                    <a href="{url_for('dashboard',_external=True)}" class="button"><span class="cen">Go to Dashboard</span></a>
                                </div>

                                <p>If you have any questions or need assistance, please feel free to contact us. We're here to help!</p>

                                <p>Best regards,</p>
                                <p>Doctors Olympiad 2023</p>
                            </body>

                            </html>

                        """

                        subject = f'{participant} has just Accepted your Team Request for the game { game }'

                        mail_with_atc(to=email, subject=subject, html=html)
                        flash('Request Accepted')
                        return redirect(url_for('tr'))
                    finally:
                        if mydb.is_connected():
                            mydb.close()
                else:
                    flash(f"{criteria['message']}")
                    return redirect(url_for('tr'))
    else:
        return redirect(url_for('login'))

@app.route('/addondoubles/<rid>/<eid>/<game>',methods=['GET','POST'])
def addondoubles(rid,eid,game):
    try:
        mydb = conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo, MCI_ID FROM register WHERE id=%s", [eid])
        data1 = cursor.fetchall()
        amount=1500
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    finally:
        if mydb.is_connected():
            mydb.close()
    if request.method=='POST':
        ref=random.randint(1000000,99999999)
        eazypay_integration = Eazypay(url_for('addondoublessuccess',eid=eid,game=game,rid=rid,_external=True))
        payment_url=eazypay_integration.get_payment_url(ref,amount,data1[0][1],data1[0][2],data1[0][3])
        try:
            mydb = conn.get_connection()
            cursor  = mydb.cursor(buffered=True)
            cursor.execute('select count(*) from games where game_name=%s',[game])
            cursor.execute('insert into payments (ordid,id,game,amount) values(%s,%s,%s,%s)',[ref,eid,game,amount])
            mydb.commit()
            cursor.close()
        except Exception as e:
            print(e)
            return {'status':'Please try again later difficulty in fetching data from database'}
        else:
            return jsonify({'status':'success','payment_url':payment_url})
        finally:
            if mydb.is_connected():
                mydb.close()
    return render_template('addondoubles.html', data1=data1,game=game,amount=amount,eid=eid,name=data1[0][1],email=data1[0][2],rid=rid)
    
@app.route('/addondoublessuccess/<rid>/<eid>/<game>',methods=['POST'])
def addondoublessuccess(rid,eid,game):
    response = request.form.to_dict()
    response_code_value = response.get('Response Code','na')
    if response_code_value != 'na':
        if payment_success_exec():
            uid=eid
            ref = int(response['ReferenceNo'])
            amount = float(response['Total Amount'])
            transaction_id = int(response['Unique Ref Number'])
            try:
                mydb = conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute('SELECT concat(FirstName," ",LastName) as name,email from register where id=%s',[uid])
                name,email=cursor.fetchone()
                cursor.execute('UPDATE  payments SET status=%s,amount=%s,id=%s,transactionid=%s WHERE ordid=%s',['Successfull',amount,uid,transaction_id,ref])
                cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [uid,game,amount])
                mydb.commit()
                cursor.execute('SELECT count(*) from individual_teams where reqid=%s',[rid])
                i_count=cursor.fetchone()[0]
                message=''
                if i_count!=0:
                    cursor.execute("UPDATE individual_teams SET status='Accepted' where reqid=%s",[rid])
                    mydb.commit()
                else:
                    message='Request Removed by co player'
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            else:
                html = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Registration Confirmation</title>
                    <style>
                        table {{
                            margin: auto;
                        }}
                        img {{
                            margin-left: 30%;
                        }}
                        h1 {{
                            text-align: center;
                        }}
                        table, tr, th, td {{
                            border: 1px solid black;
                            border-collapse: collapse;
                        }}
                        th {{
                            text-align: left;
                        }}
                        td {{
                            width: 60%;
                        }}
                    </style>
                </head>
                <body>
                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%"/>
                    <h1>Hi {name},<br><br>Thanks for registering to {game} in Doctors Olympiad 2023.<br><br>Your Payment details</h1>
                    <table cellpadding="10">
                        <tr>
                            <th>UNIQUE REFERENCE ID</th>
                            <td>{uid}</td>
                        </tr>
                        <tr>
                            <th>Name</th>
                            <td>{name}</td>
                        </tr>
                        <tr>
                            <th>email</th>
                            <td>{email}</td>
                        </tr>
                        <tr>
                            <th>Game</th>
                            <td>{game}</td>
                        </tr>
                        <tr>
                            <th>Transaction ID</th>
                            <td>{transaction_id}</td>
                        </tr>
                        <tr>
                            <th>Payment</th>
                            <td>{amount}</td>
                        </tr>
                    </table>
                </body>
                </html>
                """
                session['user']=uid
                # subject = 'Payment Successful! From Doctors Olympiad 2023'
                # mail_with_atc(email,subject,html)
                subject='Registration Successful for Doctors Olympiad 2023'
                # body=f'Hi {name},\n\nThanks for registering to {game} in Doctors Olympiad 2023\n\n\n\nunique reference id:{uid}\nName: {name}\ndef accept game: {game}\nTransaction id: {transaction_id}\n\n\n\n\nThanks and Regards\nDoctors Olympiad 2023\n\n\nContact:+91 9759634567'
                mail_with_atc(to=email, subject=subject, html=html)
                
                flash('Payment Successful'+message)
                return redirect(url_for('dashboard'))
                # print(response)
                # Payment is successful
                # return render_template('thank-you.html')
            finally:
                if mydb.is_connected():
                    mydb.close()
        else:
            # Payment failed, show failure message
            response_msg = get_response_message(response['Response Code'])
            return f"<h1>Transaction failed. Error: {response_msg}</h1>"
    else:
        # 'Response_Code' key is missing in the response
        return "Invalid response received from payment gateway."

@app.route('/removeindividual/<tid>/<game>')
def removeindividual(tid,game):
    if session.get('user'):
        eid=session['user']
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('delete from individual_teams where teamid=%s',[tid])
            cursor.execute('delete from sub_games where team_number=%s',[tid])
            mydb.commit()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return redirect(url_for('registeredgame',game=game))
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

def individual_doubles_check_t(eid,game,category,lid):
    cond=True
    try:
        mydb=conn.get_connection()
        cursor=mydb.cursor(buffered=True)
        cursor.execute("SELECT count(*) from individual_teams where id=%s and game=%s and category =%s and status=%s",[eid,game,category,'Accepted'])
        count=cursor.fetchone()[0]
        cursor.execute("select count(*) from sub_games where id=%s and game=%s and category=%s",[eid,game,category])
        count2=cursor.fetchone()[0]
        cursor.execute("SELECT gender from register where id=%s",[eid])
        check_gender=cursor.fetchone()[0]
        cursor.execute('SELECT age from register  where id=%s',[eid])
        age=cursor.fetchone()[0]
        cursor.execute('SELECT age,gender from register where id=%s',[lid])
        lead_age,gender=cursor.fetchone()
        cursor.close()
    except Exception as e:
        print(e)
        return {'cond':cond,'message':'Please try again later difficulty in fetching data from database'}
    else:
        if count>0:
            cond=False
            message='You are already in other team'
            return {'cond':cond,'message':message}
        
        if count2>0:
            cond=False
            message='You are already in other team'
            return {'cond':cond,'message':message}
        if category!="Mixed Doubles":
            if check_gender!=gender:
                cond=False
                message='Cannot add other gender in team'
                return {'cond':cond,'message':message}
        if category=="Mixed Doubles":
            if check_gender==gender:
                cond=False
                message='Cannot add same gender in team'
                return {'cond':cond,'message':message}
        if game in ('CARROMS','TENNIKOIT'):
            if age>=50:
                if lead_age<50:
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
            if age<50:
                if lead_age>50:
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
        if game == 'BADMINTON':
            if age<35:
                if lead_age>35:
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
            elif age>=35 and age<=45:
                if not (lead_age>=35 and lead_age<=45):
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
            elif age>=46 and age<=55:
                if not (lead_age>=46 and lead_age<=55):
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
            elif age>55:
                if lead_age<55:
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
        
        if game  == 'LAWN TENNIS':
            if category!="Mixed Doubles":
                if age<35:
                    if lead_age>35:
                        cond=False
                        message="You doesn't belong to co player age group"
                        return {'cond':cond,'message':message}
                elif age>=35 and age<=45:
                    if not (lead_age>=35 and lead_age<=45):
                        cond=False
                        message="You doesn't belong to co player age group"
                        return {'cond':cond,'message':message}
                elif age>=46 and age<=55:
                    if not (lead_age>=46 and lead_age<=55):
                        cond=False
                        message="You doesn't belong to co player age group"
                        return {'cond':cond,'message':message}
                elif age>55:
                    if lead_age<55:
                        cond=False
                        message="You doesn't belong to co player age group"
                        return {'cond':cond,'message':message}

        
        if game =='TABLE TENNIS':
            if age<=39:
                if lead_age>=40:
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
            elif age>=40 and age<=54:
                if not (lead_age>=40 and lead_age<=54):
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
            elif age>=55:
                if lead_age<55:
                    cond=False
                    message="You doesn't belong to co player age group"
                    return {'cond':cond,'message':message}
    finally:
        if mydb.is_connected():
            mydb.close()
    if cond==True:
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute("SELECT concat_ws(' ',FirstName,LastName) as fullname from register where id=%s",[eid])
            message=cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return {'cond':cond,'message':'Please try again later difficulty in fetching data from database'}
        else:
            return {'cond':cond,'message':message}
        finally:
            if mydb.is_connected():
                mydb.close()


        
@app.route('/admin')
def admin():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select count(*) from register where id not in (231000,231003,231014,231006,231037)')
            users = cursor.fetchone()[0]
            cursor.execute('select sum(amount) from payments where status="Successfull" and id not in (231003,231014,231006,231037)')
            pay = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM game where game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and amount>2000")
            games = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM game where game not in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and (amount>=5000 or amount is NULL)")
            teams1 = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM game where game not in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and (amount between 1 and 4999)")
            individual_teams=cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM game where game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and amount<2000")
            ind_games = cursor.fetchone()[0]
            #graphs data
            cursor.execute("select state,count(state) from register where id  not in (231000,231003,231014,231006,231037) group by state")
            State = cursor.fetchall()
            #return result
            cursor.execute("SELECT g.game,count(g.game) FROM register AS r INNER JOIN (SELECT id, MIN(sno) AS min_sno FROM game GROUP BY id) AS subquery ON r.id = subquery.id INNER JOIN game AS g ON r.id = g.id AND subquery.min_sno = g.sno where r.id not in (231003,231014,231006,231037) group by g.game")
            Game = cursor.fetchall()
            cursor.execute("select game,count(game) from game where game IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and  amount>2000 group by game")
            indiv=cursor.fetchall()
            cursor.execute("select game,count(game) from game where game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and  (amount between 1 and 4999) group by game")
            teams=cursor.fetchall()
            cursor.execute("select game,count(game) from game where game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and (amount>=5000 or amount is NULL)  group by game")
            frans=cursor.fetchall()
            cursor.execute("select date_format(date,'%M') as month,sum(amount) as total from payments where status!='pending' and id not in (231003,231014,231006,231037) group by month")
            pays=cursor.fetchall()
            cursor.execute("SELECT game,COUNT(game) FROM game where game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and id not in (231003,231014,231006,231037) and amount<2000 group by game")
            add_indi=cursor.fetchall()
            cursor.execute('select count(r.id) from register as r inner join payments as p on r.id=p.id where p.status="Successfull" and p.transactionid is NOT NULL')
            online_payments=str(cursor.fetchone()[0])
            cursor.execute('select count(r.id) from register as r inner join payments as p on r.id=p.id where p.status="Successfull" and p.transactionid is  NULL')
            offline_payments=str(cursor.fetchone()[0])
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        finally:
            if mydb.is_connected():
                mydb.close()
        states=[]
        count=[]
        for s in State:
            states.append(s[0])
            count.append(str(s[1]))
        states=",".join(states)
        count=",".join(count)
        #All games data
        game =[]
        cnt =[]
        for g in Game:
            game.append(g[0])
            cnt.append(str(g[1]))
        game=','.join(game)
        cnt=','.join(cnt)

        #individual games Data
        ind=[]
        ct=[]
        for i in indiv:
            ind.append(i[0])
            ct.append(str(i[1]))
        ind=",".join(ind)
        ct=",".join(ct)
        #Team Games data
        team=[]
        cut=[]
        for t in teams:
            team.append(t[0])
            cut.append(str(t[1]))
        team=",".join(team)
        cut=",".join(cut)
        #print(team,cut)
        #for franchase games
        fran=[]
        ctn=[]
        for f in frans:
            fran.append(f[0])
            ctn.append(str(f[1]))
        fran=",".join(fran)
        ctn=",".join(ctn)
        # for payments graph
        payy=[]
        cunt=[]
        for p in pays:
            payy.append(p[0])
            cunt.append(str(p[1]))
        payy=",".join(payy)
        cunt=",".join(cunt)
        #for add_on_individuals
        ad_ind=[]
        ad_cnt=[]
        for a in add_indi:
            ad_ind.append(a[0])
            ad_cnt.append(str(a[1]))
        ad_ind=",".join(ad_ind)
        ad_cnt=",".join(ad_cnt)
        return render_template('admin.html',users=users,pay=pay,games=games,teams1=teams1,teams=teams,individual_teams=individual_teams,ind_games=ind_games,states=states,count=count,game=game,cnt=cnt,ind=ind,ct=ct,team=team,cut=cut,fran=fran,ctn=ctn,payy=payy,cunt=cunt,ad_ind=ad_ind,ad_cnt=ad_cnt,online_payments=online_payments,offline_payments=offline_payments)
    else:
        return redirect(url_for('login'))

@app.route('/CGS')
def CGA():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT game, COUNT(game) FROM game WHERE game  IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS','CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and game.id not in (231000,231003,231014,231006,231037) GROUP BY game")
            indvdual=cursor.fetchall()
            cursor.execute("SELECT game,SUM(amount) AS total FROM game WHERE game  IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS','CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and game.id not in (231003,231014,231006,231037,231000) GROUP BY game")
            amount=cursor.fetchall()
            cursor.execute("SELECT game, COUNT(*) AS count FROM game WHERE game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS','CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and game.id not in (231000,231003,231014,231006,231037) and (amount>=5000 or amount is NULL) GROUP BY game")
            Teams=cursor.fetchall()
            cursor.execute("SELECT game,sum(amount) AS count FROM game WHERE game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS','CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and game.id not in (231000,231003,231014,231006,231037) GROUP BY game")
            TeamAmt=cursor.fetchall()
            #return Teams
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}            
        finally:
            if mydb.is_connected():
                mydb.close()
        inds=[]
        cnt=[]
        for g in indvdual:
            inds.append(g[0])
            cnt.append(str(g[1]))
        inds=','.join(inds)
        cnt=','.join(cnt)
        indAmt=[]
        cut=[]
        for i in amount:
            indAmt.append(i[0])
            cut.append(str(i[1]))
        indAmt=','.join(indAmt)
        cut=','.join(cut)
        tms=[]
        ctn=[]
        for t in Teams:
            tms.append(t[0])
            ctn.append(str(t[1]))
        tms=','.join(tms)
        ctn=','.join(ctn)
        Tamt=[]
        cunt=[]
        for a in TeamAmt:
            Tamt.append(a[0])
            cunt.append(str(a[1]))
        Tamt=','.join(Tamt)
        cunt=','.join(cunt)
        #return Tamt
        return render_template('graph.html',inds=inds,cnt=cnt,indAmt=indAmt,cut=cut,tms=tms,ctn=ctn,Tamt=Tamt,cunt=cunt)
    else:
        return redirect(url_for('login'))
@app.route('/payments')
def payments():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select p.ordid,p.id,concat(r.FirstName," ",r.LastName),r.mobileno,r.email,p.game,p.amount,p.transactionid,p.date from payments as p inner join register as r on r.id=p.id where p.status!="pending" and p.id not in (231003,231014,231006,231037)  order by date desc')
            payment = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            
            return render_template('a-payment.html',payment = payment,desicion='Yes')
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/getallgamedata/<game>')
def getallgamedata(game):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        doubles=['TABLE TENNIS','LAWN TENNIS','CARROMS','BADMINTON','TENNIKOIT']
        d_columns = ['player1 id', 'player1 Name','player1 Email','player1 Mobile No','player1 Age','player1 Gender','player1 Shirt Size','player1 MCI ID','player1 State','player1 City','player1 food preference','Category','player2 id', 'player2 Name','player2 Email','player2 Mobile No','player2 Age','player2 Gender','player2 Shirt Size','player2 MCI ID','player2 State','player2 City','player2 food preference','status']
        s_columns= ['Id', 'Name','Email','Mobile No','Age','Gender','Shirt Size','MCI ID','State','City','food preference','Category'] 
        if game in doubles:
            if game in ['BADMINTON','LAWN TENNIS']:
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<35", (game,'Mens Doubles'))
                below_35_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<35", (game,'Mixed Doubles'))
                below_35_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<35", (game,'Womens Doubles'))
                below_35_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<35" , (game,'Mens Single'))
                below_35_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age<35", (game,'Womens Single'))
                below_35_women_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 35 and 45", (game,'Mens Doubles'))
                between_35_45_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 35 and 45", (game,'Mixed Doubles'))
                between_35_45_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 35 and 45", (game,'Womens Doubles'))
                between_35_45_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 35 and 45" , (game,'Mens Single'))
                between_35_45_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age between 35 and 45", (game,'Womens Single'))
                between_35_45_women_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 46 and 55", (game,'Mens Doubles'))
                between_46_55_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 46 and 55", (game,'Mixed Doubles'))
                between_46_55_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 46 and 55", (game,'Womens Doubles'))
                between_46_55_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 46 and 55" , (game,'Mens Single'))
                between_46_55_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age between 46 and 55", (game,'Womens Single'))
                between_46_55_women_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>55", (game,'Mens Doubles'))
                above_55_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>55", (game,'Mixed Doubles'))
                above_55_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>55", (game,'Womens Doubles'))
                above_55_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>55" , (game,'Mens Single'))
                above_55_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age>55", (game,'Womens Single'))
                above_55_women_singles=cursor.fetchall()
            elif game=='CARROMS':
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=50", (game,'Mens Doubles'))
                above_50_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=50", (game,'Mixed Doubles'))
                above_50_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=50", (game,'Womens Doubles'))
                above_50_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=50" , (game,'Mens Single'))
                above_50_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age>=50", (game,'Womens Single'))
                above_50_women_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<50", (game,'Mens Doubles'))
                below_50_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<50", (game,'Mixed Doubles'))
                below_50_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<50", (game,'Womens Doubles'))
                below_50_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<50" , (game,'Mens Single'))
                below_50_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age<50", (game,'Womens Single'))
                below_50_women_singles=cursor.fetchall()
            elif game=='TENNIKOIT':
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=50", (game,'Womens Doubles'))
                above_50_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age>=50", (game,'Womens Single'))
                above_50_women_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<50", (game,'Womens Doubles'))
                below_50_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age<50", (game,'Womens Single'))
                below_50_women_singles=cursor.fetchall()
            elif game =='TABLE TENNIS':
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<=39", (game,'Mens Doubles'))
                beloweq_39_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<=39", (game,'Mixed Doubles'))
                beloweq_39_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<=39", (game,'Womens Doubles'))
                beloweq_39_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age<=39" , (game,'Mens Single'))
                beloweq_39_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age<=39", (game,'Womens Single'))
                beloweq_39_women_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 40 and 54", (game,'Mens Doubles'))
                between_40_54_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 40 and 54", (game,'Mixed Doubles'))
                between_40_54_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 40 and 54", (game,'Womens Doubles'))
                between_40_54_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age between 40 and 54" , (game,'Mens Single'))
                between_40_54_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age between 40 and 54", (game,'Womens Single'))
                between_40_54_women_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=55", (game,'Mens Doubles'))
                above_55_mens_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=55", (game,'Mixed Doubles'))
                above_55_mixed_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category, s.id, s.fullname,k.mobileno,s.email,k.age,k.gender,k.SHIRT_SIZE,k.MCI_ID,k.state,k.city,k.food_preference, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=55", (game,'Womens Doubles'))
                above_55_women_doubles = cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and r.age>=55" , (game,'Mens Single'))
                above_55_mens_singles=cursor.fetchall()
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games t INNER JOIN register r ON r.ID = t.id where t.game=%s and  t.category=%s and t.id not in (231003,231014,231006,231037) and  r.age>=55", (game,'Womens Single'))
                above_55_women_singles=cursor.fetchall()
        elif game in ['SWIMMING',"ATHLETICS"]:
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age<35 and r.gender='Male'", [game])
            m_below_35 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age<35 and r.gender!='Male'", [game])
            f_below_35 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age between 35 and 45 and r.gender='Male'", [game])
            m_between_35_and_45 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age between 35 and 45 and r.gender!='Male'", [game])
            f_between_35_and_45 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age between 46 and 55 and r.gender='Male'", [game])
            m_between_46_and_55 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age between 46 and 55 and r.gender!='Male'", [game])
            f_between_46_and_55 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age>55 and r.gender!='Male'", [game])
            f_above_55 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age>55 and r.gender='Male'", [game])
            m_above_55 = cursor.fetchall()
        else:
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age>=50 and r.gender='Male'", [game])
            m_above_equal_50 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age<50 and r.gender='Male'", [game])
            m_below_50 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age>=50 and r.gender!='Male'", [game])
            f_above_equal_50 = cursor.fetchall()
            cursor.execute("SELECT r.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, r.gender,r.SHIRT_SIZE,r.MCI_ID,r.state,r.city,r.food_preference,t.category FROM sub_games as t INNER JOIN register r ON r.ID = t.id  where t.game=%s and t.id not in (231003,231014,231006,231037) and r.age<50 and r.gender!='Male'", [game])
            f_below_50 = cursor.fetchall()
            
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:
        print(game)
        if game in ['BADMINTON','LAWN TENNIS']:
            below_35_mens_doubles = pd.DataFrame(below_35_mens_doubles, columns=d_columns)
            below_35_mixed_doubles = pd.DataFrame(below_35_mixed_doubles, columns=d_columns)
            below_35_women_doubles = pd.DataFrame(below_35_women_doubles, columns=d_columns)
            below_35_mens_singles = pd.DataFrame(below_35_mens_singles, columns=s_columns)
            below_35_women_singles = pd.DataFrame(below_35_women_singles, columns=s_columns)

            between_35_45_mens_doubles = pd.DataFrame(between_35_45_mens_doubles, columns=d_columns)
            between_35_45_mixed_doubles = pd.DataFrame(between_35_45_mixed_doubles, columns=d_columns)
            between_35_45_women_doubles = pd.DataFrame(between_35_45_women_doubles, columns=d_columns)
            between_35_45_mens_singles = pd.DataFrame(between_35_45_mens_singles, columns=s_columns)
            between_35_45_women_singles = pd.DataFrame(between_35_45_women_singles, columns=s_columns)

            between_46_55_mens_doubles = pd.DataFrame(between_46_55_mens_doubles, columns=d_columns)
            between_46_55_mixed_doubles = pd.DataFrame(between_46_55_mixed_doubles, columns=d_columns)
            between_46_55_women_doubles = pd.DataFrame(between_46_55_women_doubles, columns=d_columns)
            between_46_55_mens_singles = pd.DataFrame(between_46_55_mens_singles, columns=s_columns)
            between_46_55_women_singles = pd.DataFrame(between_46_55_women_singles, columns=s_columns)

            above_55_mens_doubles = pd.DataFrame(above_55_mens_doubles, columns=d_columns)
            above_55_mixed_doubles = pd.DataFrame(above_55_mixed_doubles, columns=d_columns)
            above_55_women_doubles = pd.DataFrame(above_55_women_doubles, columns=d_columns)
            above_55_mens_singles = pd.DataFrame(above_55_mens_singles, columns=s_columns)
            above_55_women_singles = pd.DataFrame(above_55_women_singles, columns=s_columns)
            datasets = [[('Below 35', below_35_mens_doubles, 'Mens Doubles'),
                        ('Below 35', below_35_mixed_doubles, 'Mixed Doubles'),
                        ('Below 35', below_35_women_doubles, 'Women Doubles'),
                        ('Below 35', below_35_mens_singles, 'Mens Singles'),
                        ('Below 35', below_35_women_singles, 'Women Singles')],
                        [('Between 35 to 45', between_35_45_mens_doubles, 'Mens Doubles'),
                        ('Between 35 to 45', between_35_45_mixed_doubles, 'Mixed Doubles'),
                        ('Between 35 to 45', between_35_45_women_doubles, 'Women Doubles'),
                        ('Between 35 to 45', between_35_45_mens_singles, 'Mens Singles'),
                        ('Between 35 to 45', between_35_45_women_singles, 'Women Singles')],
                        [('Between 46 to 55', between_46_55_mens_doubles, 'Mens Doubles'),
                        ('Between 46 to 55', between_46_55_mixed_doubles, 'Mixed Doubles'),
                        ('Between 46 to 55', between_46_55_women_doubles, 'Women Doubles'),
                        ('Between 46 to 55', between_46_55_mens_singles, 'Mens Singles'),
                        ('Between 46 to 55', between_46_55_women_singles, 'Women Singles')],
                        [('Above 55', above_55_mens_doubles, 'Mens Doubles'),
                        ('Above 55', above_55_mixed_doubles, 'Mixed Doubles'),
                        ('Above 55', above_55_women_doubles, 'Women Doubles'),
                        ('Above 55', above_55_mens_singles, 'Mens Singles'),
                        ('Above 55', above_55_women_singles, 'Women Singles')]]
            zip_output = io.BytesIO()
            with zipfile.ZipFile(zip_output, 'w') as zip_file:
                for datasets_list in datasets:
                    for dataset_name, dataset, sheet_name in datasets_list:
                        excel_output = io.BytesIO()
                        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
                            dataset.to_excel(writer, sheet_name=sheet_name, index=True, columns=None)
                        excel_output.seek(0)
                        zip_file.writestr(f'{game}_{dataset_name}_{sheet_name}.xlsx', excel_output.getvalue())

            zip_output.seek(0)

        
            return send_file(zip_output,download_name=f'{game}_workbooks.zip',as_attachment=True,mimetype='application/zip')
        elif game=='TABLE TENNIS':
            beloweq_39_mixed_doubles = pd.DataFrame(beloweq_39_mixed_doubles, columns=d_columns)
            beloweq_39_women_doubles = pd.DataFrame(beloweq_39_women_doubles, columns=d_columns)
            beloweq_39_mens_singles = pd.DataFrame(beloweq_39_mens_singles, columns=s_columns)
            beloweq_39_women_singles = pd.DataFrame(beloweq_39_women_singles, columns=s_columns)
            beloweq_39_mens_doubles = pd.DataFrame(beloweq_39_mens_doubles, columns=d_columns)

            between_40_54_mens_doubles = pd.DataFrame(between_40_54_mens_doubles, columns=d_columns)
            between_40_54_mixed_doubles = pd.DataFrame(between_40_54_mixed_doubles, columns=d_columns)
            between_40_54_women_doubles = pd.DataFrame(between_40_54_women_doubles, columns=d_columns)
            between_40_54_mens_singles = pd.DataFrame(between_40_54_mens_singles, columns=s_columns)
            between_40_54_women_singles = pd.DataFrame(between_40_54_women_singles, columns=s_columns)

            above_55_mens_doubles = pd.DataFrame(above_55_mens_doubles, columns=d_columns)
            above_55_mixed_doubles = pd.DataFrame(above_55_mixed_doubles, columns=d_columns)
            above_55_women_doubles = pd.DataFrame(above_55_women_doubles, columns=d_columns)
            above_55_mens_singles = pd.DataFrame(above_55_mens_singles, columns=s_columns)
            above_55_women_singles = pd.DataFrame(above_55_women_singles, columns=s_columns)
            datasets = [[('Below 39', beloweq_39_mens_doubles, 'Mens Doubles'),
                        ('Below 39', beloweq_39_mixed_doubles, 'Mixed Doubles'),
                        ('Below 39', beloweq_39_women_doubles, 'Women Doubles'),
                        ('Below 39', beloweq_39_mens_singles, 'Mens Singles'),
                        ('Below 39', beloweq_39_women_singles, 'Women Singles')],
                        [('Between 40 to 54', between_40_54_mens_doubles, 'Mens Doubles'),
                        ('Between 40 to 54', between_40_54_mixed_doubles, 'Mixed Doubles'),
                        ('Between 40 to 54', between_40_54_women_doubles, 'Women Doubles'),
                        ('Between 40 to 54', between_40_54_mens_singles, 'Mens Singles'),
                        ('Between 40 to 54', between_40_54_women_singles, 'Women Singles')],
                        [('Above 55', above_55_mens_doubles, 'Mens Doubles'),
                        ('Above 55', above_55_mixed_doubles, 'Mixed Doubles'),
                        ('Above 55', above_55_women_doubles, 'Women Doubles'),
                        ('Above 55', above_55_mens_singles, 'Mens Singles'),
                        ('Above 55', above_55_women_singles, 'Women Singles')]]
            zip_output = io.BytesIO()
            with zipfile.ZipFile(zip_output, 'w') as zip_file:
                for datasets_list in datasets:
                    for dataset_name, dataset, sheet_name in datasets_list:
                        excel_output = io.BytesIO()
                        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
                            dataset.to_excel(writer, sheet_name=sheet_name, index=True, columns=None)
                        excel_output.seek(0)
                        zip_file.writestr(f'{game}_{dataset_name}_{sheet_name}.xlsx', excel_output.getvalue())

            zip_output.seek(0)

            # Return the zip file as a response (assuming you're using Flask)
            return send_file(zip_output, download_name=f'{game}_workbooks.zip', as_attachment=True, mimetype='application/zip')
        elif game=='CARROMS':
            above_50_mens_doubles = pd.DataFrame(above_50_mens_doubles, columns=d_columns)
            above_50_mixed_doubles = pd.DataFrame(above_50_mixed_doubles, columns=d_columns)
            above_50_women_doubles = pd.DataFrame(above_50_women_doubles, columns=d_columns)
            above_50_mens_singles = pd.DataFrame(above_50_mens_singles, columns=s_columns)
            above_50_women_singles = pd.DataFrame(above_50_women_singles, columns=s_columns)

            below_50_mens_doubles = pd.DataFrame(below_50_mens_doubles, columns=d_columns)
            below_50_mixed_doubles = pd.DataFrame(below_50_mixed_doubles, columns=d_columns)
            below_50_women_doubles = pd.DataFrame(below_50_women_doubles, columns=d_columns)
            below_50_mens_singles = pd.DataFrame(below_50_mens_singles, columns=s_columns)
            below_50_women_singles = pd.DataFrame(below_50_women_singles, columns=s_columns)

            # Assuming you have similar categories and columns as in the reference code
            datasets = [
                [('Above 50', above_50_mens_doubles, 'Mens Doubles'),
                ('Above 50', above_50_mixed_doubles, 'Mixed Doubles'),
                ('Above 50', above_50_women_doubles, 'Women Doubles'),
                ('Above 50', above_50_mens_singles, 'Mens Singles'),
                ('Above 50', above_50_women_singles, 'Women Singles')],
                [('Below 50', below_50_mens_doubles, 'Mens Doubles'),
                ('Below 50', below_50_mixed_doubles, 'Mixed Doubles'),
                ('Below 50', below_50_women_doubles, 'Women Doubles'),
                ('Below 50', below_50_mens_singles, 'Mens Singles'),
                ('Below 50', below_50_women_singles, 'Women Singles')]
            ]
            zip_output = io.BytesIO()
            with zipfile.ZipFile(zip_output, 'w') as zip_file:
                for datasets_list in datasets:
                    for dataset_name, dataset, sheet_name in datasets_list:
                        excel_output = io.BytesIO()
                        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
                            dataset.to_excel(writer, sheet_name=sheet_name, index=True, columns=None)
                        excel_output.seek(0)
                        zip_file.writestr(f'{game}_{dataset_name}_{sheet_name}.xlsx', excel_output.getvalue())

            zip_output.seek(0)

            # Return the zip file as a response (assuming you're using Flask)
            return send_file(zip_output, download_name=f'{game}_workbooks.zip', as_attachment=True, mimetype='application/zip')
        elif game=='TENNIKOIT':
            above_50_women_doubles = pd.DataFrame(above_50_women_doubles, columns=d_columns)
            above_50_women_singles = pd.DataFrame(above_50_women_singles, columns=s_columns)
            below_50_women_doubles = pd.DataFrame(below_50_women_doubles, columns=d_columns)
            below_50_women_singles = pd.DataFrame(below_50_women_singles, columns=s_columns)

            # Assuming you have similar categories and columns as in the reference code
            datasets = [[('Above 50', above_50_women_doubles, 'Women Doubles'),
                ('Above 50', above_50_women_singles, 'Women Singles')],
                [('Below 50', below_50_women_doubles, 'Women Doubles'),
                ('Below 50', below_50_women_singles, 'Women Singles')]]
            zip_output = io.BytesIO()
            with zipfile.ZipFile(zip_output, 'w') as zip_file:
                for datasets_list in datasets:
                    for dataset_name, dataset, sheet_name in datasets_list:
                        excel_output = io.BytesIO()
                        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
                            dataset.to_excel(writer, sheet_name=sheet_name, index=True, columns=None)
                        excel_output.seek(0)
                        zip_file.writestr(f'{game}_{dataset_name}_{sheet_name}.xlsx', excel_output.getvalue())

            zip_output.seek(0)

            # Return the zip file as a response (assuming you're using Flask)
            return send_file(zip_output, download_name=f'{game}_workbooks.zip', as_attachment=True, mimetype='application/zip')
        elif game in ['SWIMMING','ATHLETICS']:
            m_below_35 = pd.DataFrame(m_below_35, columns=s_columns)
            f_below_35 = pd.DataFrame(f_below_35, columns=s_columns)
            m_between_35_and_45 = pd.DataFrame(m_between_35_and_45, columns=s_columns)
            f_between_35_and_45 = pd.DataFrame(f_between_35_and_45, columns=s_columns)
            m_between_46_and_55 = pd.DataFrame(m_between_46_and_55, columns=s_columns)
            f_between_46_and_55 = pd.DataFrame(f_between_46_and_55, columns=s_columns)
            f_above_55 = pd.DataFrame(f_above_55, columns=s_columns)
            m_above_55 = pd.DataFrame(m_above_55, columns=s_columns)
            datasets = [[('Below 35 Male', m_below_35),
                        ('Below 35 Female', f_below_35)],
                        [('Between 35 and 45 Male', m_between_35_and_45),
                        ('Between 35 and 45 Female', f_between_35_and_45)],
                        
                        [('Between 46 and 55 Male', m_between_46_and_55),
                        ('Between 46 and 55 Female', f_between_46_and_55)],
                        
                        [('Above 55 Male', m_above_55),
                        ('Above 55 Female', f_above_55)]]
            zip_output = io.BytesIO()
            with zipfile.ZipFile(zip_output, 'w') as zip_file:
                for datasets_list in datasets:
                    for dataset_name, dataset in datasets_list:
                        excel_output = io.BytesIO()
                        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
                            dataset.to_excel(writer, sheet_name=dataset_name, index=True, columns=None)
                        excel_output.seek(0)
                        zip_file.writestr(f'{game}_{dataset_name}.xlsx', excel_output.getvalue())

            zip_output.seek(0)

            return send_file(zip_output, download_name=f'{game}_workbooks.zip', as_attachment=True, mimetype='application/zip')
        else:
            m_above_equal_50 = pd.DataFrame(m_above_equal_50, columns=s_columns)
            m_below_50 = pd.DataFrame(m_below_50, columns=s_columns)
            f_above_equal_50 = pd.DataFrame(f_above_equal_50, columns=s_columns)
            f_below_50 = pd.DataFrame(f_below_50, columns=s_columns)
            datasets = [
                [('Above 50 Male', m_above_equal_50),
                ('Below 50 Male', m_below_50)],
                [('Above 50 Female', f_above_equal_50),
                ('Below 50 Female', f_below_50)]]
            zip_output = io.BytesIO()
            with zipfile.ZipFile(zip_output, 'w') as zip_file:
                for datasets_list in datasets:
                    for dataset_name, dataset in datasets_list:
                        excel_output = io.BytesIO()
                        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
                            dataset.to_excel(writer, sheet_name=dataset_name, index=True, columns=None)
                        excel_output.seek(0)
                        zip_file.writestr(f'{game}_{dataset_name}.xlsx', excel_output.getvalue())

            zip_output.seek(0)

            return send_file(zip_output, download_name=f'{game}_workbooks.zip', as_attachment=True, mimetype='application/zip')
    finally:
        if mydb.is_connected():
            mydb.close()

@app.route('/getallpaymentdetails/<dec>')
def getallpaymentdetails(dec):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        if dec=='Yes':
            cursor.execute('select p.ordid,p.id,concat(r.FirstName," ",r.LastName),r.mobileno,r.email,r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council,p.game,p.amount,p.transactionid,p.date from payments as p inner join register as r on r.id=p.id where p.status!="pending" and p.id not in (231003,231014,231006,231037)  order by date desc')
            rdetails = cursor.fetchall()
            columns = ['Order id', 'User ID', 'Name','Mobile No','Email','Age','Gender','DOB','City','Address','State','Country','Degree','MCI ID','Shirt Size','Food Preference','Medical Council','Game','Amount','Transaction id','Date']

        else:
            cursor.execute('select p.ordid,p.id,concat(r.FirstName," ",r.LastName),r.mobileno,r.email,r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council,p.game,p.amount,p.date from payments as p inner join register as r on r.id=p.id where p.status="pending" and p.id not in (231003,231014,231006,231037)  order by date desc')
            rdetails = cursor.fetchall()
            columns = ['Order id', 'User ID', 'Name','Mobile No','Email','Age','Gender','DOB','City','Address','State','Country','Degree','MCI ID','Shirt Size','Food Preference','Medical Council','Game','Amount','Date']
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:

        # Convert query result to a pandas DataFrame
        df = pd.DataFrame(rdetails, columns=columns)

        # Create an in-memory Excel file
        excel_output = io.BytesIO()
        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Sheet1', index=False)

        excel_output.seek(0)

        # Serve the file as a downloadable attachment
        return send_file(
            excel_output,
            download_name='payment_details.xlsx',
            as_attachment=True,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    finally:
        if mydb.is_connected():
            mydb.close()

@app.route('/individualregistrations')
def individualregistrations():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.city, r.state, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003, 231014, 231006, 231037) and g.amount > 2000 order by r.id desc")
            rdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('individualregistrations.html',rdetails=rdetails,dec='m1')
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


@app.route('/individualteamregistrations')
def individualteamregistrations():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.city, r.state, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game not in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003, 231014, 231006, 231037) and (g.amount between 1 and 6000) order by r.id desc")
            rdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:       
            return render_template('individualregistrations.html',rdetails=rdetails,dec='m3')
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/individualaddonregistrations')
def individualaddonregistrations():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.city, r.state, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game  in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003, 231014, 231006, 231037) and g.amount < 2000 order by r.id desc")
            rdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('individualregistrations.html',rdetails=rdetails,dec='m2')
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/getallregistrationdetails/<dec>')
def getallregistrationdetails(dec):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        if dec=='m1':
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003,231014,231006,231037) and g.amount>2000")
            rdetails = cursor.fetchall()
        elif dec=='m2':
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003,231014,231006,231037) and g.amount<2000")
            rdetails = cursor.fetchall()
        elif dec=='m3':
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game not in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003,231014,231006,231037) and (g.amount between 1 and 6000)")
            rdetails = cursor.fetchall()
        else:
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game not in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003,231014,231006,231037) and g.amount>6000")
            rdetails = cursor.fetchall()
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:
    
    # Convert query result to a pandas DataFrame
        columns = ['ID', 'Full Name', 'Email', 'Mobile', 'Age', 'Gender', 'DOB', 'City', 'Address', 'State', 'Country', 'Degree', 'MCI_ID', 'SHIRT_SIZE', 'Food Preference', 'Council', 'Game']

        df = pd.DataFrame(rdetails, columns=columns)

        # Create an in-memory Excel file
        excel_output = io.BytesIO()
        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Sheet1', index=False)

        excel_output.seek(0)

        # Serve the file as a downloadable attachment
        return send_file(
            excel_output,
            download_name='game_details.xlsx',
            as_attachment=True,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    finally:
        if mydb.is_connected():
            mydb.close()

@app.route('/franchiseregistrations')
def franchiseregistrations():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT r.ID, concat(r.FirstName, ' ', r.LastName), r.Email, r.mobileno, r.age, r.gender, r.city, r.state, r.food_preference, r.council, g.game FROM register as r inner join game as g on r.id=g.id where g.game  not in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and r.id not in (231003, 231014, 231006, 231037) and g.amount > 6000 order by r.id desc")
            rdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('individualregistrations.html',rdetails=rdetails,dec='m4')
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/getallpendingusers')
def getallpendingusers():
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute('SELECT r.ID, CONCAT(r.FirstName," ",r.LastName), r.Email, r.mobileno, r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council,g.game, g.ordid,g.amount, g.status, g.date FROM temporary AS r LEFT JOIN payments AS g ON r.id=g.id LEFT JOIN register AS reg_email ON r.email=reg_email.email LEFT JOIN register AS reg_mobile ON r.mobileno=reg_mobile.mobileno WHERE reg_email.email IS NULL OR reg_mobile.mobileno IS NULL;')
        rdetails = cursor.fetchall()
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:
        # Convert query result to a pandas DataFrame
        columns = ['Temp id', 'Name','Email','Mobile No','Age','Gender','DOB','City','Address','State','Country','Degree','MCI ID','Shirt Size','Food Preference','Medical Council','Game','Order id','amount','status','Date']
        df = pd.DataFrame(rdetails, columns=columns)

        # Create an in-memory Excel file
        excel_output = io.BytesIO()
        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Sheet1', index=False)

        excel_output.seek(0)

        # Serve the file as a downloadable attachment
        return send_file(
            excel_output,
            download_name='pending_details.xlsx',
            as_attachment=True,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    finally:
        if mydb.is_connected():
            mydb.close()


@app.route('/pendingregistrations')
def pendingregistrations():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('SELECT r.ID, CONCAT(r.FirstName," ",r.LastName), r.Email, r.mobileno, r.city, r.state, g.game, g.ordid,g.amount, g.status, g.date FROM temporary AS r LEFT JOIN payments AS g ON r.id=g.id LEFT JOIN register AS reg_email ON r.email=reg_email.email LEFT JOIN register AS reg_mobile ON r.mobileno=reg_mobile.mobileno WHERE reg_email.email IS NULL OR reg_mobile.mobileno IS NULL order by r.id desc')

            rdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('pending_registrations.html',rdetails = rdetails)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


@app.route('/pendingpayments')
def pendingpayments():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select p.ordid,p.id,concat(r.FirstName," ",r.LastName),r.mobileno,r.email,p.game,p.amount,p.date from payments as p inner join register as r on r.id=p.id where p.status="pending" and p.id not in (231003,231014,231006,231037)  order by date desc')
            payment = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('a-payment.html',payment = payment,desicion='No')
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))
@app.route('/users')
def users():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            query = '''SELECT
            r.ID, concat(r.FirstName," ",r.LastName),r.gender, r.mobileno,r.city, r.state,g.game FROM
            register AS r INNER JOIN (SELECT id, MIN(sno) AS min_sno FROM game
            GROUP BY id) AS subquery ON r.id = subquery.id INNER JOIN game AS g ON r.id = g.id AND subquery.min_sno = g.sno
            where r.id not in (231003,231014,231006,231037) order by r.ID desc
            '''
            cursor.execute(query)

            rdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('admin_registrationdetails.html',rdetails = rdetails)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

   


@app.route('/viewalldetails/<id1>')
def viewalldetails(id1):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select r.ID, r.FirstName, r.LastName, r.Email, r.PASSWORD, r.mobileno, r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.TandCs_acception, r.council, r.c_data, r.c_ext, r.p_data, r.p_ext,g.game from register as r inner join game as g on r.id= g.id where r.id=%s order by g.sno asc limit 1',[id1])
            rdetails = cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('viewalldetails.html',rdetails = rdetails)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/gamesadata/<id1>')
def gamesdata(id1):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select * from sub_games s join individual_teams i on s.id=i.id join teams t on s.id = t.id where s.id=%s',[id1])
            games = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('gamesdata.html',games=games)
        finally:
            if mydb.is_connected():
                mydb.close()

    else:
        return redirect(url_for('login'))
    
@app.route('/viewcfile/<fid>')
def viewcfile(fid):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select c_ext,c_data from register where id=%s',[fid])
            data=cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            filename=f'{fid}.{data[0]}'
            bin_file=data[1]
            byte_data=BytesIO(bin_file)
            #return send_file(byte_data,download_name=filename,as_attachment=True)
            return send_file(byte_data,download_name=filename,as_attachment=False)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


@app.route('/viewpfile/<fid>')
def viewpfile(fid):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select p_ext,p_data from register where id=%s',[fid])
            data=cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            filename=f'{fid}.{data[0]}'
            bin_file=data[1]
            byte_data=BytesIO(bin_file)
            #return send_file(byte_data,download_name=filename,as_attachment=True)
            return send_file(byte_data,download_name=filename,as_attachment=False)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


@app.route('/downloadcfile/<fid>')
def downloadcfile(fid):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select c_ext,c_data from register where id=%s',[fid])
            data=cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            filename=f'{fid}.{data[0]}'
            bin_file=data[1]
            byte_data=BytesIO(bin_file)
            #return send_file(byte_data,download_name=filename,as_attachment=True)
            return send_file(byte_data,download_name=filename,as_attachment=True)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/downloadpfile/<fid>')
def downloadpfile(fid):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select p_ext,p_data from register where id=%s',[fid])
            data=cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            filename=f'{fid}.{data[0]}'
            bin_file=data[1]
            byte_data=BytesIO(bin_file)
            #return send_file(byte_data,download_name=filename,as_attachment=True)
            return send_file(byte_data,download_name=filename,as_attachment=True)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/cgames')
def cgames():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT game, COUNT(*) AS count, SUM(amount) AS total FROM game WHERE game  IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS','CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and game.id not in (231003,231014,231006,231037) GROUP BY game")
            individualdetails = cursor.fetchall()
            cursor.execute("SELECT g.game, COUNT(*) AS count FROM game as g inner join register as r on r.id=g.id  WHERE game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS','CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and g.id not in (231000,231003,231014,231006,231037) and (g.amount>=5000 or g.amount is NULL) and r.gender='Male' GROUP BY g.game")
            teamdetails = cursor.fetchall()
            cursor.execute("SELECT g.game, COUNT(*) AS count FROM game as g inner join register as r on r.id=g.id  WHERE game NOT IN ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS','CYCLOTHON', 'WALKATHON', 'SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING', 'TABLE TENNIS', 'LAWN TENNIS') and g.id not in (231000,231003,231014,231006,231037) and (g.amount>=5000 or g.amount is NULL) and r.gender!='Male' GROUP BY g.game")
            fteamdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('pgames.html',teamdetails = teamdetails,individualdetails = individualdetails,fteamdetails=fteamdetails)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))



@app.route('/ateams/<game>')
def ateams(game):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT r.ID, CONCAT(r.FirstName, ' ', r.LastName) AS FullName, s.team_number AS TeamID, s.game,s.team_name,r.mobileno FROM register r INNER JOIN sub_games s ON r.ID = s.id and s.id not in (231003,231014,231006,231037,231000)  WHERE s.game = %s and r.gender='Male'", [game])
            teamdetails = cursor.fetchall()
            cursor.execute("select g.id,r.mobileno,concat(r.Firstname,' ',r.Lastname) as name,r.gender,r.city,r.state,g.game from game as g left join sub_games as s on g.id=s.id inner join register as r on r.id=g.id where g.game not in ('BADMINTON','TABLE TENNIS','LAWN TENNIS','CARROMS','TENNIKOIT') and g.game=%s and (g.amount>=5000 or g.amount is NULL) and r.gender='Male' and s.id is NULL",[game])
            not_turned_up=cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('ateams.html',teamdetails = teamdetails,not_turned_up=not_turned_up)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))
#need changes here
@app.route('/fateams/<game>')
def fateams(game):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('SELECT r.ID, CONCAT(r.FirstName, " ", r.LastName) AS FullName, s.team_number AS TeamID, s.game,s.team_name,r.mobileno FROM register r INNER JOIN sub_games s ON r.ID = s.id and s.id not in (231003,231014,231006,231037,231000)  WHERE s.game = %s and r.gender="Female"', [game])
            teamdetails = cursor.fetchall()
            cursor.execute('select g.id,r.mobileno,concat(r.Firstname," ",r.Lastname) as name,r.gender,r.city,r.state,g.game from game as g left join sub_games as s on g.id=s.id and g.game=s.game inner join register as r on r.id=g.id where g.game=%s and  g.amount is NULL and s.id is NULL and r.gender="Female"',(game,))
            not_turned_up=cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('ateams.html',teamdetails = teamdetails,not_turned_up=not_turned_up)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


@app.route('/aindividual/<game>')
def aindividual(game):
    if session.get('user'):
        if game in ('BADMINTON', 'CARROMS', 'TABLE TENNIS', 'LAWN TENNIS'):
            try:
                mydb=conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute("SELECT t.id, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email, r.age, t.category, s.id, s.fullname,k.age,s.email, s.status FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.game=%s and t.id not in (231003,231014,231006,231037)", [game])          
                teamdetails = cursor.fetchall()
                query='select r.id,concat(r.firstname," ",r.lastname),r.age,r.mobileno,r.email from game as g inner join register as r on r.id=g.id and r.id not in (231003,231014,231006,231037) where g.game=%s and r.id NOT IN (SELECT id FROM sub_games WHERE game=%s and id not in (231003,231014,231006,231037) UNION ALL SELECT id FROM individual_teams WHERE game=%s AND id IS NOT NULL and id not in (231003,231014,231006,231037))'
                cursor.execute(query,[game,game,game])
                notturned=cursor.fetchall()
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            finally:
                if mydb.is_connected():
                    mydb.close()
        else:
            try:
                mydb=conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute('select r.id,concat(r.firstname," ",r.lastname),r.age,r.mobileno,r.email,s.category from register as r inner join sub_games as s on r.id=s.id and r.id not in (231003,231014,231006,231037) where s.game=%s',[game])
                teamdetails = cursor.fetchall()
                query= 'select g.id,concat(r.FirstName," ",r.LastName) ,r.age,r.mobileno,r.email from game as g left join (select id,game,category from sub_games where game=%s) as s on s.id=g.id inner join register as r on r.id=g.id where g.game=%s and s.category is NULL'
                cursor.execute(query,[game,game])
                notturned=cursor.fetchall()
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later difficulty in fetching data from database'}
            finally:
                if mydb.is_connected():
                    mydb.close()

        return render_template('aindividual.html',teamdetails = teamdetails,notturned=notturned,game=game)
    else:
        return redirect(url_for('login'))

@app.route('/ateamdetails/<tid>')
def ateamdetails(tid):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT r.ID, CONCAT(r.FirstName, ' ', r.LastName) AS FullName,r.mobileno,r.email,r.shirt_size,s.game FROM register as r INNER JOIN sub_games s ON r.ID = s.id WHERE s.team_number = %s", [tid])
            lead = cursor.fetchone()
            cursor.execute("SELECT t.id,t.fullname,r.mobileno,t.email,r.shirt_size,t.game,t.status FROM teams as t inner join register as r on r.id=t.id  WHERE t.teamid=%s",[tid])
            teamdetails = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('ateamdetails.html',lead = lead,teamdetails = teamdetails) 
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))      

@app.route('/pgamedata/<game>')
def pgamedata(game):
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select * from game g join register r on g.id = r.id where g.game= %s',[game])
            pgames = cursor.fetchall()    
            cursor.close()
        except Exception as e:
            print(e)
            return {'message':'Please try again later difficulty in fetching data from database'}
        else:
            return render_template('ppgames.html',pgames = pgames)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return redirect(url_for('login'))


@app.route('/getalldetails')
def getalldetails():
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        query = '''SELECT r.ID, concat(r.FirstName, " ", r.LastName), r.Email, r.mobileno, r.age, r.gender, r.DOB, r.city, r.address, r.state, r.country, r.degree, r.MCI_ID, r.SHIRT_SIZE, r.food_preference, r.council, g.game FROM register AS r INNER JOIN (SELECT id, MIN(sno) AS min_sno FROM game GROUP BY id) AS subquery ON r.id = subquery.id INNER JOIN game AS g ON r.id = g.id AND subquery.min_sno = g.sno order by r.ID desc'''
        cursor.execute(query)
        rdetails = cursor.fetchall()
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:

    # Convert query result to a pandas DataFrame
        columns = ['ID', 'Full Name', 'Email', 'Mobile', 'Age', 'Gender', 'DOB', 'City', 'Address', 'State', 'Country', 'Degree', 'MCI_ID', 'SHIRT_SIZE', 'Food Preference', 'Council', 'Primary Game']
        df = pd.DataFrame(rdetails, columns=columns)

        # Create an in-memory Excel file
        excel_output = io.BytesIO()
        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Sheet1', index=False)

        excel_output.seek(0)

        # Serve the file as a downloadable attachment
        return send_file(
            excel_output,
            download_name='user_details.xlsx',
            as_attachment=True,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    finally:
        if mydb.is_connected():
            mydb.close()


@app.route('/download_c_all_files')
def download_c_all_files():
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select id, c_ext, c_data from register where id not in (231003,231014,231006,231037)')
        file_data = cursor.fetchall()
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:

        if file_data is not None and len(file_data) > 0:
            # Create a ZIP archive in memory
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zipf:
                for fid, c_ext, c_data in file_data:
                    if c_data is not None:
                        filename = f'{fid}.{c_ext}'
                        zipf.writestr(filename, c_data)

            zip_buffer.seek(0)

            # Create a response with the ZIP archive
            response = make_response(zip_buffer.read())
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = 'attachment; filename=certificates_all_files.zip'

            return response
        else:
            return "No files found to download."
    finally:
        if mydb.is_connected():
            mydb.close()


@app.route('/download_p_all_files')
def download_p_all_files():
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select id, p_ext, p_data from register where id not in (231003,231014,231006,231037)')
        file_data = cursor.fetchall()
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:

        if file_data is not None and len(file_data) > 0:
            # Create a ZIP archive in memory
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zipf:
                for fid, c_ext, c_data in file_data:
                    if c_data is not None:
                        filename = f'{fid}.{c_ext}'
                        zipf.writestr(filename, c_data)

            zip_buffer.seek(0)

            # Create a response with the ZIP archive
            response = make_response(zip_buffer.read())
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = 'attachment; filename=Photos_all_files.zip'

            return response
        else:
            return "No files found to download."
    finally:
        if mydb.is_connected():
            mydb.close()



@app.route('/buyaddonplayers/<game>/<quantity>',methods=['GET','POST'])
def buyaddonplayers(game,quantity):
    if session.get('user'):
        try:
            eid=session.get('user')
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT ID, CONCAT(FirstName, ' ', LastName) AS FullName, Email, MobileNo FROM register WHERE id=%s", [eid])
            data1 = cursor.fetchall()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong! Write a mail to "info@doctorsolympiad.com"'}
        finally:
            if mydb.is_connected():
                mydb.close()
        quantity=quantity if quantity.isdigit()==True else '1'
        amount=int(quantity)*1000
        if request.method=='POST':
            ref=random.randint(1000000,99999999)
            eazypay_integration = Eazypay(url_for('addon_p',_external=True))
            payment_url=eazypay_integration.get_payment_url(ref,amount,data1[0][1],data1[0][2],data1[0][3])
            try:
                mydb=conn.get_connection()
                cursor  = mydb.cursor(buffered=True)
                cursor.execute('insert into payments (ordid,id,game,addonplayer,amount) values(%s,%s,%s,%s,%s)',[ref,eid,game,quantity,amount])
                mydb.commit()
                cursor.close()
            except Exception as e:
                print(e)
                return jsonify({'status':'failed','message':'Please try again later difficulty in fetching data from database'})
            else:
                return jsonify({'status':'success','payment_url':payment_url})
            finally:
                if mydb.is_connected():
                    mydb.close()
        return render_template('ptadd.html', data1=data1,game=game,amount=amount,eid=eid,name=data1[0][1],email=data1[0][2],addonplayers=quantity)
    else:
        return redirect(url_for('login'))



@app.route('/addon_p',methods=['POST'])
def addon_p():
    response = request.form.to_dict()
    response_code_value = response.get('Response Code','na')
    if response_code_value != 'na':
        if payment_success_exec():
            ref = int(response['ReferenceNo'])
            amount = float(response['Total Amount'])
            transaction_id = int(response['Unique Ref Number'])
            date=str(response['Transaction Date'])
            try:
                mydb = conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game,addonplayer from payments where ordid=%s',[ref])
                eid,game,players=cursor.fetchone()
                cursor.execute('SELECT concat(FirstName," ",LastName),email from register where id=%s',[eid])
                name,email=cursor.fetchone()
                cursor.execute('update payments set amount=%s,status=%s,transactionid=%s where ordid=%s',[amount,'Successfull',transaction_id,ref])
                mydb.commit()
            except Exception as e:
                print(e)
                return {"Message":"Error Connecting to database contact info@doctorsolympiad.com for further support"}
            else:
                flash('Payment Successfull!')
                return redirect(url_for('registeredgame',game=game))
            finally:
                if mydb.is_connected():
                    mydb.close()
            
        else:
            response_msg = get_response_message(response['Response Code'])
            print(response_msg)
            return f"<h1>Transaction failed. Error: {response_msg}</h1>"
    else:
        return "Invalid response received from payment gateway."










def fetch_data(pgreferenceno):
    # Define the base URL
    base_url = "https://eazypay.icicibank.com/EazyPGVerify?"

    # Construct the query parameters
    params = {
        "ezpaytranid": "",
        "amount": "",
        "paymentmode": "",
        "merchantid": "376890",
        "trandate": "",
        "pgreferenceno": pgreferenceno
    }

    # Encode the parameters and create the full URL
    full_url = base_url + urlencode(params)

    # Send a GET request to the URL
    response = requests.get(full_url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the response and return the data as a dictionary
        data = {}
        for pair in response.text.split('&'):
            key, value = pair.split('=')
            data[key] = value
        return data
    else:
        return None




@app.route('/icici', methods=['GET', 'POST'])
def icici():
    pgreferenceno = None
    data = None

    if request.method == 'POST':
        if 'pgreferenceno' in request.form:
            pgreferenceno = request.form.get('pgreferenceno')

            # Fetch data using the user-provided pgreferenceno
            data = fetch_data(pgreferenceno)
        else:
            pg=request.form['pg']
            data = fetch_data(pg)
            print(data)
            if data['status']!='Success':
                flash('Payment still pending!')
                return render_template('paytest.html', pgreferenceno=pgreferenceno, data=data)
            amount=data['amount']
            transaction_id=data['ezpaytranid']
            date=data['trandate']
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game from payments where ordid=%s',[pg])
                eid,game=cursor.fetchone()
                cursor.execute('select gender,email,mobileno from temporary where id=%s',[eid])
                gender,email,mobileno=cursor.fetchone()
                cursor.execute('insert into register (FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext) select FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council,c_data,c_ext,p_data,p_ext from temporary where id=%s',[eid])
                mydb.commit()
                cursor.execute('SELECT id from register where email=%s',[email])
                uid=cursor.fetchone()[0]
                cursor.execute('SELECT concat(FirstName," ",LastName) as name from register where email=%s',[email])
                name=cursor.fetchone()[0]
                cursor.execute('UPDATE  payments SET status=%s,amount=%s,id=%s,transactionid=%s WHERE ordid=%s',['Successfull',amount,uid,transaction_id,pg])
                cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [uid,game,amount])
                cursor.execute('DELETE FROM temporary where id=%s or email=%s or mobileno=%s',[eid,email,mobileno])
                mydb.commit()
                if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                    category="Men's singles" if gender=='Male' else "Women's singles"
                    cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,uid,category])
                    mydb.commit()
                    #  print(details)
                cursor.execute('select ID,Concat(FirstName," ",LastName),Email,concat("91","",mobileno) AS mobile,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council from register where id=%s',[uid])
                deta=cursor.fetchone()+(game,)
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later! We are facing difficulty in fetching data from database'}
            else:
                scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
                credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
                client = gspread.authorize(credentials)
                spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
                worksheet = spreadsheet.get_worksheet(0)
                deta_str = [str(item) for item in deta]  # Convert all items to strings
                worksheet.append_row(deta_str)

                html = f"""
                <!DOCTYPE html>
                <html lang="en">

                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Registration Confirmation</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            margin: 0 auto;
                            max-width: 600px;
                            padding: 20px;
                            background-color: rgba(206,238,255,0.5);
                        }}

                        h1 {{
                            text-align: center;
                        }}

                        img {{
                            display: block;
                            margin: 0 auto;
                            max-width: 100%;
                        }}

                        table {{
                            width: 100%;
                            border-collapse: collapse;
                            margin-top: 20px;
                        }}

                        th,
                        td {{
                            border: 1px solid black;
                            padding: 10px;
                            text-align: left;
                        }}

                        th {{
                            background-color: #f2f2f2;
                        }}

                        ul {{
                            list-style-type: none;
                            padding: 0;
                        }}

                        ul li {{
                            margin-bottom: 10px;
                        }}
                    </style>
                </head>

                <body>
                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" />
                    <h1>Welcome to Doctors Olympiad 2023</h1>
                    <p>Dear {name},</p>
                    <p>Greetings from the IMA National Sports Meet: Doctors Olympiad 2023 team! We are thrilled to have received your
                        registration for this exciting event. Get ready to showcase your sportsmanship and camaraderie on the field!</p>

                    <h2>Registration Details:</h2>
                    <table>
                        <tr>
                            <th>Event:</th>
                            <td>IMA National Sports Meet: Doctors Olympiad 2023</td>
                        </tr>
                        <tr>
                            <th>Participant's Name:</th>
                            <td>{name}</td>
                        </tr>
                        <tr>
                            <th>Registered Game:</th>
                            <td>{game}</td>
                        </tr>
                        <tr>
                            <th>Registration Date:</th>
                            <td>{date}</td>
                        </tr>
                        <tr>
                            <th>Unique ID:</th>
                            <td>{uid}</td>
                        </tr>
                        <tr>
                            <th>Transaction ID</th>
                            <td>{transaction_id}</td>
                        </tr>
                        <tr>
                            <th>Amount</th>
                            <td>&#8377; {amount} /-</td>
                        </tr>
                    </table>

                    <p>Your enthusiasm and commitment to joining us for this event are truly appreciated. We can't wait to see you in
                        action, competing in {game} and being part of this fantastic celebration of sports and
                        unity within the medical community.</p>

                    <h2>Event Details:</h2>
                    <table>
                        <tr>
                            <th>Date:</th>
                            <td>22nd November 2023</td>
                        </tr>
                        <tr>
                            <th>Time:</th>
                            <td>2 PM Onwards Tentative</td>
                        </tr>
                        <tr>
                            <th>Venue:</th>
                            <td>DOCTORS SPORTS ACADEMY GROUNDS</td>
                        </tr>
                    </table>

                    <p>Stay tuned for forthcoming updates and crucial information as we approach the event date. Furthermore, please make it a point to regularly check both your email and WhatsApp for important notices and updates.
                        Should you have any questions or require assistance, feel free to reach out to our dedicated team at <a href="mailto:info@doctorsolympiad.com"
                            style="text-decoration: none;">info@doctorsolympiad.com</a>
                or <a href="tel:9759434567"
                        style="text-decoration: none;">9759434567</a>.</p>

                    <p>Once again, thank you for registering for the IMA National Sports Meet: Doctors Olympiad 2023. Your participation
                        contributes to the success of this event and the spirit of camaraderie among medical professionals.</p>

                    <p>Warm regards,</p>
                    <p>Doctors Olympiad 2023<br><a href="mailto:info@doctorsolympiad.com"
                        style="text-decoration: none;">info@doctorsolympiad.com</a><br><a href="tel:9759434567" style="text-decoration: none;">9759434567</a></p>

                </body>

                </html>
                """
                subject='Registration Successful for Doctors Olympiad 2023'
                mail_with_atc(to=email, subject=subject, html=html)                
                flash('Status Updated')

                return render_template('paytest.html', pgreferenceno=pgreferenceno, data=data)
            finally:
                if mydb.is_connected():
                    mydb.close()


    return render_template('paytest.html', pgreferenceno=pgreferenceno, data=data)


@app.route('/icici/addon', methods=['GET', 'POST'])
def iciciaddon():
    pgreferenceno = None
    data = None

    if request.method == 'POST':
        if 'pgreferenceno' in request.form:
            pgreferenceno = request.form.get('pgreferenceno')
            data = fetch_data(pgreferenceno)
        else:
            pg=request.form['pg']
            data = fetch_data(pg)
            print(data)
            if data['status']!='Success':
                flash('Payment still pending!')
                return render_template('paytest.html', pgreferenceno=pgreferenceno, data=data)
            amount=data['amount']
            transaction_id=data['ezpaytranid']
            date=data['trandate']
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True)
                cursor.execute('SELECT id,game from payments where ordid=%s',[pg])
                eid,game=cursor.fetchone()
                cursor.execute('select gender,concat(firstname," ",lastname),email from register where id=%s',[eid])
                gender,name,email=cursor.fetchone()
                cursor.execute('UPDATE  payments SET status=%s,amount=%s,transactionid=%s WHERE ordid=%s',['Successfull',amount,transaction_id,pg])
                cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [eid,game,amount])
                mydb.commit()
                if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                    category="Men's singles" if gender=='Male' else "Women's singles"
                    cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,eid,category])
                    mydb.commit()
                cursor.close()
            except Exception as e:
                print(e)
                return {'message':'Please try again later! We are facing difficulty in fetching data from database'}
            else:
                html = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Registration Confirmation</title>
                    <style>
                        table {{
                            margin: auto;
                        }}
                        img {{
                            margin-left: 30%;
                        }}
                        h1 {{
                            text-align: center;
                        }}
                        table, tr, th, td {{
                            border: 1px solid black;
                            border-collapse: collapse;
                        }}
                        th {{
                            text-align: left;
                        }}
                        td {{
                            width: 60%;
                        }}
                    </style>
                </head>
                <body>
                    <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%"/>
                    <h1>>Hi {name},<br><br>Thanks for registering to {game} in Doctors Olympiad 2023.<br><br>Your Payment details</h1>
                    <table cellpadding="10">
                        <tr>
                            <th>UNIQUE REFERENCE ID</th>
                            <td>{eid}</td>
                        </tr>
                        <tr>
                            <th>Name</th>
                            <td>{name}</td>
                        </tr>
                        <tr>
                            <th>email</th>
                            <td>{email}</td>
                        </tr>
                        <tr>
                            <th>Game</th>
                            <td>{game}</td>
                        </tr>
                        <tr>
                            <th>Transaction ID</th>
                            <td>{transaction_id}</td>
                        </tr>
                        <tr>
                            <th>Payment</th>
                            <td>{amount}</td>
                        </tr>
                    </table>
                </body>
                </html>
                """
                subject='Registration Successful for Doctors Olympiad 2023'
                mail_with_atc(to=email, subject=subject, html=html)                
                flash('Status Updated')

                return render_template('paytest.html', pgreferenceno=pgreferenceno, data=data)
            finally:
                if mydb.is_connected():
                    mydb.close()
    return render_template('paytest.html', pgreferenceno=pgreferenceno, data=data)

@app.route('/client_error',methods=['POST'])
def client_error():
    error_data = request.json
    to='info@doctorsolympiad.com'
    subject='Error in application'
    body=f'You got this errr:{error_data}'
    sendmail(to=to,subject=subject,body=body)
    return {'message':'Success'}
 
@app.route('/offlineregistration',methods=['GET','POST'])
def offline():
    if request.method == 'POST':
        try:
            fname = request.form['fname']
            lname = request.form['lname']
            email = request.form['email']
            password = request.form['password']
            mobile = request.form['mobile']
            age = request.form['age']
            gender = request.form['gender']
            dob_year = request.form['dob_year']
            dob_month=request.form['dob_month']
            dob_day=request.form['dob_day']
            city = request.form['city']
            address = request.form['address']
            state = request.form['state']
            country = request.form['country']
            degree = request.form['degree']
            mci = request.form['mci']
            #game = request.form['game']
            shirtsize = request.form['shirtsize']
            food_preference=request.form['food']
            council=request.form['council']
        except Exception as e:
            message="Please fill all the fields"
            return jsonify({'message':message})
        dob=f"{dob_year}-{dob_month}-{dob_day}"
        try:
            mydb=conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute('SELECT COUNT(*) FROM register WHERE Email = %s', [email])
            count1 = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM register WHERE mobileno = %s', [mobile])
            count2 = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            print(e)
            return jsonify({'message': 'Difficulty in checking the records for duplicate mail id try again later'})
        finally:
            if mydb.is_connected():
                mydb.close()
        if count2 == 1:
            message='Mobile number already exists.'
            return jsonify({'message':message})
        if count1 == 1:
            message='Email already in use'
            return jsonify({'message':message})
       

        '''if gender=='Male' and game in ['KHO KHO','THROW BALL','WOMEN BOX CRICKET']:
                message=f'{game} can only be played by Female players.'
                return jsonify({'message':message})
        if gender=='Female' and game in ['FOOTBALL','HARD TENNIS CRICKET','CRICKET WHITE BALL']:
            message=f'{game} can only be played by Male players.'
            return jsonify({'message':message})'''
      
        amount=4000 if food_preference=='Yes' else 3000       
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
        # data = {
        #     'fname': fname, 'lname': lname, 'email': email, 'password': hashed_password, 'mobile': mobile,
        #     'age': age, 'gender': gender, 'dob': dob, 'city': city.lower().strip(), 'address': address.strip(), 'state': state,
        #     'country': country, 'degree': degree, 'mci': mci, 'game': game,
        #     'amount': amount,'shirtsize': shirtsize,
        #     'food_preference':food_preference,'council':council,
        # }
        data = {
            'fname': fname, 'lname': lname, 'email': email, 'password': hashed_password, 'mobile': mobile,
            'age': age, 'gender': gender, 'dob': dob, 'city': city.lower().strip(), 'address': address.strip(), 'state': state,
            'country': country, 'degree': degree, 'mci': mci,'shirtsize': shirtsize,
            'food_preference':food_preference,'council':council,'game':'Culturals','amount': amount,
        }
        ref=random.randint(1000000,99999999)
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('INSERT INTO register(FirstName,LastName,Email,password,mobileno,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (data['fname'], data['lname'], data['email'], data['password'], data['mobile'], data['age'], data['gender'], data['dob'], data['city'], data['address'], data['state'], data['country'], data['degree'], data['mci'],data['shirtsize'], data['food_preference'],data['council']))
            cursor.execute('SELECT id FROM register WHERE Email = %s AND mobileno = %s ORDER BY id DESC LIMIT 1',[data['email'], data['mobile']])
            eid=cursor.fetchone()[0]
            #cursor.execute('INSERT INTO game (id,game,amount) VALUES (%s,%s,%s)', [eid,data['game'],data['amount']])
            #cursor.execute('insert into payments (ordid,id,game,amount,status) values(%s,%s,%s,%s,%s)',[ref,eid,game,amount,'Successfull'])
            cursor.execute('insert into payments (ordid,id,game,amount,status) values(%s,%s,%s,%s,%s)',[ref,eid,'Culturals',amount,'Successfull'])
            mydb.commit()
            '''if game in ('CHESS','ROWING','FENCING','CYCLOTHON','ARCHERY','ROLLER SKATING'):
                category="Men's singles" if gender=='Male' else "Women's singles"
                cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,eid,category])
                mydb.commit()'''
            cursor.execute('select ID,Concat(FirstName," ",LastName),Email,concat("91","",mobileno) AS mobile,age,gender,DOB,city,address,state,country,degree,MCI_ID,shirt_size,food_preference,council from register where id=%s',[eid])
            #deta=cursor.fetchone()+(game,)
            deta=cursor.fetchone()+('Culturals',)
            cursor.close()

        except Exception as e:
            print(e)
            message='Please try after some time:Difficulty in updating the data'
            return  jsonify({'message':message})
        else:
            now=datetime.now()
            date=now.strftime("%Y/%m/%d")
            name=f"{fname} {lname}"
            scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
            credentials = ServiceAccountCredentials.from_json_keyfile_name('decoded-app-396706-566512d1ca79.json', scope)
            client = gspread.authorize(credentials)
            spreadsheet = client.open('doctors')  # Replace 'doctors' with your actual sheet name
            worksheet = spreadsheet.get_worksheet(0)
            deta_str = [str(item) for item in deta]  # Convert all items to strings
            worksheet.append_row(deta_str)
            '''html = f"""
            <!DOCTYPE html>
            <html lang="en">

            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Registration Confirmation</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 0 auto;
                        max-width: 600px;
                        padding: 20px;
                        background-color: rgba(206,238,255,0.5);
                    }}

                    h1 {{
                        text-align: center;
                    }}

                    img {{
                        display: block;
                        margin: 0 auto;
                        max-width: 100%;
                    }}

                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                    }}

                    th,
                    td {{
                        border: 1px solid black;
                        padding: 10px;
                        text-align: left;
                    }}

                    th {{
                        background-color: #f2f2f2;
                    }}

                    ul {{
                        list-style-type: none;
                        padding: 0;
                    }}

                    ul li {{
                        margin-bottom: 10px;
                    }}
                </style>
            </head>

            <body>
                <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%" />
                <h1>Welcome to Doctors Olympiad 2023</h1>
                <p>Dear {name},</p>
                <p>Greetings from the IMA National Sports Meet: Doctors Olympiad 2023 team! We are thrilled to have received your
                    registration for this exciting event. Get ready to showcase your sportsmanship and camaraderie on the field!</p>

                <h2>Registration Details:</h2>
                <table>
                    <tr>
                        <th>Event:</th>
                        <td>IMA National Sports Meet: Doctors Olympiad 2023</td>
                    </tr>
                    <tr>
                        <th>Participant's Name:</th>
                        <td>{name}</td>
                    </tr>
                    <tr>
                        <th>Registered Game:</th>
                        <td>{game}</td>
                    </tr>
                    <tr>
                        <th>Registration Date:</th>
                        <td>{date}</td>
                    </tr>
                    <tr>
                        <th>Unique ID:</th>
                        <td>{eid}</td>
                    </tr>
                    <tr>
                        <th>Amount</th>
                        <td>&#8377; {amount} /-</td>
                    </tr>
                </table>

                <p>Your enthusiasm and commitment to joining us for this event are truly appreciated. We can't wait to see you in
                    action, competing in {game} and being part of this fantastic celebration of sports and
                    unity within the medical community.</p>

                <h2>Event Details:</h2>
                <table>
                    <tr>
                        <th>Date:</th>
                        <td>22nd November 2023</td>
                    </tr>
                    <tr>
                        <th>Time:</th>
                        <td>2 PM Onwards Tentative</td>
                    </tr>
                    <tr>
                        <th>Venue:</th>
                        <td>DOCTORS SPORTS ACADEMY GROUNDS</td>
                    </tr>
                </table>

                <p>Stay tuned for forthcoming updates and crucial information as we approach the event date. Furthermore, please make it a point to regularly check both your email and WhatsApp for important notices and updates.
                    Should you have any questions or require assistance, feel free to reach out to our dedicated team at <a href="mailto:info@doctorsolympiad.com"
                        style="text-decoration: none;">info@doctorsolympiad.com</a>
            or <a href="tel:9759434567"
                    style="text-decoration: none;">9759434567</a>.</p>

                <p>Once again, thank you for registering for the IMA National Sports Meet: Doctors Olympiad 2023. Your participation
                    contributes to the success of this event and the spirit of camaraderie among medical professionals.</p>

                <p>Warm regards,</p>
                <p>Doctors Olympiad 2023<br><a href="mailto:info@doctorsolympiad.com"
                    style="text-decoration: none;">info@doctorsolympiad.com</a><br><a href="tel:9759434567" style="text-decoration: none;">9759434567</a></p>

            </body>

            </html>
            """
            subject='Registration Successful for Doctors Olympiad 2023'
            mail_with_atc(to=email, subject=subject, html=html)'''
            return jsonify({'message':'success'})
        finally:
            if mydb.is_connected():
                mydb.close()
    response = make_response(render_template('offlineregister.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response
@app.errorhandler(404)
def page_not_found(error):
    return render_template('error_handler.html')

@app.errorhandler(502)
def page_not_found(error):
    return render_template('error_handler-502.html')
@app.route('/womenfreefranchise/<game>')
def womenfreefranchise(game):
    if session.get('user'):
        uid=session.get('user')
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("SELECT CONCAT(FirstName, ' ', LastName) AS FullName, Email FROM register WHERE id=%s", [uid])
            name,email = cursor.fetchone()
            cursor.close()
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong! Write a mail to "info@doctorsolympiad.com"'}
        
        else:
            cursor=mydb.cursor(buffered=True)
            cursor.execute("SELECT count(*) FROM game WHERE id=%s and game=%s and amount is NULL",(uid,game))
            add_count=cursor.fetchone()[0]
            if add_count==0:
                cursor.execute('INSERT INTO game (id, game) VALUES (%s, %s)', [uid, game])
                mydb.commit()
            else:
                flash('Registration already done')
                return redirect(url_for('dashboard'))
            cursor.close()
        finally:
            if mydb.is_connected():
                mydb.close()

        html = f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Registration Confirmation</title>
                        <style>
                            table {{
                                margin: auto;
                            }}
                            img {{
                                margin-left: 30%;
                            }}
                            h1 {{
                                text-align: center;
                            }}
                            table, tr, th, td {{
                                border: 1px solid black;
                                border-collapse: collapse;
                            }}
                            th {{
                                text-align: left;
                            }}
                            td {{
                                width: 60%;
                            }}
                        </style>
                    </head>
                    <body>
                        <img src="https://i.ytimg.com/vi/wq13sUIMWB0/maxresdefault.jpg" width="40%"/>
                        <h1>>Hi {name},<br><br>Thanks for registering to {game} in Doctors Olympiad 2023.<br><br>Your Payment details</h1>
                        <table cellpadding="10">
                            <tr>
                                <th>UNIQUE REFERENCE ID</th>
                                <td>{uid}</td>
                            </tr>
                            <tr>
                                <th>Name</th>
                                <td>{name}</td>
                            </tr>
                            <tr>
                                <th>email</th>
                                <td>{email}</td>
                            </tr>
                            <tr>
                                <th>Game</th>
                                <td>{game}</td>
                            </tr>
                        </table>
                    </body>
                    </html>
                    """
        subject='Registration Successful for Doctors Olympiad 2023'
        mail_with_atc(to=email, subject=subject, html=html)

        flash('Registration Successful')
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
@app.route('/addnotturned/<game>')
def addnotturned(game):
    games=['TABLE TENNIS','LAWN TENNIS','CARROMS','BADMINTON','TENNIKOIT']
    if game not in games:
        return {'message':'Game not listed in insertion list'}
    else:
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            query= 'select g.id,r.gender from game as g left join (select id,game,category from sub_games where game=%s) as s on s.id=g.id inner join register as r on r.id=g.id where g.game=%s and s.category is NULL'
            cursor.execute(query,[game,game])
            notturned=cursor.fetchall()
            if len(notturned)==0:
                return "No thing to turnin"
        except Exception as e:
            print("Error while connecting to MySQL", e)
            return f"Error while connecting to MySQL {e}"
        else:
            try:
                print(notturned)
                for k,l in notturned:
                    category='Womens Single' if l=='Female' else "Mens Single"
                    cursor.execute('insert into sub_games (game,id,category) values(%s,%s,%s)',[game,k,category])
                mydb.commit() 
                return {'message':'All IN TO Singles'}
            except Exception as e:
                mydb.rollback()
                print("Error while inserting data into table", e)
                return f"Error while inserting data into table {e}"
            finally:
                cursor.close()
        finally:
            if (mydb.is_connected()):
                mydb.close()

@app.route('/getallnotturneddata/<game>')
def getallnotturneddata(game):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        query='select r.id,concat(r.firstname," ",r.lastname),r.age,concat("91",r.mobileno) as mobileno,r.email from game as g inner join register as r on r.id=g.id and r.id not in (231003,231014,231006,231037) where g.game=%s and r.id NOT IN (SELECT id FROM sub_games WHERE game=%s and id not in (231003,231014,231006,231037) UNION ALL SELECT id FROM individual_teams WHERE game=%s AND id IS NOT NULL and id not in (231003,231014,231006,231037))'
        cursor.execute(query,[game,game,game])
        rdetails=cursor.fetchall()
        cursor.close()
    except Exception as e:
        print(e)
        return {'message':'Please try again later difficulty in fetching data from database'}
    else:
        columns = ['ID','NAME','AGE','Mobile','EMAIL']
        df = pd.DataFrame(rdetails, columns=columns)

        # Create an in-memory Excel file
        excel_output = io.BytesIO()
        with pd.ExcelWriter(excel_output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Sheet1', index=False)

        excel_output.seek(0)

        # Serve the file as a downloadable attachment
        return send_file(
            excel_output,
            download_name=f'{game}_pending_details.xlsx',
            as_attachment=True,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    finally:
        if mydb.is_connected():
            mydb.close()
@app.route('/qr/<qr>')
def qr(qr):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute("SELECT id,concat(firstname,' ',lastname) as name,mobileno,email,food_preference,shirt_size from register where id=%s ",[qr])
        details=cursor.fetchone()
        cursor.execute("select game from game where id=%s",[qr])
        games=cursor.fetchall()
        games_list=",".join([i[0] for i in games])
        cursor.execute("SELECT t.game,t.category, s.id, s.fullname,s.status,s.email FROM sub_games t LEFT JOIN individual_teams s ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where t.id=%s and t.game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS')", [qr])          
        game_cat=cursor.fetchall()
        query="SELECT t.game,t.category, t.id, concat(r.firstname,' ',r.lastname),s.status FROM individual_teams s LEFT JOIN sub_games as t  ON t.team_number = s.teamid INNER JOIN register r ON r.ID = t.id LEFT JOIN register k ON k.id = s.id where s.id=%s and t.game in ('ATHLETICS', 'ARCHERY', 'BADMINTON', 'CARROMS', 'CHESS', 'CYCLOTHON', 'WALKATHON','SWIMMING', 'TENNIKOIT', 'THROW', 'ROWING', 'ROLLER SKATING', 'FENCING', 'SHOOTING','TABLE TENNIS', 'LAWN TENNIS')"
        cursor.execute(query,(qr,))
        partner_data=cursor.fetchall()
        cursor.execute("SELECT p_data,p_ext from register where id=%s",(qr,))
        data=cursor.fetchone()
        cursor.close()
    except Exception as e:
        print(e)
        return f"Error connecting to database {e}"
    finally:
        if mydb.is_connected():
            mydb.close()
    game_cat+=partner_data if partner_data!=[] else []
    args={}
    if data[1]!=None:
        p_ext=data[1]
        base64_image = base64.b64encode(data[0]).decode('utf-8')
        args={'p_ext':p_ext,'base64_image':base64_image}
    return render_template('qr.html',games=games_list,details=details,game_cat=game_cat,**args)

@app.route('/getqr')
def getqr():
    if session.get('user'):
        return render_template('displayqr.html')
    else:
        return redirect(url_for('login'))
@app.route('/getvipqr/<sno>')
def getvipqr(sno):
    try:
        mydb=conn.get_connection()
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select name,mobile,hospital from vip where sno=%s',[sno])
        name,mobile,hospital=cursor.fetchone()
    except Exception as e:
        print(e)
        return {'message':f'Please try again later difficulty in fetching data from database {e}'}
    finally:
        if mydb.is_connected():
            mydb.close()
    return render_template('vipdisplayqr.html',sno=sno,mobile=mobile,hospital=hospital,name=name)

if __name__ == '__main__':
    app.run()
