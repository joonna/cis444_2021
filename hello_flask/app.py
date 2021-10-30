from flask import Flask,render_template,request
from flask_json import FlaskJSON, JsonError, json_response, as_json
import jwt

import datetime
import bcrypt


from db_con import get_db_instance, get_db

app = Flask(__name__)
FlaskJSON(app)

USER_PASSWORDS = { "cjardin": "strong password"}

IMGS_URL = {
            "DEV" : "/static",
            "INT" : "https://cis-444-fall-2021.s3.us-west-2.amazonaws.com/images",
            "PRD" : "http://d2cbuxq67vowa3.cloudfront.net/images"
            }

CUR_ENV = "PRD"
JWT_SECRET = None

global_db_con = get_db()


with open("secret", "r") as f:
    JWT_SECRET = f.read()

@app.route('/') #endpoint
def index():
    return 'Web App with Python Caprice!' + USER_PASSWORDS['cjardin']

@app.route('/buy') #endpoint
def buy():
    return 'Buy'

@app.route('/hello') #endpoint
def hello():
    return render_template('hello.html',img_url=IMGS_URL[CUR_ENV] ) 

@app.route('/back',  methods=['GET']) #endpoint
def back():
    return render_template('backatu.html',input_from_browser=request.args.get('usay', default = "nothing", type = str) )

@app.route('/backp',  methods=['POST']) #endpoint
def backp():
    print(request.form)
    salted = bcrypt.hashpw( bytes(request.form['fname'],  'utf-8' ) , bcrypt.gensalt(10))
    print(salted)

    print(  bcrypt.checkpw(  bytes(request.form['fname'],  'utf-8' )  , salted ))

    return render_template('backatu.html',input_from_browser= str(request.form) )

@app.route('/auth',  methods=['POST']) #endpoint
def auth():
        print(request.form)
        return json_response(data=request.form)



#Assigment 2
@app.route('/ss1') #endpoint
def ss1():
    return render_template('server_time.html', server_time= str(datetime.datetime.now()) )

@app.route('/getTime') #endpoint
def get_time():
    return json_response(data={"password" : request.args.get('password'),
                                "class" : "cis44",
                                "serverTime":str(datetime.datetime.now())
                            }
                )

@app.route('/auth2') #endpoint
def auth2():
    jwt_str = jwt.encode({"username" : "cary",
                            "age" : "so young",
                            "books_ordered" : ['f', 'e'] } 
                            , JWT_SECRET, algorithm="HS256")
    #print(request.form['username'])
    return json_response(jwt=jwt_str)

@app.route('/exposejwt') #endpoint
def exposejwt():
    jwt_token = request.args.get('jwt')
    print(jwt_token)
    return json_response(output=jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"]))


@app.route('/hellodb') #endpoint
def hellodb():
    cur = global_db_con.cursor()
    cur.execute("insert into music values( 'dsjfkjdkf', 1);")
    global_db_con.commit()
    return json_response(status="good")

#Assignment 3
@app.route('/retrieveBooks', methods = ['GET']) #endpoint
def retrieveBooks():
#	print("entering retrieveBooks")
	token = request.headers.get('Authorization')
	tokenValidation = verifyToken(token)
#	print("token was checked")
	if(tokenValidation == False):
#		print("token valid was bad")
		return json_response(status='Error', msg='Invalid JWT Token')

	cur = global_db_con.cursor()
	cur.execute("SELECT name FROM books;")
	name = cur.fetchall();
#	print("I fetched books")

	cur.execute("SELECT price FROM books;")
	price = cur.fetchall();
#	print("I fetched price")
	#print(books[0][0])
	#print(books[0][1])
	return json_response(jwt = token, name = name, price = price)

@app.route('/userAuth', methods = ['POST']) #endpoint
def userAuth():
#	print(request.form)
#	print("-------")
	cur = global_db_con.cursor()
	dbEntry = "SELECT password FROM users WHERE username ='"
	dbEntry += request.form['uname']
	dbEntry += "';"
	cur.execute(dbEntry)
	r = cur.fetchone();
#	print(r[0])
	uPass = str(r[0])
	if bcrypt.checkpw( bytes(request.form['pass'], 'utf-8'), uPass.encode('utf-8')):
#		jwt_str = jwt.encode({"username": request.form['uname'], algorithm="HS256")
		jwt_str = jwt.encode({"username": request.form['uname'], "password": request.form['pass']}, JWT_SECRET, algorithm="HS256")
#		print("-------")
#		print(jwt_str.username)
		return json_response(jwt=jwt_str)
	print("INVALID")
	return json_reponse(status='Error', msg='Invalid Login')

@app.route('/createNewUser', methods = ['POST']) #endpoint
def createNewUser():
	print(request.form)
	#get user info
	newUser = request.form['uname']
	newPass = request.form['pass']
	#salt user password
	salted = bcrypt.hashpw(bytes(request.form['pass'], 'utf-8'), bcrypt.gensalt(10))
	print(newUser)
	#Creating database entry
	dbEntry = "INSERT INTO users(username, password) VALUES('"
	dbEntry += str(newUser)
	dbEntry += "','"
	dbEntry += str(salted.decode('utf-8'))
	dbEntry += "');"
	#
	cur = global_db_con.cursor()
	cur.execute(dbEntry)
	#
	global_db_con.commit()

	return json_response(status="good")

@app.route('/purchaseBook', methods = ['POST']) #endpoint
def purchaseBook():
#	print("I'm in here!")
	cur = global_db_con.cursor()
	token = request.headers.get('Authorization') #username
#	print(token)
	bookName = request.form['book']
#	print(bookName)
	#time = request.form['currentTime']
	#print(time)
	time = datetime.datetime.now()
#	print(time)
	deToken = decodeToken(token)
#	print(deToken)

	dbEntry = "INSERT INTO purchases(userID, book, date) VALUES('"
	dbEntry += str(deToken)
	dbEntry += "','"
	dbEntry += str(bookName)
	dbEntry += "','"
	dbEntry += str(time)
	dbEntry += "');"

	print(dbEntry)

	cur.execute(dbEntry)
	global_db_con.commit()

	return json_response(status = 'success')

def decodeToken(token):
	decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
	tString = decoded.get('username')
	return tString;

def verifyToken(token):
	print(token)
	tString = decodeToken(token)
	cur = global_db_con.cursor()
	dbEntry = "SELECT EXISTS(SELECT USERNAME FROM users WHERE username = '"
	dbEntry += tString;
	dbEntry += "' limit 1);"
	cur.execute(dbEntry)
	r = cur.fetchone()
	print(r[0])
	if(r[0] == True):
		return True
	return False



#apprunhost
app.run(host='0.0.0.0', port=80)

