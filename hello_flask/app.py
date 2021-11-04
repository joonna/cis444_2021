from flask import Flask,render_template,request,jsonify
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


def JWT_Token(user):
    token = jwt.encode({'username': user,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
        JWT_SECRET, algorithm="HS256")
    return token

with open("secret", "r") as f:
    JWT_SECRET = f.read()

@app.route('/') #endpoint
def index():
    return render_template('hello.html',img_url=IMGS_URL[CUR_ENV])

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
    salted = bcrypt.hashpw( bytes(request.form['password'],  'utf-8' ) , bcrypt.gensalt(12))
    print(salted)

    print(  bcrypt.checkpw(  bytes(request.form['password'],  'utf-8' )  , salted ))

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
@app.route('/login', methods=['POST'])
def login():
    user_ID = request.form['username']
    password = request.form['password']
    cur = global_db_con.cursor()
    cur.execute(f"select password from users where username = '{user_ID}';")
    db_pass = cur.fetchone()[0]
    if(db_pass == None):
        print("username not found")
        status = 403
        return jsonify(status)
    else:
        db_pass = bytes(db_pass, 'utf-8')
        checkPass = bcrypt.checkpw(bytes(password, 'utf-8'), db_pass)
        if(checkPass):
            token = JWT_Token(user_ID)
            return jsonify(token)
        else:
            print("password doesn't match database")
            status = 403
            return jsonify(status)



@app.route('/store', methods=['GET']) #endpoint
def store():
    cur = global_db_con.cursor()
    cur.execute("select name from books;")
    books = cur.fetchall()
    if books == None:
       return "Book table returned nothing"
    else:
     bookList = []
     for book in books:
        bookList.append(book)
    return json_response(bookList = books)
    

@app.route('/signup', methods=['POST']) #endpoit
def signup():
    user_name = request.form['username']
    passwork = request.form['password']
    cur = global_db_con.cursor()
    cur.execute(f"select * from users where username = '{user_name}';")
    nameCheck = cur.fetchone()
    if nameCheck == None:
        salted = bcrypt.hashpw( bytes(request.form['password'],  'utf-8' ) , bcrypt.gensalt(12))
        decryptSalt = salted.decode('utf-8')
        print(decryptSalt)
        cur.execute(f"insert into users(username, password) values('{user_name}', '{decryptSalt}');")
        global_db_con.commit()
        token = JWT_Token(user_name)
        return jsonify(token)
    else:
        print("username already used, choose another")
        return make_response(
            'Username already exists',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'})


@app.route('/purchase', methods=['POST'])
def purchase():
    passedJWT = request.form['jwt']
    book = request.form['name']
    decodedJWT = jwt.decode(passedJWT, JWT_SECRET, algorithms=["HS256"])
    print(decodedJWT)
    user_name = decodedJWT['username']
    cur = global_db_con.cursor()
    cur.execute(f"select * from users where username = '{user_name}';")
    db_user = cur.fetchone()[0]
    if(db_user == None):
        print("username not found")
        status = 401
        return jsonify(status)
    else:
        cur.execute(f"insert into purchases(u_id, b_id) values('{user_name}', '{book}');")
        global_db_con.commit()
        status = 200
        return jsonify(status)


app.run(host='0.0.0.0', port=80)
