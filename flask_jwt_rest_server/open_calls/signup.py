from flask import request, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token
from db_con import get_db_instance, get_db
import psycopg2
from tools.logging import logger
import bcrypt

global JWT

def handle_request():
    logger.debug("Signup Handle Request")
    #use data here to auth the user
    
    password_from_user_form = request.form['password']
    user = {
            "sub" : request.form['username'] #sub is used by pyJwt as the owner of the token
            }
    cur = g.db.cursor()
    cur.execute("select * from users where username = '" + request.form['username'] + "';")
    dbcred = cur.fetchone()
    #print(dbcred)

    if dbcred is not None:
        logger.debug("User already Exists!")
        return json_response( data={"message": "Username already Exists: " + request.form['username']}, status = 404)
    else:
        #print("in else statement!")
        #salt password for new user
        salt_bae = bcrypt.hashpw(bytes(password_from_user_form, "utf-8"), bcrypt.gensalt(10))
        logger.debug(salt_bae)
        cur.execute("insert into users (username, password) values ('"+request.form['username']+"', '"+ salt_bae.decode("utf-8") +"');")
        cur.close()
        g.db.commit()
        logger.debug("Successful Signup, Welcome, " + request.form['username'])
        return json_response( token = create_token(user) , authenticated =True)

    return json_response( token = create_token(user) , authenticated = False)
