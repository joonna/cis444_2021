from flask import request, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token
from db_con import get_db_instance, get_db
import psycopg2    
from tools.logging import logger
import bcrypt

global JWT

def handle_request():
    logger.debug("Login Handle Request")
    #use data here to auth the user

    password_from_user_form = request.form['password']
    user = {
            "sub" : request.form['username'] #sub is used by pyJwt as the owner of the token
            }
    cur = g.db.cursor()
    cur.execute("select * from users where username = '" + request.form['username'] + "';")
    dbcred = cur.fetchone()
    cur.close()
    #print(dbcred)
    
    if dbcred is None:
        logger.debug("No User")
        return json_response( data={"message": "Invalid user name: " + str(request.form['username'])}, status = 404)
    else:
        #print("in else statement")
        if bcrypt.checkpw(bytes(request.form['password'], "utf-8"), bytes(dbcred[2], "utf-8")) == True:
            logger.debug("Successful Login, : " + str(request.form['username']))

        else:
            #print("Invalid password")

            return json_response( data={"message": "Incorrect Password"}, status = 404)

    return json_response( token = create_token(user) , authenticated = True)
    
    if not user:
        return json_response(status_=401, message = 'Invalid credentials', authenticated =  False )

    return json_response( token = create_token(user) , authenticated = False)

