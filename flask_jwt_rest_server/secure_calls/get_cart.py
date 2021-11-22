from flask import request, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token
import json
from tools.logging import logger

def handle_request():
    logger.debug("Get Cart Handle Request")
    cur = g.db.cursor()
    try:
        cur.execute("select * from purchases;")
        purchases=cur.fetchall()
        cur.close()
    except:
        print("cannot read from database")
        return json_response(data={"message": "Error occured while reading from database."}, status=500)

    count=1
    message = '{"purchases":['
    for b in purchases:

        if count < len(purchases) :
            message += '{"title":"'+str(b[1]) + '","price":"' + str(b[2]) +'"},'
            count=count+1
        else:
            message += '{"title":"'+str(b[1]) +'","price":"' + str(b[2]) +'"}'
    message += "]}"
    print(message)
    return json_response( token = create_token(  g.jwt_data ) , data = json.loads(message))
  
