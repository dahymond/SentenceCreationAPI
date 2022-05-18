from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt



app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SentencesDatabase
users = db["Users"]

def UserExist(username):
    if users.count_documents({"Username":username}) == 0:
        return False
    else:
        return True

def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw)==hashed_pw:
        return True
    else:
        return False

def verifiedCredentials(username, password):
    if not UserExist(username):
        return errorMessageHandler(301, "Username already exist, Invalid username"), True

    correct_pw =  verifyPw(username, password)
    if not correct_pw:
        return errorMessageHandler(302, "Invalid password"), True
    return None, False

def errorMessageHandler(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return jsonify(retJson)

def countTokens(username):
    token = users.find({
        "Username": username
    })[0]["Token"]
    return token



class Register(Resource):
    def post(self):
        #Step1 is to get posted data by the user
        postedData = request.get_json()

        #Get the  data
        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            retJson = {
                "status": 301,
                "message": "Username already registered"
            }
            return jsonify(retJson)

        #hash(pasword+salt) = eovwndjvwojhweg87244kjb4
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #store username and passowrd into the database]
        users.insert_one({
            "Username": username,
            "Password": "hashed_pw",
            "Sentence": " ",
            "Token": 6
        })

        retJson = {
            "status":200,
            "msg": "You successfully signed up for the API"
        }
        return jsonify(retJson)

class Store(Resource):
     def post(self):
         #get the posted data
         postedData = request.get_json()

         # Read the data
         username = postedData["username"]
         password = postedData["password"]
         sentence = postedData["sentence"]

         #check for errors/verify username and password matches
         correct_pw = verifyPw(username, password)

         if not  correct_pw:
             return errorMessageHandler(302, "invalid password")

         #verify the username has enough tokens
         num_tokens = countTokens(username)
         if num_tokens <= 0:
             return errorMessageHandler(301, "Insufficient Token")

         #store the sentence, take 1 token away adn return 200 OK
         users.update_one({
             "Username: username"
         }, {
             "$set":{"Sentence":sentence,
                     "Tokens": num_tokens-1
                     }
         })
         errorMessageHandler(200, "Sentence saved successfully")

api.add_resource(Register, '/register')
api.add_resource(Store, '/store')

if __name__=="__main__":
    app.run(host='0.0.0.0')