#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        
        errors = {}
        if 'username' not in json or not json['username']:
            errors['username'] = 'Username is required.'
        if 'password' not in json or not json['password']:
            errors['password'] = 'Password is required.'

        if errors:
            return make_response({"errors": errors}, 422)
        
        hashed_password = generate_password_hash(json['password'])
        
        
        user = User(username=json['username'])
        user.password_hash = hashed_password
        user.image_url = json.get('image_url', '')
        user.bio = json.get('bio', '')
        
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        
        return make_response({
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 201)
        

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            if user:
                return make_response({
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }, 200)
            
            else:
                return make_response({"error": "Unauthorized access"}, 401)
        
        return make_response({"error": "Unauthorized access"}, 401)
            

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
         
        user = User.query.filter(User.username == username).first()
        
        if user and user.authenticate(password):
            session['user_id'] =  user.id
            
            return make_response({
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200)
        
        return make_response({"error": "Invalid username or password"}, 401)
        

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        
        return make_response({"error": "Unauthorized access"}, 401)
    

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return make_response({"error": "Unauthorized access"}, 401)
        
        recipes = [{
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user_id": recipe.user_id,
            } for recipe in Recipe.query.all()]

        return make_response(recipes, 200)
    
    def post(self):
        if not session.get('user_id'):
            return make_response({"error": "Unauthorized access"}, 401)
        
        data = request.get_json()
        
        if 'title' not in data or 'instructions' not in data:
            return make_response({"error": "Invalid recipe data"}, 422)

        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data.get('minutes_to_complete', 0),
                user_id=session['user_id']
            )
            
            db.session.add(new_recipe)
            db.session.commit()

            response = {
                "id": new_recipe.id,
                "title": new_recipe.title,
                "instructions": new_recipe.instructions,
                "minutes_to_complete": new_recipe.minutes_to_complete,
                "user_id": new_recipe.user_id,
            }

            return make_response(response, 201)
        except Exception as e:
            return make_response({"error": str(e)}, 500)
        
        

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)