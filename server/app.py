#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):

    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        errors = {}
        existing_user = User.query.filter(User.username == username).first()
        if existing_user or not username:
            errors['username'] = 'Username is required or username exists'
        if not password:
            errors['password'] = 'Password is required.'
        if errors:
            return make_response(jsonify({"errors": errors}), 422)
        user = User(
            username = username,
            image_url = image_url,
            bio = bio
        )
        user.password_hash = password
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id

        return make_response(jsonify(user.to_dict()), 201)

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response(jsonify({"error": "Unauthorized"}), 401)
        user = User.query.filter(User.id == user_id).first()
        if user:
            return make_response(jsonify(user.to_dict()), 200)
        else:
            return make_response(jsonify({"error": "Unauthorized"}), 401)

class Login(Resource):
    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return make_response(jsonify(user.to_dict()), 200)
        
        return make_response(jsonify({'error': 'Invalid username or password'}), 401)

class Logout(Resource):
    def delete(self):
        if 'user_id' not in session or session['user_id'] is None:
            return make_response(jsonify({'error': 'Unauthorized'}), 401)
        session['user_id'] = None
        return make_response(jsonify({"m):essage": "Logged out successfully"}), 200)


class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            response_body = {
                "error": "Unauthorised"
            }
            return make_response(jsonify(response_body), 401)
        recipes = Recipe.query.filter_by(user_id = session.get('user_id')).all()
        recipes_list = [recipe.to_dict() for recipe in recipes]
        return make_response(jsonify(recipes_list), 200)
    
    def post(self):
        data = request.json
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        errors = {}
        if not title:
            errors['title'] = 'Title is required.'
        if not instructions:
            errors['instructions'] = 'Instructions are required.'
        if minutes_to_complete is None or not isinstance(minutes_to_complete, int) or minutes_to_complete <= 0:
            errors['minutes_to_complete'] = 'Minutes to complete must be a positive integer.'
        if errors:
            return make_response(jsonify({"errors": errors}), 422)
        
        user_id = session.get('user_id')
        if not user_id:
            return make_response(jsonify({"errors": "Unauthorized"}), 401)
        try:
            recipe = Recipe(
                title = title,
                instructions = instructions,
                minutes_to_complete = minutes_to_complete,
                user_id = user_id
            )
            db.session.add(recipe)
            db.session.commit()
        except Exception as e:
            return make_response(jsonify({"error": "Failed to create recipe"}), 422)

        return make_response(jsonify(recipe.to_dict()), 201)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)