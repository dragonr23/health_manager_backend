from app import app, db
from flask import request, jsonify
from app.models import User, Record
import time
import jwt

@app.route('/')
def index():
    return ''

@app.route('/authenticate/register', methods=['POST'])
def register():
    try:
        token = request.headers.get('token')
        #decode the token back to a dictionary
        data = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithm=['HS256']
        )
        print(data)
        #create the user and save
        user = User(email=data['email'], username=data['username'])
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'success'})
    except:
        return jsonify({'message': 'Error #001: User not created'})


@app.route('/authenticate/login', methods=['GET'])
def login():
    try:
        token = request.headers.get('token')
        print(token)
        #decode the token back to a dictionary
        data = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithm=['HS256']
        )
        print(data)
        #query db to get user and check password_hash
        user = User.query.filter_by(email=data['email']).first()
        if user is None or not user.check_password(data['password']):
                return jsonify({'message' : 'Error #002: Invalid Credentials'})

        #create a token for that user and return it
        return jsonify({ 'message' : 'success', 'username': user.username, 'token': user.get_token()})
    except:
        return jsonify({'message': 'Error #003: Failure to login'})



@app.route('/api/login', methods=['GET'])
def data():
    try:
        token = request.headers.get('token')
        #get user id or None
        user = User.verify_token(token)
        if not user:
            return jsonify({ 'message' : 'Error #004: Invalid User'})
        #this is usually where you would query the database with user_id that we got back from the verify token method, and create a new token to be passed back with encrypted information
        data = {
            'logged - in' : 'yes'
        }
        return jsonify({ 'info': data })
    except:
        return jsonify({ 'message' : 'Error #005: Invalid Token'})

#TODO: need to retrieve the user for the user_id for the record
@app.route('/api/retrieve', methods=['GET'])
def retrieve():
    id = request.headers.get('id')
    username = request.headers.get('username')
    email = request.headers.get('email')

    user = []
    if email:
        result = User.query.filter_by(email=email).first()

        if result == None:
            return jsonify({'success': 'No Users Found'})


        user = {
            'id': result.id,
            'username': result.username,
            'email': result.email,
        }

        user.append(user)

        return jsonify({
            'success': 'Retrieved Users',
            'user': user
        })


@app.route('/api/saverecord', methods=['POST'])
def saverecord():

    try:
        user_id = request.headers.get('user_id')
        date = request.headers.get('date')
        sleep = request.headers.get('sleep')
        nutrition = request.headers.get('nutrition')
        hydration = request.headers.get('hydration')
        family = request.headers.get('family')
        friends = request.headers.get('friends')
        intimate = request.headers.get('intimate')
        vigorous = request.headers.get('vigorous')
        movement = request.headers.get('movement')
        standing = request.headers.get('standing')
        needed_work = request.headers.get('needed_work')
        creative_work = request.headers.get('creative_work')
        relaxed_state = request.headers.get('relaxed_state')
        substance_abuse = request.headers.get('substance_abuse')
        unhealthy_relationships = request.headers.get('unhealthy_relationships')
        self_harm = request.headers.get('self_harm')
        mental_clarity = request.headers.get('mental_clarity')
        notes = request.headers.get('notes')


        record = Record(user_id=user_id, date=date, sleep=sleep, nutrition=nutrition, hydration=hydration, family=family, friends=friends, intimate=intimate, vigorous=vigorous, movement=movement, standing=standing, needed_work=needed_work, creative_work=creative_work, relaxed_state=relaxed_state, substance_abuse=substance_abuse, unhealthy_relationships=unhealthy_relationships, self_harm=self_harm, mental_clarity=mental_clarity, notes=notes)

        db.session.add(record)
        db.session.commit()

        return jsonify({
            'success': 'Record Created'
        })
    except:
        return jsonify({
            'error': 'Record Not Created'
        })

#TO DO: Everything
@app.route('/api/retrieverecords', methods=['GET'])
def retrieverecords():
    user_id = request.headers.get('user_id')
    date = request.headers.get('date')
    sleep = request.headers.get('sleep')
    nutrition = request.headers.get('nutrition')
    hydration = request.headers.get('hydration')
    family = request.headers.get('family')
    friends = request.headers.get('friends')
    intimate = request.headers.get('intimate')
    vigorous = request.headers.get('vigorous')
    movement = request.headers.get('movement')
    standing = request.headers.get('standing')
    needed_work = request.headers.get('needed_work')
    creative_work = request.headers.get('creative_work')
    relaxed_state = request.headers.get('relaxed_state')
    substance_abuse = request.headers.get('substance_abuse')
    unhealthy_relationships = request.headers.get('unhealthy_relationships')
    self_harm = request.headers.get('self_harm')
    mental_clarity = request.headers.get('mental_clarity')
    notes = request.headers.get('notes')

    if user_id:
        results = Record.query.filter_by(user_id=user_id).all()


    if results == []:
        return jsonify({ 'success': 'No Records'})

    records = []

    for result in results:
        record = {
            'user_id': result.user_id,
            'date': result.date,
            'sleep': result.sleep,
            'nutrition': result.nutrition,
            'hydration': result.hydration,
            'family': result.family,
            'friends': result.friends,
            'intimate': result.intimate,
            'vigorous': result.vigorous,
            'movement': result.movement,
            'standing': result.standing,
            'needed_work': result.needed_work,
            'creative_work': result.creative_work,
            'relaxed_state': result.relaxed_state,
            'substance_abuse': result.substance_abuse,
            'unhealthy_relationships': result.unhealthy_relationships,
            'self_harm': result.self_harm,
            'mental_clarity': result.mental_clarity,
            'notes': result.notes
        }

        records.append(record)

    return jsonify({
        'success': 'Retrieved Record',
        'records': records
    })
