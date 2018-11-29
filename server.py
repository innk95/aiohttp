import os
from aiohttp import web
from pymongo import MongoClient
import jwt
import hashlib, uuid

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'


client = MongoClient(
    os.environ['DB_PORT_27017_TCP_ADDR'],
    27017)
db = client['dev']

async def handle(request):
    return web.Response(text='server running')


async def auth(request):
    data =  await request.post()
    if not 'username' in data or not 'password' in data:
        return web.json_response({'error' : 'Нет данных'})

    user = db.users.find_one({'username': data['username']})
    if(user is None):
        #Хешируем пароль
        salt = uuid.uuid4().hex
        hashed_password = hashlib.sha256((data['password'] + salt).encode('utf-8')).hexdigest()
        payload = {
            'username' : data['username']
        }
        jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
        #Данные на сохранение
        sendData = {
            'username': data['username'],
            'token': jwt_token.decode('utf-8'),
            'salt' : salt,
            'hashed_password' : hashed_password
        }
        db.users.insert_one(sendData)
        return web.json_response({'token' : jwt_token.decode('utf-8')})
    else:
        hashed_password = hashlib.sha256((data['password'] + user['salt']).encode('utf-8')).hexdigest()
        if user['hashed_password'] == hashed_password:
            return web.json_response({'token' : user['token']})
        return web.json_response({'error' : 'wrong password'})


async def user(request):
    if request.rel_url.query['token'] is None:
        return web.json_response({'error' : 'Нет данных'})

    user = db.users.find_one({'token': request.rel_url.query['token']})
    if user is None:
        return web.json_response({'error': 'wrong token'})
    return web.json_response({'username': user['username']})


app = web.Application()
app.router.add_get('/', handle)
app.router.add_route('POST', '/auth/login', auth)
app.router.add_route('GET', '/user', user)

web.run_app(app, port=5856)