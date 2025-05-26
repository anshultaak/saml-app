from flask import Flask
from mongoengine import connect, Document, StringField
import mongomock

# Create a simple test app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-key'
app.config['TESTING'] = True

# Connect to mock MongoDB
connect('sso_test', mongo_client_class=mongomock.MongoClient)

# Define a simple model
class TestUser(Document):
    username = StringField(required=True)
    email = StringField(required=True)

# Create a route
@app.route('/')
def index():
    return 'SSO Application Test - MongoDB Connection Working'

@app.route('/create_user')
def create_user():
    user = TestUser(username='testuser', email='test@example.com')
    user.save()
    return f'User created: {user.username} ({user.email})'

@app.route('/users')
def list_users():
    users = TestUser.objects.all()
    return '<br>'.join([f'{user.username} ({user.email})' for user in users])

if __name__ == '__main__':
    app.run(debug=True)
