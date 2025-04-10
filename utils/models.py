from flask_login import UserMixin
#---------------USER/PW STORAGE--------------#
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

from werkzeug.security import generate_password_hash

#print(generate_password_hash("admin"))
#print(generate_password_hash("user123"))
