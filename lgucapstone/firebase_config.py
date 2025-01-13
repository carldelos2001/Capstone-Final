import firebase_admin
from firebase_admin import credentials, db, storage

# Path to your Firebase service account key JSON file
cred = credentials.Certificate('C:/Users/delos/capstoneproject/lgucapstoneproject/lgucapstone/json/lgucapstoneproject-b94fe-7c5fc7731eb2.json')
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://lgucapstoneproject-b94fe-default-rtdb.firebaseio.com',
    'storageBucket': 'lgucapstoneproject-b94fe.appspot.com'
})

# Get a reference to the database and storage
firebase_db = db.reference('/')
firebase_storage = storage.bucket()

