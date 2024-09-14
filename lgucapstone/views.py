from django.http import HttpResponse
from django.template import loader
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import OrdinanceResolutionForm
from .firebase_config import firebase_db, storage
from firebase_admin import storage, credentials, db

import firebase_admin
import pyrebase
import json


config = {
    "apiKey": "AIzaSyAMwvUHsWFkTmJyfzuh4DxzOrMYEjcXHvI",
    "authDomain": "lgucapstoneproject-b94fe.firebaseapp.com",
    "databaseURL": "https://lgucapstoneproject-b94fe-default-rtdb.firebaseio.com",
    "projectId": "lgucapstoneproject-b94fe",
    "storageBucket": "lgucapstoneproject-b94fe.appspot.com",
    "messagingSenderId": "984934888272",
    "appId": "1:984934888272:web:e835b8e02ae708629a7255",
    "measurementId": "G-F84YQS756S"
}       

firebase=pyrebase.initialize_app(config) 
authe = firebase.auth()
database = firebase.database()





def home(request):
    return render(request,'home.html')

def lgucapstone(request):
    return render(request, 'landing.html')

# -->>>> USER SIGN UP 
def signup(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            # Create a new user with Firebase Authentication
            user = authe.create_user_with_email_and_password(email, password)
            
            # Get the user ID from the created user
            user_id = user['localId']
            
            # Set the user's role to "user" in the Firebase Realtime Database
            data = {
                "email": email,
                "role": "user"  # Automatically mark as "user"
            }
            database.child("users").child(user_id).set(data)
            
            # Redirect to login page or another page after successful sign-up
            return redirect('login')  # Replace with your login route
        except Exception as e:
            print(f"Error: {e}")  # Print the error for debugging
            messages.error(request, str(e))  # Display the error message to the user

    return render(request, 'signup.html')  # Replace with your sign-up template





# >>>>> USER LOG IN
def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            # Authenticate the user with Firebase Authentication
            user = authe.sign_in_with_email_and_password(email, password)
            
            # If authentication is successful, redirect to home
            return redirect('home')

        except Exception as e:
            error_response = json.loads(e.args[1])  # Get the error response in JSON format
            error_message = error_response.get('error', {}).get('message', '')

            # Map Firebase error codes to user-friendly messages
            if error_message == 'EMAIL_NOT_FOUND':
                messages.error(request, 'Please check your email and password.')
            elif error_message == 'INVALID_PASSWORD':
                messages.error(request, 'Please check your email and password.')
            elif error_message == 'USER_DISABLED':
                messages.error(request, 'This account has been disabled. Please contact support.')
            else:
                # A fallback for any other unknown errors
                messages.error(request, 'Please check your email and password.')

    return render(request, 'login.html')

def user_ordinance(request):
    return render(request,'user_ordinance.html')
def user_resolution(request):
    return render(request, 'user_resolution.html')
def user_services(request):
    return render(request, 'user_services.html')
def user_announcement(request):
    return render(request, 'user_announcement.html')

# >>>> ADMIN LOG IN
def admin_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            # Authenticate the user with Firebase Authentication
            admin = authe.sign_in_with_email_and_password(email, password)
            
            # Check if the user is successfully authenticated
            if admin:
                # Retrieve the authenticated user's email
                admin_email = email  # Use the email from the login attempt
                
                # Check the role of the authenticated user in the "admin" path
                user_role = database.child("admin").order_by_child("email").equal_to(admin_email).get().val()
                
                # Check if the user role is "admin"
                if user_role and next(iter(user_role.values()))['role'] == "admin":
                    return redirect('admin_dash')  # Replace with your admin dashboard route
                else:
                    messages.error(request, "You do not have admin access.")
                    authe.sign_out()  # Sign out the user if they are not an admin
        except Exception as e:
            print(f"Error: {e}")  # Print the error for debugging
           

    return render(request, 'adminlog.html')  # Replace with your admin login template

def admin_dash(request):
    return render(request, 'admindash.html')

# >>>>> RETRIEVE USERS DATAAA
def get_user_data(user_id):
    try:
        user_data = database.child("users").child(user_id).get().val()
        return user_data
    except Exception as e:
        print(f"Error retrieving user data: {e}")
        return None

def account_settings(request):
    if request.method == 'GET':
        user_id = request.session.get('user_id')  # Assuming user_id is stored in session
        if user_id:
            user_data = get_user_data(user_id)
            if user_data:
                return render(request, 'account_settings.html', {'user_data': user_data})
            else:
                messages.error(request, "Error retrieving user data.")
                return redirect('home')
        else:
            messages.error(request, "User not logged in.")
            return redirect('login')

# >>>> ADMIN DASHBOARD       
def dashboard(request):
    # Fetch ordinances from Firebase Realtime Database
    ordinances_ref = firebase_db.child('ordinances_resolutions').get()
    ordinances = ordinances_ref.val()  # This will be a dictionary of data from Firebase

    # Convert Firebase data into a list of dictionaries if needed
    if ordinances is not None:
        ordinances_list = [
            {
                'title': entry.get('title'),
                'year': entry.get('year'),
                'date_proposed': entry.get('date_proposed'),
                'date_approved': entry.get('date_approved'),
                'author': entry.get('author'),
                'file_type': entry.get('file_type'),
                'document_url': entry.get('document_url')
            }
            for entry in ordinances.values()
        ]
    else:
        ordinances_list = []

    context = {
        'ordinances': ordinances_list,
        # Add context data for charts if needed
    }
    return render(request, 'admindash.html', context)


# >>>>>>> ADDING ORDINANCE AND RESOLUTIONNN
def add_ordinance_resolution(request):
    if request.method == 'POST':
        form = OrdinanceResolutionForm(request.POST, request.FILES)
        if form.is_valid():
            # Extract form data
            title = form.cleaned_data['title']
            year = form.cleaned_data['year']
            date_proposed = form.cleaned_data['date_proposed']
            date_approved = form.cleaned_data['date_approved']
            author = form.cleaned_data['author']
            file_type = form.cleaned_data['file_type']
            document = request.FILES['document']  # Use the uploaded file

            # Determine the storage path based on file type
            if file_type == 'ordinance':
                storage_path = f'ordinances/{document.name}'
                db_path = 'ordinances'
            elif file_type == 'resolution':
                storage_path = f'resolutions/{document.name}'
                db_path = 'resolutions'
            else:
                storage_path = f'other/{document.name}'
                db_path = 'other_documents'

            # Upload the document to Firebase Storage
            document_url = upload_file_to_firebase_storage(document, storage_path)

            # Save data to Firebase Realtime Database based on file type
            firebase_db.child(db_path).push({
                'title': title,
                'year': year,
                'date_proposed': date_proposed.isoformat(),
                'date_approved': date_approved.isoformat(),
                'author': author,
                'file_type': file_type,
                'document_url': document_url  # Save the document URL
            })

            return redirect('admin_dash')  # Replace with your desired redirect
    else:
        form = OrdinanceResolutionForm()

    return render(request, 'admin_ordi_reso.html', {'form': form})


def upload_file_to_firebase_storage(file, storage_path):
    # Firebase Storage reference
    bucket = storage.bucket()
    blob = bucket.blob(storage_path)

    # Upload the file
    blob.upload_from_file(file)

    # Make the file publicly accessible
    blob.make_public()

    # Return the file's public URL
    return blob.public_url


def ordinances_view(request):
    ref = db.reference('ordinances_resolutions')  # Reference to your ordinances path in Firebase
    ordinances = ref.get()  # Fetch all ordinances
    
    # Prepare data for rendering in template
    context = {
        'ordinances': ordinances  # Passing ordinances data to template
    }
    
    return render(request, 'user_ordinance.html', context)