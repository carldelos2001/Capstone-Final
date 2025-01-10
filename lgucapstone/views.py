from django.http import HttpResponse
from django.template import loader
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import OrdinanceResolutionForm, StaffOrdinanceResolutionForm
from .firebase_config import firebase_db, storage
from firebase_admin import storage, credentials, db
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from firebase_admin.exceptions import FirebaseError
from firebase_admin import auth, db
from firebase_admin import db
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.auth. decorators import login_required

import bcrypt
import random
import string
import firebase_admin
import pyrebase
import json


import logging

logger = logging.getLogger(__name__)

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
    first_name = request.session.get('first_name', 'Guest')
    context = {
        'first_name': first_name,
    }
    return render(request, 'home.html', context)


def lgucapstone(request):
    return render(request, 'landing.html')

# -->>>> USER SIGN UP 
def signup(request):
    if request.method == 'POST':
        firstname = request.POST.get('first_name')
        lastname = request.POST.get('last_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            # Create a new user with Firebase Authentication
            user = authe.create_user_with_email_and_password(email, password)
            
            # Get the user ID from the created user
            user_id = user['localId']
            
            # Set the user's data in the 'accounts' database
            data = {
                "name": f"{firstname} {lastname}",
                "email": email,
                "password": password,  # Note: Storing passwords in plain text is not recommended
                "role": "user"  # Automatically mark as "user"
            }
            database.child("accounts").child(user_id).set(data)
            
            # Redirect to login page or another page after successful sign-up
            return redirect('main_login') 
        except Exception as e:
            print(f"Error: {e}")  # Print the error for debugging
            messages.error(request, str(e))  # Display the error message to the user

    return render(request, 'signup.html')  




# >>>>> USER LOG IN
def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            # Authenticate the user with Firebase Authentication
            user = authe.sign_in_with_email_and_password(email, password)
            user_id = user['localId']
            user_info = authe.get_account_info(user['idToken'])
            firstname = user_info['users'][0].get('displayName', 'Guest')

            # Fetch the user's role from Firebase Database
            role_ref = database.child('users').child(user_id).child('role').get()
            user_role = role_ref.val()

            # Store user details in session
            request.session['firstname'] = firstname
            request.session['email'] = email
            request.session['user_id'] = user_id
            request.session['role'] = user_role

            # Redirect based on role
            if user_role == 'admin':
                return redirect('admin_dash')
            elif user_role == 'user':
                return redirect('home')
            else:
                # Handle unexpected role
                messages.error(request, 'Invalid user role. Please contact support.')
                return redirect('login')

        except Exception as e:
            error_response = json.loads(e.args[1])
            error_message = error_response.get('error', {}).get('message', '')

            # Map Firebase error codes to user-friendly messages
            if error_message == 'EMAIL_NOT_FOUND':
                messages.error(request, 'Email not found.')
            elif error_message == 'INVALID_PASSWORD':
                messages.error(request, 'Invalid password.')
            elif error_message == 'USER_DISABLED':
                messages.error(request, 'Account disabled. Contact support.')
            else:
                messages.error(request, 'Login failed. Please try again.')

    return render(request, 'login.html')


@csrf_exempt
def get_user_info(request):
    if request.method == 'GET':
        try:
            user_id = request.session.get('user_id')  # Retrieve user ID from session
            if not user_id:
                return JsonResponse({'error': 'User not logged in'}, status=401)

            user_ref = db.reference(f'users/{user_id}')  # Reference to the user's data in Firebase
            user_data = user_ref.get()  # Fetch the user data

            if user_data:
                return JsonResponse({
                    'firstName': user_data.get('firstname'),
                    'lastName': user_data.get('lastname'),
                    'email': user_data.get('email'),
                })
            else:
                return JsonResponse({'error': 'User not found'}, status=404)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def update_user_info(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_id = request.session.get('user_id')
            if not user_id:
                return JsonResponse({'success': False, 'message': 'User not logged in'}, status=401)

            user_ref = db.reference(f"users/{user_id}")
            user_ref.update(data)
            
            return JsonResponse({'success': True})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'}, status=400)
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)



def user_ordinance(request):
    return render(request,'user_ordinance.html')

def user_resolution(request):
    return render(request, 'user_resolution.html')

def user_services(request):
    return render(request, 'user_services.html')

def user_announcement(request):
    return render(request, 'user_announcement.html')

def admin_report(request):
    return render(request, 'admin_report.html')

def admin_minutes(request):
    return render(request, 'admin_minutes1.html')

def admin_attendance(request):
    return render(request, 'admin_attendance.html')

def user_forgotpass(request):
    return render(request, 'user_forgotpass.html')

def admin_promanage(request):
    return render(request, 'admin_projectmanagement.html')

def admin_services(request):
    return render(request, 'admin_services.html')

def admin_staff_account(request):
    return render(request, 'admin_staff_account_create.html')

def admin_notice(request):
    return render(request, 'admin_notice1.html')

def staff_announcement(request):
    return render(request, 'staff_announcement.html')

def main_login(request):
    return render(request, 'mainlogin.html')

def staff_dash(request):
    return render(request, 'staff_dashboard.html')

def staff_report(request):
    return render(request, 'staff_report.html')

def staff_services(request):
    return render(request, 'staff_services.html')

def staff_feedback(request):
    return render(request, 'staff_feedback.html')

def staff_session(request):
    return render(request, 'staff_session.html')



def admin_serve(request):
    return render(request, 'admin_serve.html')

def user_feedback(request):
    return render(request, 'user_feedback.html')

def admin_feedback(request):
    return render(request, 'admin_feedback.html')

def admin_board(request):
    return render(request, 'admin_board.html')

# >>>> ADMIN LOG IN
def admin_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            # Authenticate the user with Firebase Authentication
            admin = authe.sign_in_with_email_and_password(email, password)
            
            # Retrieve the admin credentials stored in Firebase
            admin_data = database.child("admin").get().val()

            # Check if the email and password match the admin credentials
            if admin_data:
                if admin_data.get('email') == email and admin_data.get('password') == password:
                    # Check if the role is "admin"
                    if admin_data.get('role') == "admin":
                        return redirect('admin_dash')
                    else:
                        messages.error(request, "You do not have admin access.")
                else:
                    messages.error(request, "Invalid email or password.")
            else:
                messages.error(request, "Admin data not found.")
            
            return redirect('admin_login')  # Redirect back to login
            
        except Exception as e:
            print(f"Error: {e}")  
            messages.error(request, "Invalid login credentials.")
    
    return render(request, 'adminlog.html')


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
# 

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

# >>>>>>> ADDING ORDINANCE AND RESOLUTIONNN


def staff_ordi_reso(request):
    if request.method == 'POST':
        form = StaffOrdinanceResolutionForm(request.POST, request.FILES)
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

            return redirect('staff_dash')  # Replace with your desired redirect
    else:
        form = StaffOrdinanceResolutionForm()

    return render(request, 'staff_ordi_reso.html', {'form': form})


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


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


@csrf_exempt
def send_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            password = data.get('password')

            # Generate OTP (example code)
            otp = generate_otp()  # Implement OTP generation
            request.session['otp'] = otp
            request.session['otp_email'] = email
            request.session['first_name'] = first_name
            request.session['last_name'] = last_name

            # Send email with OTP
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}.',
                'stevendelosreyes123@gmail.com',
                [email],  # Send OTP to the retrieved email
                fail_silently=False,
            )

            return JsonResponse({'success': True})

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'}, status=400)
        except Exception as e:
            print(f'Error: {e}')
            return JsonResponse({'success': False, 'message': str(e)}, status=500)


@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            otp = data.get('otp')
            password = data.get('password')

            # Check OTP from session
            session_otp = request.session.get('otp')
            email = request.session.get('otp_email')

            # Debugging after retrieving session variables
            print(f'OTP: {otp}, Password: {password}')
            print(f"Session OTP: {session_otp}, Session Email: {email}")

            if not otp or not password:
                return JsonResponse({'success': False, 'message': 'OTP and password are required'}, status=400)

            if otp == str(session_otp):
                # OTP is correct, create Firebase user
                user = authe.create_user_with_email_and_password(email, password)
                
                # Store user in Firebase database
                user_id = user['localId']
                user_data = {
                    "firstname": request.session.get('first_name'),
                    "lastname": request.session.get('last_name'),
                    "email": email,
                    "role": "user"  # Automatically mark as "user"
                }
                database.child("accounts").child(user_id).set(user_data)

                # Clear OTP and email from session
                del request.session['otp']
                del request.session['otp_email']
                del request.session['first_name']
                del request.session['last_name']

                return JsonResponse({'success': True})

            else:
                return JsonResponse({'success': False, 'message': 'Invalid OTP'}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'}, status=400)
        except Exception as e:
            print(f'Error: {e}')
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
@csrf_exempt
def verify_otp_only(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            otp = data.get('otp')
            email = data.get('email')
            password = data.get('password')
            first_name = data.get('first_name') 
            last_name = data.get('last_name')
            role = data.get('role')

            # Check OTP from session
            session_otp = request.session.get('otp')

            # Validate required fields
            if not all([otp, email, password, first_name, last_name, role]):
                return JsonResponse({'success': False, 'message': 'Missing required fields'}, status=400)

            if otp != str(session_otp):
                return JsonResponse({'success': False, 'message': 'Invalid OTP'}, status=400)

            try:
                # Create Firebase user
                user = authe.create_user_with_email_and_password(email, password)
                user_id = user['localId']

                # Store user data in Firebase
                user_data = {
                    "firstname": first_name,
                    "lastname": last_name, 
                    "email": email,
                    "role": role
                }

                database.child("accounts").child(user_id).set(user_data)

                # Clear session data
                session_keys = ['otp', 'otp_email']
                for key in session_keys:
                    if key in request.session:
                        del request.session[key]

                return JsonResponse({'success': True})

            except Exception as e:
                print(f'Firebase Error: {str(e)}')
                return JsonResponse({
                    'success': False, 
                    'message': 'Failed to create account. Please try again.'
                }, status=400)

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid request format'}, status=400)
        except Exception as e:
            print(f'Error: {e}')
            return JsonResponse({
                'success': False,
                'message': 'An error occurred. Please try again.'
            }, status=500)

    return JsonResponse({'success': False, 'message': 'Method not allowed'}, status=405)
@csrf_exempt
def send_login_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                return JsonResponse({'success': False, 'message': 'Email and password are required'}, status=400)

            try:
                # Authenticate user
                user = authe.sign_in_with_email_and_password(email, password)

                # Generate OTP and store it in session
                otp = generate_otp()
                request.session['login_otp'] = otp
                request.session['login_email'] = email

                # Send OTP via email
                send_mail(
                    'Your Login OTP Code',
                    f'Your OTP code is {otp}.',
                    'stevendelosreyes123@gmail.com',
                    [email],
                    fail_silently=False,
                )

                return JsonResponse({'success': True})

            except Exception as e:
                print(f'Error: {e}')
                return JsonResponse({'success': False, 'message': 'Authentication failed'}, status=400)

        except Exception as e:
            print(f'Error: {e}')
            return JsonResponse({'success': False, 'message': 'Error sending OTP'}, status=500)

@csrf_exempt
def verify_login_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            otp = data.get('otp')

            # Check OTP from session
            session_otp = request.session.get('login_otp')
            email = request.session.get('login_email')

            if not otp:
                return JsonResponse({'success': False, 'message': 'OTP is required'}, status=400)

            if otp == str(session_otp):
                # OTP is correct
               
             

                # Clear OTP from session
                del request.session['login_otp']
                del request.session['login_email']

                return JsonResponse({'success': True})

            else:
                return JsonResponse({'success': False, 'message': 'Invalid OTP'}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'}, status=400)
        except Exception as e:
            print(f'Error: {e}')
            return JsonResponse({'success': False, 'message': str(e)}, status=500)

@csrf_exempt
def send_forgot_password_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')  # Retrieve email from the request body

            if not email:
                return JsonResponse({'success': False, 'message': 'Email is required'}, status=400)

            otp = generate_otp()  # Generate OTP

            request.session['forgot_password_otp'] = otp
            request.session['forgot_password_email'] = email

            # Send email with OTP
            send_mail(
                'Your Password Reset OTP Code',
                f'Your OTP for LGU Sangguniang Bayan Management Platform is {otp}. Please do not share this code with anyone for your security.',
                'stevendelosreyes123@gmail.com',
                [email],  # Send OTP to the retrieved email
                fail_silently=False,
            )

            return JsonResponse({'success': True})

        except Exception as e:
            print(f'Error: {e}')
            return JsonResponse({'success': False, 'message': 'Error sending OTP'}, status=500)

@csrf_exempt
def reset_password_with_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            otp = data.get('otp')
            new_password = data.get('new_password')
            email = data.get('email')

            # Check OTP from session
            session_otp = request.session.get('forgot_password_otp')
            session_email = request.session.get('forgot_password_email')

            if not otp or not new_password or not email:
                return JsonResponse({'success': False, 'message': 'OTP, new password, and email are required'}, status=400)

            if otp == str(session_otp) and email == session_email:
                try:
                    # Update the user's password in Firebase
                    accounts_ref = db.reference('accounts')
                    account_query = accounts_ref.order_by_child('email').equal_to(email).get()
                    
                    if account_query:
                        account_key = list(account_query.keys())[0]
                        accounts_ref.child(account_key).update({'password': new_password})

                        # Clear OTP from session
                        del request.session['forgot_password_otp']
                        del request.session['forgot_password_email']

                        return JsonResponse({'success': True})
                    else:
                        return JsonResponse({'success': False, 'message': 'Account not found'}, status=404)
                except Exception as firebase_error:
                    print(f'Firebase Error: {firebase_error}')
                    return JsonResponse({'success': False, 'message': 'Failed to update password'}, status=500)
            else:
                return JsonResponse({'success': False, 'message': 'Invalid OTP or email'}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'}, status=400)
        except Exception as e:
            print(f'Error: {e}')
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
        
@csrf_exempt
def submit_requirements(request):
    if request.method == 'POST':
        try:
            body_unicode = request.body.decode('utf-8')
            body_data = json.loads(body_unicode)  # Assuming you're sending JSON data
            
            # Log incoming request data
            print("Request Data:", body_data)

            documents = body_data.get('documents', [])
            appointment_date = body_data.get('appointmentDate')
            appointment_time = body_data.get('appointmentTime')

            # Validate required fields
            if not documents or not appointment_date or not appointment_time:
                return JsonResponse({'error': 'Missing required fields.'}, status=400)

            # Process your requirements here

            return JsonResponse({'success': 'Requirements submitted successfully.'})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON.'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=405)

def get_account_data(request):
    email = request.GET.get('email')
    if email:
        try:
            ref = db.reference('accounts')  # Points to your Firebase "accounts" folder
            accounts = ref.order_by_child('email').equal_to(email).get()
            
            for key, account_data in accounts.items():
                if account_data.get('email') == email:
                    return JsonResponse(account_data, safe=False)
            
            return JsonResponse({"error": "Account not found."}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request."}, status=400)

def get_user_data(request):
    email = request.GET.get('email')
    if email:
        try:
            ref = db.reference('accounts')  # Points to your Firebase "accounts" folder
            accounts = ref.order_by_child('email').equal_to(email).get()
            
            for key, account_data in accounts.items():
                if account_data.get('email') == email:
                    return JsonResponse(account_data, safe=False)
            
            return JsonResponse({"error": "Account not found."}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request."}, status=400)


@csrf_exempt

def admin_login_view(request):
    if request.method == 'POST':
        try:
            # Parse the request body to get the email and password
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')
            
            ref = db.reference('accounts')  
            accounts = ref.order_by_child('email').equal_to(email).get()
            
            if not accounts:
                return JsonResponse({'success': False, 'message': 'Invalid email or password'}, status=400)

            for key, account in accounts.items():
                role = account.get('role')

                if role == 'user':
                    try:
                        # Authenticate user with Firebase Authentication
                        authe.sign_in_with_email_and_password(email, password)
                        return JsonResponse({'success': True, 'redirect_url': '/home/'})
                    except:
                        return JsonResponse({'success': False, 'message': 'Invalid email or password'}, status=400)
                elif role == 'admin':
                    if account.get('password') == password:
                        return JsonResponse({'success': True, 'redirect_url': '/admin_dash/'})
                elif role == 'staff':
                    if account.get('password') == password:
                        return JsonResponse({'success': True, 'redirect_url': '/staff_dash/'})
                else:
                    return JsonResponse({'success': False, 'message': 'Invalid role'}, status=403)

            # If we've gone through all accounts and haven't returned, the credentials are incorrect
            return JsonResponse({'success': False, 'message': 'Invalid email or password'}, status=400)
        
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'}, status=400)
        except FirebaseError as e:
            return JsonResponse({'success': False, 'message': f'Firebase error: {str(e)}'}, status=500)
        except Exception as e:
            print(f'Error: {e}')  # Log the error for debugging
            return JsonResponse({'success': False, 'message': 'An error occurred. Please try again.'}, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)
@csrf_exempt
def verify_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                return JsonResponse({'success': False, 'message': 'Email and password are required'}, status=400)

            # Query Firebase for the account
            ref = db.reference('accounts')
            accounts = ref.order_by_child('email').equal_to(email).get()

            if not accounts:
                return JsonResponse({'success': False, 'message': 'Account not found'}, status=404)

            # Check if password matches
            for account in accounts.values():
                if account.get('password') == password:
                    return JsonResponse({'success': True})
                break

            return JsonResponse({'success': False, 'message': 'Invalid password'}, status=401)

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'}, status=400)
        except Exception as e:
            print(f'Error verifying password: {e}')
            return JsonResponse({'success': False, 'message': 'An error occurred'}, status=500)

    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

@csrf_exempt
def send_email_to_officials(request):
    if request.method == 'POST':
        try:
            # Parse request data
            data = json.loads(request.body)
            notice_id = data.get('notice_id')

            if not notice_id:
                return JsonResponse({'success': False, 'message': 'Notice ID is required'}, status=400)

            # Retrieve officials from Firebase
            try:
                ref = db.reference('officials')
                officials = ref.get()
            except Exception as e:
                print(f"Firebase error getting officials: {str(e)}")  # Debug logging
                return JsonResponse({'success': False, 'message': f'Error accessing Firebase: {str(e)}'}, status=500)

            if not officials:
                return JsonResponse({'success': False, 'message': 'No officials found.'}, status=404)

            # Get notice data from Firebase first
            try:
                notice_ref = db.reference(f'notices/{notice_id}')
                notice = notice_ref.get()
                
                if not notice:
                    return JsonResponse({'success': False, 'message': f'Notice with ID {notice_id} not found'}, status=404)
            except Exception as e:
                print(f"Firebase error getting notice: {str(e)}")  # Debug logging
                return JsonResponse({'success': False, 'message': f'Error retrieving notice: {str(e)}'}, status=500)

            

            # Send email to each official
            email_errors = []
            successful_emails = []
            for official_id, official_data in officials.items():
                email = official_data.get('email')
                if not email:
                    continue  # Skip officials without an email

                try:
                    # Prepare subsection HTML with error handling
                    adoptionMinutesHtml = ''
                    if notice.get('adoptionMinutesSubsections'):
                        for i, content in enumerate(notice['adoptionMinutesSubsections']):
                            if content:  # Only add if content exists
                                adoptionMinutesHtml += f'<div>6.{i+1} {content}</div>'

                    communicationsHtml = ''
                    if notice.get('communicationsSubsections'):
                        for i, content in enumerate(notice['communicationsSubsections']):
                            if content:
                                communicationsHtml += f'<div>7.{i+1} {content}</div>'

                    committeeReportHtml = ''
                    if notice.get('committeeReportSubsections'):
                        for i, content in enumerate(notice['committeeReportSubsections']):
                            if content:
                                committeeReportHtml += f'<div>8.{i+1} {content}</div>'

                    firstReadingHtml = ''
                    if notice.get('firstReadingSubsections'):
                        for i, content in enumerate(notice['firstReadingSubsections']):
                            if content:
                                firstReadingHtml += f'<div>9.{i+1} {content}</div>'

                    # Prepare email content using Django template
                    context = {
                        'notice': notice,
                        
                        'adoptionMinutesHtml': adoptionMinutesHtml,
                        'communicationsHtml': communicationsHtml, 
                        'committeeReportHtml': committeeReportHtml,
                        'firstReadingHtml': firstReadingHtml
                    }
                    
                    try:
                        html_content = render_to_string('emailnotice1_template.html', context)
                    except Exception as template_error:
                        print(f"Template rendering error: {str(template_error)}")  # Debug logging
                        raise Exception(f"Failed to render email template: {str(template_error)}")

                    subject = f"Important Notice of Session (Minutes #{notice.get('minutesNo', '')})"
                    
                    try:
                        email_message = EmailMultiAlternatives(
                            subject=subject,
                            body="This is a plain text fallback for the email.",
                            from_email="stevendelosreyes123@gmail.com",
                            to=[email],
                        )
                        email_message.attach_alternative(html_content, "text/html")
                        email_message.send()
                        successful_emails.append(email)
                    except Exception as email_error:
                        print(f"Email sending error: {str(email_error)}")  # Debug logging
                        raise Exception(f"Failed to send email: {str(email_error)}")
                        
                except Exception as e:
                    print(f"Detailed email error for {email}: {str(e)}")  # Debug logging
                    email_errors.append(f"Failed to send email to {email}: {str(e)}")

            # Return response with both successes and failures
            response = {
                'success': len(successful_emails) > 0,
                'message': f'Emails sent: {len(successful_emails)}, Failed: {len(email_errors)}',
                'successful_emails': successful_emails,
                'failed_emails': email_errors,
                'total_sent': len(successful_emails),
                'total_failed': len(email_errors)
            }
            
            # Choose status code based on outcome
            if len(email_errors) == 0:
                return JsonResponse(response, status=200)
            elif len(successful_emails) > 0:
                return JsonResponse(response, status=207)  # Partial success
            else:
                return JsonResponse(response, status=500)  # Complete failure

        except json.JSONDecodeError:
            print("Invalid JSON format in request")  # Debug logging
            return JsonResponse({'success': False, 'message': 'Invalid JSON format in request body.'}, status=400)
        except Exception as e:
            print(f"Unexpected error in main try block: {str(e)}")  # Debug logging
            return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'}, status=500)
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method. Only POST is allowed.'}, status=405)
    
@csrf_exempt
def send_email_to_officials_minutes(request):
    if request.method == 'POST':
        try:
            # Parse request data
            data = json.loads(request.body)
            minutes_id = data.get('minutes_id')
            attendance = data.get('attendance')

            if not minutes_id:
                return JsonResponse({'success': False, 'message': 'Minutes ID is required'}, status=400)

            # Retrieve officials from Firebase
            try:
                ref = db.reference('officials')
                officials = ref.get()
            except Exception as e:
                print(f"Firebase error getting officials: {str(e)}")  # Debug logging
                return JsonResponse({'success': False, 'message': f'Error accessing Firebase: {str(e)}'}, status=500)

            if not officials:
                return JsonResponse({'success': False, 'message': 'No officials found.'}, status=404)

            # Get minutes data from Firebase first
            try:
                minutes_ref = db.reference(f'minutes/{minutes_id}')
                minutes = minutes_ref.get()
                
                if not minutes:
                    return JsonResponse({'success': False, 'message': f'Minutes with ID {minutes_id} not found'}, status=404)
            except Exception as e:
                print(f"Firebase error getting minutes: {str(e)}")  # Debug logging
                return JsonResponse({'success': False, 'message': f'Error retrieving minutes: {str(e)}'}, status=500)

            # Send email to each official
            email_errors = []
            successful_emails = []
            for official_id, official_data in officials.items():
                email = official_data.get('email')
                if not email:
                    continue  # Skip officials without an email

                try:
                    # Prepare subsection HTML with error handling
                    adoptionMinutesHtml = ''
                    if minutes.get('adoptionMinutesSubsections'):
                        for i, content in enumerate(minutes['adoptionMinutesSubsections']):
                            if content:  # Only add if content exists
                                adoptionMinutesHtml += f'<div>6.{i+1} {content}</div>'

                    communicationsHtml = ''
                    if minutes.get('communicationsSubsections'):
                        for i, content in enumerate(minutes['communicationsSubsections']):
                            if content:
                                communicationsHtml += f'<div>7.{i+1} {content}</div>'

                    committeeReportHtml = ''
                    if minutes.get('committeeReportSubsections'):
                        for i, content in enumerate(minutes['committeeReportSubsections']):
                            if content:
                                committeeReportHtml += f'<div>8.{i+1} {content}</div>'

                    firstReadingHtml = ''
                    if minutes.get('firstReadingSubsections'):
                        for i, content in enumerate(minutes['firstReadingSubsections']):
                            if content:
                                firstReadingHtml += f'<div>9.{i+1} {content}</div>'

                    # Prepare email content using Django template
                    context = {
                        'minutes': minutes,
                        'attendance': attendance,
                        'adoptionMinutesHtml': adoptionMinutesHtml,
                        'communicationsHtml': communicationsHtml, 
                        'committeeReportHtml': committeeReportHtml,
                        'firstReadingHtml': firstReadingHtml
                    }
                    
                    try:
                        html_content = render_to_string('emailminutes1_template.html', context)
                    except Exception as template_error:
                        print(f"Template rendering error: {str(template_error)}")  # Debug logging
                        raise Exception(f"Failed to render email template: {str(template_error)}")

                    subject = f"Minutes of the Session: Minutes #{minutes.get('minutesNo', '')}"
                    
                    try:
                        email_message = EmailMultiAlternatives(
                            subject=subject,
                            body="This is a plain text fallback for the email.",
                            from_email="stevendelosreyes123@gmail.com",
                            to=[email],
                        )
                        email_message.attach_alternative(html_content, "text/html")
                        email_message.send()
                        successful_emails.append(email)
                    except Exception as email_error:
                        print(f"Email sending error: {str(email_error)}")  # Debug logging
                        raise Exception(f"Failed to send email: {str(email_error)}")
                        
                except Exception as e:
                    print(f"Detailed email error for {email}: {str(e)}")  # Debug logging
                    email_errors.append(f"Failed to send email to {email}: {str(e)}")

            # Return response with both successes and failures
            response = {
                'success': len(successful_emails) > 0,
                'message': f'Emails sent: {len(successful_emails)}, Failed: {len(email_errors)}',
                'successful_emails': successful_emails,
                'failed_emails': email_errors,
                'total_sent': len(successful_emails),
                'total_failed': len(email_errors)
            }
            
            # Choose status code based on outcome
            if len(email_errors) == 0:
                return JsonResponse(response, status=200)
            elif len(successful_emails) > 0:
                return JsonResponse(response, status=207)  # Partial success
            else:
                return JsonResponse(response, status=500)  # Complete failure

        except json.JSONDecodeError:
            print("Invalid JSON format in request")  # Debug logging
            return JsonResponse({'success': False, 'message': 'Invalid JSON format in request body.'}, status=400)
        except Exception as e:
            print(f"Unexpected error in main try block: {str(e)}")  # Debug logging
            return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'}, status=500)
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method. Only POST is allowed.'}, status=405)