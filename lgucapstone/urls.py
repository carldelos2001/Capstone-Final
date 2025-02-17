from django.urls import path
from . import views
from .views import send_otp
from .views import verify_otp
from .views import verify_login_otp
from .views import send_login_otp
from .views import get_user_info
from .views import update_user_info
from .views import submit_requirements
from .views import verify_otp_only
from .views import verify_password
from .views import send_email_to_officials
from .views import send_email_to_officials_minutes


urlpatterns = [
    path('', views.lgucapstone, name='lgucapstone'),
    path('signup', views.signup, name='signup'),
    path('login', views.login, name='login'),
    path('home', views.home, name='home'),
    path('user_ordinance', views.user_ordinance, name='user_ordinance'),
    path('user_resolution', views.user_resolution, name='user_resolution'),
    path('user_services', views.user_services, name='user_services'),
    path('user_announcement', views.user_announcement, name='user_announcement'),
    path('user_feedback', views.user_feedback, name='user_feedback'),

    path('admin_login', views.admin_login, name='admin_login'),
    path('admin_dash', views.admin_dash, name='admin_dash'),
    path('account_settings', views.account_settings, name='account_settings'),
    path('add_ordinance_resolution', views.add_ordinance_resolution, name='add_ordinance_resolution'),
    path('admin_report', views.admin_report, name='admin_report'),
    path('admin_minutes', views.admin_minutes, name='admin_minutes'),
    path('admin_attendance', views.admin_attendance, name='admin_attendance'),
    path('admin_services', views.admin_services, name='admin_services'),
    path('admin_staff_account', views.admin_staff_account, name='admin_staff_account'),
    path('admin_notice', views.admin_notice, name='admin_notice'),
    path('main_login/', views.main_login, name='main_login'),
    path('admin_serve', views.admin_serve, name='admin_serve'),
    path('admin_feedback', views.admin_feedback, name='admin_feedback'),
    path('admin_board', views.admin_board, name='admin_board'),

    path('admin_login_view/', views.admin_login_view, name='admin_login_view'),

    path('staff_announcement', views.staff_announcement, name='staff_announcement'),
    path('staff_dash', views.staff_dash, name='staff_dash'),
    path('staff_report', views.staff_report, name='staff_report'),
    path('staff_services', views.staff_services, name='staff_services'),
    path('staff_feedback', views.staff_feedback, name='staff_feedback'),
    path('staff_session', views.staff_session, name='staff_session'),
    path('staff_ordi_reso', views.staff_ordi_reso, name='staff_ordi_reso'),

    path('send-otp/', send_otp, name='send_otp'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('verify-otp-only/', verify_otp_only, name='verify_otp_only'),
    path('verify-password/', verify_password, name='verify_password'),
    

    path('send_email_to_officials/', send_email_to_officials, name='send_email_to_officials'),
    path('send_email_to_officials_minutes/', send_email_to_officials_minutes, name='send_email_to_officials_minutes'),

    path('send_login_otp/', send_login_otp, name='send_login_otp'),
    path('verify_login_otp/', verify_login_otp, name='verify_login_otp'),
    path('send_forgot_password_otp/', views.send_forgot_password_otp, name='send_forgot_password_otp'),
    path('reset_password_with_otp/', views.reset_password_with_otp, name='reset_password_with_otp'),

    path('user_forgotpass', views.user_forgotpass, name='user_forgotpass'),

    path('admin_promanage', views.admin_promanage, name='admin_promanage'),
    path('get_user_info/', get_user_info, name='get_user_info'),
    path('update_user_info/', update_user_info, name='update_user_info'),
    path('api/submit-requirements/', submit_requirements, name='submit_requirements'),
    path('get_account_data/', views.get_account_data, name='get_account_data'),
    path('get_user_data/', views.get_user_data, name='get_user_data'),
    
]