from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

from .models import Profile


def login_view(request):

    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')

        user = authenticate(
            request,
            username=email,
            password=password
        )

        if user is not None:
            auth_login(request, user)

            if request.POST.get('remember_me') != 'on':
                request.session.set_expiry(0)
            else:
                request.session.set_expiry(1209600)

            return redirect('dashboard')

        messages.error(request, 'Invalid email address or password.')

    return render(request, 'accounts/login.html')


def register_view(request):

    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':

        name = request.POST.get('name', '').strip()
        email = request.POST.get('email', '').strip().lower()
        phone = request.POST.get('phone', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if not all([name, email, phone, password, confirm_password]):
            messages.error(request, 'Please complete all fields.')

        elif password != confirm_password:
            messages.error(request, 'Passwords do not match.')

        elif User.objects.filter(email__iexact=email).exists():
            messages.error(request, 'Email is already registered.')

        else:
            try:
                validate_password(password)

                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    first_name=name
                )

                Profile.objects.create(
                    user=user,
                    phone_number=phone
                )

                messages.success(
                    request,
                    'Registration successful! Please log in.'
                )

                return redirect('login')

            except ValidationError as error:
                for message in error.messages:
                    messages.error(request, message)

    return render(request, 'accounts/register.html')


@login_required
def dashboard(request):

    if request.user.is_staff:
        return redirect('admin_dashboard')

    return render(request, 'accounts/user_dashboard.html')


@login_required
def admin_dashboard(request):

    if not request.user.is_staff:
        return redirect('dashboard')

    return render(request, 'accounts/admin_dashboard.html')


@login_required
def logout_view(request):

    if request.method == 'POST':
        logout(request)
        return redirect('login')

    return redirect('dashboard')
