# FLAW 4: Security Logging and Monitoring Failures (A09:2021)
# import logging
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
# FLAW 1: Broken Access Control (A01:2021)
# from django.views.decorators.cache import cache_control
from .models import Product
# FLAW 3: Identification and Authentication Failures (A07:2021)
# from django.contrib.auth.password_validation import validate_password
# from django.core.exceptions import ValidationError


# FLAW 4: Security Logging and Monitoring Failures (A09:2021)
# logger = logging.getLogger('shoppinglist')

@login_required
# FLAW 1: Broken Access Control (A01:2021)
# @cache_control(no_cache=True, must_revalidate=True, no_store=True)
def homePageView(request):
    if not request.user.is_authenticated:
        return redirect("login.html")

    products = Product.objects.filter(user=request.user)

    return render(request, 'index.html', {'products': products})

def loginPageView(request):
    # FLAW 2: Insecure Design (A04:2021)
    # Credentials should be sent using POST to avoid exposure in URLs.

    if request.GET.get("username") != None:  # if request.POST.get("username") != None:
        username = request.GET["username"] # username = request.POST["username"]
        password = request.GET["password"] # password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # FLAW 4: Security Logging and Monitoring Failures (A09:2021)
            # logger.info(f"User {username} logged in successfully.")
            return redirect("/")
        else:
            # FLAW 4: Security Logging and Monitoring Failures (A09:2021)
            # logger.warning(f"Failed login attempt for username: {username}")
            return render(request,'login.html')

    return render(request, 'login.html')
    
def createAccountPageView(request):
        
    if request.user.is_authenticated:
        return redirect("/")
    
    if request.method=="POST":
        
        username = request.POST["username"] 
        password = request.POST["password"]

        if not username or not password:
            # # FLAW 4: Security Logging and Monitoring Failures (A09:2021)
            # logger.warning("Account creation attempt with missing username or password.")
            return render(request, 'createaccount.html')
        
        try:
            # FLAW 4: Security Logging and Monitoring Failures (A09:2021)
            # and
            # FLAW 3: Identification and Authentication Failures (A07:2021)
        
            # validate_password(password)
            User.objects.create_user(username, "", password)

            # logger.info(f"User account created for username: {username}")
            return redirect("login")
        except: # except ValidationError as e:
            # logger.warning(f"Password validation failed for username: {username}, errors: {e.messages}")
            return render(request, 'createaccount.html') # return render(request, 'createaccount.html', {'errors': e.messages})

    
    return render(request,'createaccount.html')

def logoutPageView(request):
    logout(request)
    # FLAW 4: Security Logging and Monitoring Failures (A09:2021)
    # logger.info(f"User {username} logged out successfully.")
    return render(request,'logout.html')

@login_required
def addView(request):
    if request.method == 'POST':
        product = request.POST.get('product', '')
        Product.objects.create(user=request.user, product=product)
        # FLAW 4: Security Logging and Monitoring Failures (A09:2021)
        # logger.info(f"Product '{product}' added by user {request.user.username}.")
    return redirect('/')

@login_required
def deleteView(request):
    
    product_id = request.POST.get('id')
    
    product = Product.objects.get(pk=product_id) 
    product.delete()
    return redirect('/')

    # FLAW 1: Broken Access Control (A01:2021)
    # and
    # FLAW 4: Security Logging and Monitoring Failures (A09:2021)
    
    # try: 
        # product = Product.objects.get(pk=product_id, user=request.user)
        # product.delete()
        # logger.info(f"Product '{product.product}' deleted by user {request.user.username}.")
    # except Product.DoesNotExist:
        # logger.warning(f"User {request.user.username} attempted to delete non-existent or unauthorized product with id {product_id}.")
    # return redirect('/')

