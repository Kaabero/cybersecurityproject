"""
URL configuration for shoppinglist project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import homePageView, logoutPageView, addView, loginPageView, deleteView, createAccountPageView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', homePageView, name='home'),
    path('login/', loginPageView, name='login'),
    path('logout/', logoutPageView, name='logout'),
    path('add/', addView, name='add'),
    path('delete/', deleteView, name='delete'),
    path('createaccount/', createAccountPageView, name='createaccount'),
]
