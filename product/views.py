from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib import auth
from django.views.generic import View
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from .token_generator import generate_token
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth import login, authenticate
from django.http import HttpResponse
from django.conf import settings
import threading


def home(request):
	return render(request,'product/home.html');

def signup(request):
	if request.method == 'POST':
		name=request.POST.get('name')
		email=request.POST.get('email')
		password=request.POST.get('password')
		cpassword=request.POST.get('cpassword')
		bval= False
		if len(name)<4:
			messages.add_message(request,messages.ERROR,'your name must have lenght>4')
			bval=True
		if(password!=cpassword):
			messages.add_message(request, messages.ERROR,'password do not match!')
			bval=True
		if len(password)<6:
			messages.add_message(request, messages.ERROR,'passwword at least 6 length!')
			bval=True
		try:
			if User.object.get(email=email):
				messages.add_message(request,messages.ERROR,'Email is taken!')
				bval=True
		except Exception as identifier:
			pass

		if bval:
			return render(request,'product/signup.html')
		user=User.objects.create_user(username=email,email=email,password=password)
		user.first_name=name
		user.is_active=False
		user.save()
		email_subject='Activate Your Account'
		current_site = get_current_site(request)
		message = render_to_string('product/activate.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': generate_token.make_token(user),
            })
		email_message=EmailMessage(
			email_subject,
			message,
			settings.EMAIL_HOST_USER,
			[email]
			)
		EmailThread(email_message).start()
		messages.add_message(request,messages.SUCCESS,'account created succesfully')
		return HttpResponse('We have sent you an email, please confirm your email address to complete registration')  
	else:
		return render(request,'product/signup.html')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS,'account activated successfully')
            return redirect('login')
        return render(request, 'product/signup.html', status=401)

class EmailThread(threading.Thread):

    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()

def login(request):
	if request.method=='POST':
		user=auth.authenticate(username=request.POST.get('username'),password=request.POST.get('password'))
		if user is not None:
			auth.login(request,user)
			return redirect('home')
		else:
			messages.add_message(request,messages.ERROR,'username or password is incorrect !')
			return render(request,'product/login.html')
	else:
		return render(request,'product/login.html')

def logout(request):
    if request.method == 'POST':
        auth.logout(request)
        return redirect('home')



	