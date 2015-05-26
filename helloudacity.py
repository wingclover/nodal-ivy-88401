import webapp2
import os
import jinja2
from google.appengine.ext import db

import re
import hashlib
import hmac
import random
import string

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

secret = 'dfksdf.d.sdfisdfjskdfnsdndsf,sdfjlsdi&(sdfe)'

def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)


jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)


class Blog(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render(self, template, **kw):
        t = jinja_environment.get_template(template)
        self.write(t.render(**kw))
        
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    
class MainPage(Handler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render('index.html')

class AboutHandler(Handler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render('about.html')

class ProjectsHandler(Handler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render('projects.html')

class GalleryHandler(Handler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render('gallery.html')

class ActivityHandler(Handler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render('activity.html')
        
class ContactHandler(Handler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render('contact.html')

class BlogHandler(Handler):
    def get(self):
        blogs = db.GqlQuery("select * from Blog order by created desc")
        self.render('blog.html', blogs=blogs) 
        
class NewPostHandler(Handler):
    def render_newpost(self, title="", body="", error=""):
        self.render('newpost.html', title=title, body=body, error=error)

    def get(self):
        self.render_newpost()       
   
    def post(self):
        title = self.request.get('subject')
        body = self.request.get('content')
        if title and body:
            newpost = Blog(title = title, body = body)
            newpost.put()
            self.redirect("/blog/%s" % newpost.key().id())
        else:
            self.render_newpost(title=title, body=body, error="We need both a title and\
            content!")

class SingleBlogHandler(Handler):
    def get(self, blog_id):
        blog = Blog.get_by_id(int(blog_id))
        self.render('blog.html', blogs = [blog])

class SignUpHandler(Handler):
    def render_form(self, username="", email="", username_error="", password_error="", \
    match_error="", email_error=""):
        self.render('signup.html', username=username, email=email, username_error=username_error, \
        password_error=password_error, match_error=match_error, email_error=email_error)
    
    def get(self):
        self.render('signup.html')
        
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        if valid_username(self.username)and valid_password(self.password)\
        and self.password == self.verify and (valid_email(self.email) or self.email == ""):
            u = User.by_name(self.username)
            if u:
                msg = 'That user already exists.'
                self.render_form(username=self.username, email=self.email, username_error = msg)
            else:
                pw_hash = make_pw_hash(self.username, self.password)
                new_user = User(name=self.username, pw_hash=pw_hash, email=self.email)
                new_user.put()
                self.set_secure_cookie('user_id', str(new_user.key().id()))
                self.redirect('/blog/welcome')
        else:
            username_error=""
            password_error=""
            match_error=""
            email_error=""
            if not valid_username(self.username):
                username_error = "That's not a valid username."

            if not valid_password(self.password):
                password_error = "That wasn't a vald password."

            if self.password != self.verify:
                match_error = "Your passwords didn't match."

            if not valid_email(self.email):
                email_error = "That's not a valid email."
                
            self.render_form(username=self.username, email=self.email, username_error=username_error, \
            password_error=password_error, match_error=match_error, email_error=email_error)        

class WelcomeHandler(Handler):
    def get(self):
        cookie_value = self.read_secure_cookie('user_id')
        self.write('Welcome, ' + str(User.get_by_id(int(cookie_value)).name))
        
class LoginHandler(Handler):
    def get(self):
        self.render("login.html")
        
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        u = User.by_name(self.username)
        if u:
            pw_hash = u.pw_hash
            if valid_pw(self.username, self.password, pw_hash):
                self.set_secure_cookie('user_id', str(u.key().id()))
                self.redirect('/blog/welcome')
            else:
                msg = "The password is not correct."
                self.render('login.html', password_error= msg)
        else:
            msg = "That username doesn't exist."
            self.render('login.html', username_error= msg)

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id =; Path=/')
        self.redirect('/blog/signup')

application = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/about', AboutHandler), 
    ('/projects', ProjectsHandler),
    ('/gallery', GalleryHandler), 
    ('/activity', ActivityHandler),
    ('/contact', ContactHandler),
    ('/blog', BlogHandler),
    ('/blog/login', LoginHandler), 
    ('/blog/logout', LogoutHandler),
    ('/blog/newpost', NewPostHandler), 
    ('/blog/signup', SignUpHandler), 
    ('/blog/welcome', WelcomeHandler),
    ('/blog/(\d+)', SingleBlogHandler)], debug=True)