#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os 
import webapp2
import jinja2
import re
import hashlib
import random
import hmac

from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

# GLOBAL FUNCTIONS
# Hashing Values
SECRET = "dannyisthebest"
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# Hashing password to be more secure
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Validation for User sign up info
def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)

def validate_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return password and PASSWORD_RE.match(password)

def validate_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return email and EMAIL_RE.match(email)

# DATABASE
# Key to find users
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# User format for database
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(), name = name, pw_hash = pw_hash, email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Key to find blog posts
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Blog format for database
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

# Handler for EVERYTHING
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# Main page to display blogs
class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('blog.html', posts = posts)

# Posting a new blog
class NewPost(Handler):
    def get(self):
        self.render("new_post.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if self.user:
            username = self.user.name
        else:
            username = "Anonymous"

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = username)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("new_post.html", subject=subject, content=content, error=error)

# Separate page for the blog post
class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

# Page to register
class SignUpPage(Handler):
    def get(self):
        self.render("signup.html")
        
    def post(self):
        has_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify_password = self.request.get("verify")
        self.email = self.request.get("email")

        params = dict(username = self.username, email = self.email)

        if not validate_username(self.username):
            params['error_username'] = "Please enter a valid username." 
            has_error = True
        
        if not validate_password(self.password):
            params['error_password'] = "Please enter a valid password."
            has_error = True
        elif self.password != self.verify_password:
            params['error_verify'] = "Your passwords do not match."
            has_error = True
        
        if not validate_email(self.email):
            params['error_email'] = "Please enter a valid email."
            has_error = True

        if has_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(SignUpPage):
    def done(self):
        u = User.by_name(self.username)
        if u:
            message = "That username already exists."
            self.render('signup.html', error_username = message)
        else:
            u = User.register(self.username, self.password, self.email) # Add user to database
            u.put()
            
            self.login(u)
            self.redirect('/welcome')

# Login
class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password) # If name and pw are together in database
        if u:
            self.login(u) # set cookies
            self.redirect('/welcome') 
        else:
            message = "Invalid login"
            self.render('login.html', error_username = message)

# Logout
class Logout(Handler):
    def get(self):
        self.logout() # Erase cookies
        self.redirect('/signup')

class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout)
], debug=True)
