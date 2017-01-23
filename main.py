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

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

SECRET = "dannyisthebest"
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def make_salt(length = 5):
    

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Users(db.Model):
    username = db.stringProperty(required = True)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('blog.html', posts = posts)

class NewPost(Handler):
    def get(self):
        self.render("new_post.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("new_post.html", subject=subject, content=content, error=error)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)

def validate_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return password and PASSWORD_RE.match(password)

def validate_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return email and EMAIL_RE.match(email)

class SignUpPage(Handler):
    def get(self):
        self.render("signup.html")
        
    def post(self):
        has_error = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify_password = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username = username, email = email)

        if not validate_username(username):
            params['error_username'] = "Please enter a valid username." 
            has_error = True
        
        if not validate_password(password):
            params['error_password'] = "Please enter a valid password."
            has_error = True
        elif password != verify_password:
            params['error_verify'] = "Your passwords do not match."
            has_error = True
        
        if not validate_email(email):
            params['error_email'] = "Please enter a valid email."
            has_error = True

        if has_error:
            self.render('signup.html', **params)
        else:
            self.response.headers.add_header('Set-Cookie', str('name=%s' % username))
            self.redirect('/blog/welcome')

class Welcome(Handler):
    def get(self):
        username = self.request.cookies.get('name')
        if validate_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

app = webapp2.WSGIApplication([
    ('/blog/?', MainPage),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/signup', SignUpPage),
    ('/blog/welcome', Welcome)
], debug=True)
