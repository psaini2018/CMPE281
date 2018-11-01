import os, sys
from flask import render_template, redirect, url_for, session, request, flash, g, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import  RegisterForm, LoginForm
from decorators import login_required
from boto3 import resource
import boto3
import botocore
from boto.s3.key import Key
from boto3.dynamodb.conditions import Key
import os,sys
from flask_bootstrap import Bootstrap
from flask import Flask, render_template
import datetime
import boto
from boto.s3.connection import S3Connection
from flask_oauth import OAuth


application = Flask(__name__)
Bootstrap(application)
oauth = OAuth()

application.config .from_object('settings')
application.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024


#################################################
##
##    Views.py Code here ########################
#################################################


AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
if not AWS_ACCESS_KEY_ID:
    raise ValueError("No AWS_ACCESS_KEY_ID secret key set for EDOCManager")

AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
if not AWS_SECRET_ACCESS_KEY:
    raise ValueError("No AWS_SECRET_ACCESS_KEY secret key set for EDOCManager")

END_POINT = os.environ.get("END_POINT")
if not END_POINT:
    raise ValueError("No END Point set  for EDOCManager")

BUCKET_NAME = os.environ.get("BUCKET_NAME")
if not BUCKET_NAME:
    raise ValueError("No Bucket set for EDOCManager")

S3_HOST  = os.environ.get("S3_HOST")
if not S3_HOST:
    raise ValueError("No S3_HOST set for EDOCManager")

##############################################################

############################ Twitter Code Begins here ########

TWITTER_CONSUMER_KEY = os.environ.get("TWITTER_CONSUMER_KEY")
TWITTER_SECRET_KEY = os.environ.get("TWITTER_SECRET_KEY")

twitter = oauth.remote_app('twitter',
    # unless absolute urls are used to make requests, this will be added
    # before all URLs.  This is also true for request_token_url and others.
    base_url='https://api.twitter.com/1/',
    # where flask should look for new request tokens
    request_token_url='https://api.twitter.com/oauth/request_token',
    # where flask should exchange the token with the remote application
    access_token_url='https://api.twitter.com/oauth/access_token',
    # twitter knows two authorizatiom URLs.  /authorize and /authenticate.
    # they mostly work the same, but for sign on /authenticate is
    # expected because this will give the user a slightly different
    # user interface on the twitter side.
    authorize_url='https://api.twitter.com/oauth/authenticate',
    # the consumer keys from the twitter application registry.
    consumer_key=TWITTER_CONSUMER_KEY,
    consumer_secret=TWITTER_SECRET_KEY
)


@application.route('/oauth-authorized')
@twitter.authorized_handler
def oauth_authorized(resp):
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)
 
    access_token = resp['oauth_token']
    session['access_token'] = access_token
    session['screen_name'] = resp['screen_name']
 
    session['twitter_token'] = (
        resp['oauth_token'],
        resp['oauth_token_secret']
    )
    return render_template('index.html')

 
###############################################################
@application.route('/')
@application.route('/index')
@application.route('/home')
#@login_required
def index():
    return render_template('index.html')


@application.route('/about')
def about():
    return render_template('about.html')

@application.route('/contact')
def contact():
    return render_template('contact.html')

####################################### User Registeration, Login and Logout Code Begin here ######################################
@application.route('/register', methods=('GET','POST'))
def register():
    if 'username' in session:
        return render_template('index.html')
    else:
        form = RegisterForm()
        if form.validate_on_submit():
           hashed_password = generate_password_hash(form.password.data)
           dynamodb_resource = resource('dynamodb', region_name=END_POINT)
           table = dynamodb_resource.Table('users')
           response = table.query(KeyConditionExpression=Key('user_name').eq(form.username.data))
           items = response['Items']
           if items:
                flash('Username already exist!, Please choose another Username and Emailid')
                return render_template('register.html', form=form)
           else:
                response = table.put_item(
                Item={
                     'user_name': form.username.data,
                     'email_id': form.email.data,
                     'fullname': form.fullname.data,
                     'password': hashed_password
                     }
               )
                return redirect( url_for('login'))
        return render_template('register.html', form=form)

@application.route('/login', methods=('GET','POST'))
def login():
    if 'username' in session:
        return render_template('index.html')
    elif  'access_token' in session:
        return render_template('index.html')
    else:
        form = LoginForm()
        error=None
        if twitterlogin == 'twitter_login1':
            return twitter.authorize(callback=url_for('oauth_authorized',
            next=request.args.get('next') or request.referrer or None))
        else:
            if request.method == 'GET' and request.args.get('next'):
               session['next'] = request.args.get('next', None)
            if form.validate_on_submit():
               dynamodb_resource = resource('dynamodb', region_name=END_POINT)
               table = dynamodb_resource.Table('users')
               response = table.query(KeyConditionExpression=Key('user_name').eq(form.username.data))
               items = response['Items']
               if items:
                   if check_password_hash(items[0]['password'],form.password.data):
                       session['username'] = items[0]['user_name']
                       session['emailid'] =  items[0]['email_id']
                       session['fullname'] = items[0]['fullname']
                       if 'next' in session:
                          next = session.get('next')
                          session.pop('next')
                          return redirect(next)
                       else:
                           return redirect(url_for('index'))
               else:
                  error = "Incorrect Username and Password"
        return render_template('login.html', form=form, error=error)

@application.route('/twitterlogin', methods=('GET','POST'))
def twitterlogin():
    error=None
    return twitter.authorize(callback=url_for('oauth_authorized',
    next=request.args.get('next') or request.referrer or None))

 
@application.route('/logout')
def logout():
    session.pop('username')
    session.pop('emailid')
    session.pop('fullname')
#    session.pop('screen_name', None)
    return redirect(url_for('index'))

####################################### User Registeration, Login and Logout Code End here ######################################
@application.route('/files')
@login_required
def files():
     if session['username'] == 'admin':
        result = list_admin_files()
        return render_template('report.html', files=result)
     else:
        result = list_files()
        return render_template('report.html', files=result)


@application.route('/uploadfile', methods=["POST"])
@login_required
def uploadfile():
    if "userfile" not in request.files:
       print("Please Specify correct filename")
       return redirect(request.url)

    file = request.files["userfile"]
    if file.filename is None:
       return redirect(request.url)
    filename = session['username'] + '/' + file.filename
    print (filename)
    file.filename = secure_filename(filename)
    output = upload_file_to_s3(file, BUCKET_NAME)
    result = list_files()
    return render_template('report.html', files=result)

@application.route('/downloadfile')
@login_required
def downloadfile():
 #   key_name='psaini/psaini_FallFee2018.log'
    key_name=request.args['keyname']
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    file = s3.get_object(Bucket=BUCKET_NAME, Key=key_name)
    print file
    return Response(file['Body'].read(),headers = {"Content-Disposition": "attachment; filename=%s" % key_name})

@application.route('/deletefile')
@login_required
def deletefile():
    key_name=request.args['keyname']
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3.delete_object(Bucket=BUCKET_NAME, Key=key_name)
    result = list_files()
    return render_template('report.html', files=result)

def upload_file_to_s3(file, bucket_name):
    k = Key(bucket_name)
    k.key = session['username'] + '/' + file.filename
    date = check_file_exist(k.key, bucket_name)
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            k.key,
            ExtraArgs={
                "ContentType": file.content_type,
                "Metadata": {"creation_date": date} 
            }
        )
    except Exception as e:
        print("Error Occurred!: ", e)
        return e

    return "File Uploaded"

def check_file_exist(filename, bucket_name):
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)
    objs = list(bucket.objects.filter(Prefix=filename))
    if len(objs) > 0 and objs[0].key == filename:
       file_metadata = build_metdata(filename)    
       date = file_metadata['creationdate']
       return date
    else:
       now = datetime.datetime.now()
       date = str(now)
       return date

def update_file_metdata(filename, bucket_name):
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)
    obj = s3.Bucket(bucket_name).Object(filename)
    date='2018-10-10 11:11'
    obj.metadata.update({'creation_date':date})
    return 'file_updated'
 
def list_files():
    FILTER=session['username'] + '/'
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3_resource = boto3.resource('s3')
    my_bucket = s3_resource.Bucket(BUCKET_NAME)
         
#    files = print_files() 
    result = my_bucket.objects.filter(Prefix=FILTER)
    file_list=print_files(result)
    return file_list

def print_files(result):
     file_metadata = {}
     file_list = []

     for f in result:
          file_metadata = build_metdata(f.key)
          file_list.append(file_metadata)
     return file_list 


def build_metdata(filename):
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    file_metadata = {}
    response = s3.head_object(Bucket=BUCKET_NAME, Key=filename)
    file_metadata['last_modified'] = response["LastModified"]
    file_metadata['filename'] = filename
    try:
        file_metadata['creationdate'] = response['ResponseMetadata']['HTTPHeaders']['x-amz-meta-creation_date']
    except:
        file_metadata['creationdate'] = 'Not Specified'

    return file_metadata 


def list_admin_files():
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3_resource = boto3.resource('s3')
    my_bucket = s3_resource.Bucket(BUCKET_NAME)
    result = my_bucket.objects.filter()
    file_list=print_files(result)
    return file_list

####################################### S3 Bucket code upload and download begin here ######################################


################################# Main Code Here ########################################################################
if __name__ == "__main__":
        application.run(debug = True, host='127.0.0.1', port=5000, passthrough_errors=True)

