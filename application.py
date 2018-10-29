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


application = Flask(__name__)
Bootstrap(application)

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
           #  salt = bcrypt.gensalt()
           #  hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), salt)
           #   dynamodb_resource = resource('dynamodb', region_name='us-east-1', endpoint_url="http://localhost")
           #  salt = uuid.uuid4().hex
           #  hashed_password = hashlib.sha512(form.password.data + salt).hexdigest()
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
    else:
        form = LoginForm()
        error=None
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


@application.route('/logout')
def logout():
    session.pop('username')
    session.pop('emailid')
    session.pop('fullname')
    return redirect(url_for('index'))

####################################### User Registeration, Login and Logout Code End here ######################################
@application.route('/files')
@login_required
def files():
#    FILTER=session['username'] + '/'
#    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
#    s3_resource = boto3.resource('s3')
#    my_bucket = s3_resource.Bucket(BUCKET_NAME)
#    result = my_bucket.objects.filter(Prefix=FILTER)
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

    return Response(file['Body'].read(),headers = {"Content-Disposition": "attachment; filename=%s" % file})

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

    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            k.key,
            ExtraArgs={
                "ContentType": file.content_type
            }
        )
    except Exception as e:
        print("Error Occurred!: ", e)
        return e

    return "File Uploaded"

def list_files():
    FILTER=session['username'] + '/'
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3_resource = boto3.resource('s3')
    my_bucket = s3_resource.Bucket(BUCKET_NAME)
    result = my_bucket.objects.filter(Prefix=FILTER)
    return result

def list_admin_files():
    s3 = boto3.client("s3",aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3_resource = boto3.resource('s3')
    my_bucket = s3_resource.Bucket(BUCKET_NAME)
    result = my_bucket.objects.filter()
    return result
####################################### S3 Bucket code upload and download begin here ######################################


################################# Main Code Here ########################################################################
if __name__ == "__main__":
        application.run(debug = True, host='127.0.0.1', port=5000, passthrough_errors=True)

