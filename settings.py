import os
basedir = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = os.environ.get('SECRET_KEY') or 'SuperSecretKeys'
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
DEBUG = True
TEST_DYNAMO_TABLE = 'Users'
PROD_DYNAMO_TABLE = 'Users_dev'
#AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
#if not AWS_ACCESS_KEY_ID:
#    raise ValueError("No AWS_ACCESS_KEY_ID secret key set for EDOCManager")
#AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
#if not AWS_SECRET_ACCESS_KEY:
#    raise ValueError("No AWS_SECRET_ACCESS_KEY secret key set for EDOCManager")
#END_POINT = os.environ.get("END_POINT")
#if not END_POINT:
#    raise ValueError("No END Point set  for EDOCManager")
#BUCKET_NAME = os.environ.get("BUCKET_NAME")
#if not BUCKET_NAME:
#    raise ValueError("No Bucket set for EDOCManager")
#S3_HOST  = os.environ.get("S3_HOST")
#if not S3_HOST:
#    raise ValueError("No S3_HOST set for EDOCManager")
