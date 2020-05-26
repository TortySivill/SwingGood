from __future__ import print_function
import sys
import os
from flask import Flask, render_template, json, request, redirect, url_for

from werkzeug import generate_password_hash, check_password_hash, secure_filename
from flask import session, flash
from flask import send_from_directory
import boto3, time, botocore
from boto3.s3.transfer import S3Transfer
from boto.s3.key import Key
import hashlib

from boto import dynamodb2
from boto.dynamodb2.table import Table
from botocore.errorfactory import ClientError

TABLE_NAME = 'Users'
TABLE_NAME2 = 'Videos'
REGION = 'us-west-2'




UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4'])



application = Flask(__name__)
application.secret_key = 'super secret key'


application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@application.route("/")
def main():
    return render_template('index.html')

@application.route('/showSignIn')
def showSignin():
    return render_template('SignIn.html')

@application.route('/validateLogin',methods=['POST'])
def validateLogin():
	try:
		_username = request.form['inputEmail']
		_password = request.form['inputPassword']


		dynamodb = boto3.resource( 'dynamodb', REGION, aws_access_key_id='secret', aws_secret_access_key='secret')
		table = dynamodb.Table(TABLE_NAME)

		try:
			response = table.get_item(
				Key={
					'user_email': _username
				}
    		)
		except ClientError as e:
			return render_template('error.html',error = 'Wrong Email address or Password.')
		else:
			item = response['Item']
			print('getItem succeeded')
			print(json.dumps(item))
			print(json.dumps(item['user_email']))
			if check_password_hash(str(item['user_password']),_password):
				session['user'] = item['user_email']
				return redirect('/userHome')

			else:
				return render_template('error.html',error = 'Wrong Email Address or Password.')
		
 
 
	except Exception as e:
		return render_template('error.html',error = str(e))

 
@application.route('/userHome')
def userHome():
    if session.get('user'):
        return render_template('UserHome.html')
    else:
        return render_template('error.html',error = 'Unauthorized Access')


@application.route('/showSignUp')
def showSignUp():
	return render_template('SignUp.html')

@application.route('/signUp', methods=['POST'])
def signUp():
	# read the posted values from the UI
	_name = request.form['inputName']
	_email = request.form['inputEmail']
	_password = request.form['inputPassword']


	dynamodb = boto3.resource( 'dynamodb', REGION, aws_access_key_id='secret', aws_secret_access_key='secret')
	table = dynamodb.Table(TABLE_NAME)

	if _name and _email and _password:
		_hashed_password = str(generate_password_hash(_password))
		response = table.put_item(
			Item={
				'user_password' : _hashed_password,
				'user_name' : _name,
				'user_email' : _email
			}
		)
		table = dynamodb.Table(TABLE_NAME2)
		response = table.put_item(
					Item={
						'user_email' : _email,
						'videos' : []
						}
					)
		return render_template('SignIn.html')
	

@application.route('/showAddVideo')
def showAddWish():
	if session.get('user'):
		return render_template('AddVideo.html')
	else:
		return render_template('error.html',error = 'Unauthorized Access')

@application.route('/showAddVideo', methods=['POST'])
def upload_file():
	try:
		if session.get('user'):
			if 'file' not in request.files:
				return render_template('error1.html',error = 'An error occurred!')
			file = request.files['file']
			if file.filename == '':
				return render_template('error1.html',error = 'An error occurred!')
			else:
				user = session.get('user')
				data = str(user).split('@')
				name = data[0] + '-' + data[1] + '-'
				s3_name = name + hashlib.md5(file.filename.encode()).hexdigest() + '.mp4'
				s3_client = boto3.client('s3',aws_access_key_id='secret',aws_secret_access_key='secret')
				file.save(os.path.join(application.config['UPLOAD_FOLDER'], s3_name))  
				s3_client.upload_file('static/uploads/' + s3_name, 'videosraw', s3_name , ExtraArgs={'ContentType': "video/mp4", 'ACL': "public-read"})

				dynamodb = boto3.resource( 'dynamodb', REGION, aws_access_key_id='secret', aws_secret_access_key='secret')
				table = dynamodb.Table(TABLE_NAME2)




				result = table.update_item(
					Key={
						'user_email' : user
					},
					UpdateExpression="SET videos = list_append(videos, :i)",
					ExpressionAttributeValues={
						':i':[s3_name],
					}
					
				)

				if result['ResponseMetadata']['HTTPStatusCode'] == 200 and 'Attributes' in result:
					return result['Attributes']['videos']

				
				os.remove('static/uploads/' + s3_name);
				return redirect('/userHome')
				
					
		else:
			return render_template('error.html',error = 'Unauthorized Access')
	except Exception as e:
		return render_template('error.html',error = str(e))




    


@application.route('/getVideo')
def getVideo():
	try:
		if session.get('user'):
			user = session.get('user')
			dynamodb = boto3.resource( 'dynamodb', REGION, aws_access_key_id='secret', aws_secret_access_key='secret')
			table2 = dynamodb.Table(TABLE_NAME2)
			try: 
				response = dynamodb.batch_get_item(
				RequestItems={
					'Videos': {
						'Keys' : [
						{
							'user_email': user
						}
						]
					}

				}
	    		)

			except ClientError as e:
				print(e.response['Error']['Message'])
			item = response['Responses']
			item = item['Videos']
			item = item[0]
			item = item['videos']
			videos_dict = []
			for video in item:
				video_dict = {
				'Name': video }
				videos_dict.append(video_dict)

				
			return json.dumps(videos_dict)
		else:
			return render_template('error.html', error = 'Unauthorized Access')
	except Exception as e:
		return render_template('error.html', error = str(e))
	#finally:
	#	cursor.close()
	#	con.close()





@application.route('/logout')
def logout():
    session.pop('user',None)
    return redirect('/')


if __name__ == "__main__":
	application.config['SESSION_TYPE'] = 'filesystem'
	application.run()