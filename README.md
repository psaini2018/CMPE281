# Introduction
* Project1 : EDOCManager

* University Name : http://www.sjsu.edu/

* Course : Cloud Technologies

* Professor : Sanjay Garje

# EDOCManager : Manage your documents
EDOCManager can manage your documents anywhere and anytime in the world. We manage your documents with higly secured technologies. We neet availabilit of 99.99% for your documents. EDOCManager deployed on AWS and using thier highly secure technologies to meet the security requirement for customer documents. For availability, EDOCManager is using S3 cross region replication and documents can be accesed for 2 years. However, this policy can be chaged based on customer requirement. EDOCManager provides fast access to your documents and allows you to upload/download/delete and update your document within no time. The application uses AWS SNS , cloudwatch and lambda to monitor the activities on your document. App health is being monitored using SNS and cloudwatch. AWS lambda function create log if there is any file upload by a user to keep a track of put activities. To meet the load requirements, we are using AWS autoscale functionality to double the capacity if load increases without any downtime. It can be further increased based on requirements. 

### EDOCManager Architecture on AWS
![Alt text](templates/awsarc1.png?raw=true "EDOCManager Architecture on AWS")

### S3 Bucket Policies Architecture
![Alt text](templates/awsarc2.png?raw=true "S3 Bucket Policies Architecture")

### Application Flow 
![Alt text](templates/appflow.png?raw=true "Application Flow")

### EDOCManager Features
1. User can create their account in EDOCManager and passwords are encrypted and securely stored in AWS DynamoDB. AWS DynamoDB provides HA in 3 AWS AZs.
2. Users can access their data only on overy SSL layers
3. EDOCMnager application is registered with Twitter. User can login using their EDOCManager credentials or Twitter login.
4. User can visit website home page to know about the website.
5. Autorized users can login to their account and manage their data.
   * Users can upload the document to AWS S3
   * Download the document from AWS S3
   * Delete the document from AWS S3
   * Review account details
   * Logout securely

### EDOCManager is built on top of AWS using following components
1.  Elasticbeans based application is been created for Development and production server.
2.  Autoscale group i.e. capacity number is set min=2 to max=4 for both Dev and Test.
3.  AWS S3 bucket is created without any public access. 
4.  Files will move to Standard IA after 75 days
5.  Amazon Glacier is used for archiving and users document will moved to Amazon glacier after 365 days.
6.  Cloudfront is been configured to download the files.
7.  CloudWatch will monitor application health and mail will be send to admin if their is any problem in application availability. Mail will be send using SNS.
8.  SNS is sued to send notification to the admin if EDOCManager has any helth issue.
9.  Route53 is been configured to redirect all the requests to classic load balancer. All the traffic will be redirected to https://www.cellinfra.com
10. Lambda function is created in python to update cloudwatch is their is any put request on S3 bucket. This wil help in monitoring the workload.
11. AWS DynamoDB is used to store users credentials and for user management.
12. AWS Codepipeline is used for stage and deploy.
    * Developers will develop application on staging server at their premise 
    * Upload changes to github
    * AWS Development code pipeline is associated with Github development branch
    * Any changes detected by AWS code pipeline will be commited to AWS code repo and pushed to development box
    * Developers test the application
    * Once developers complete the testing, they can push the changes to master branch in github
    * AWS Prod code pipeline will detect the changes in master branch and will make deploy the code on prod server
13. Classic load balancer is been used to redirect the requests.

### Deployment Instructions
1.  Tools requirement: Python 2.7 with flask, Users table in DynamoDB with User_name (partition Key) and Emailid (sort key). Rest of the atributes created by EDocmanager.
2.  Create a virtual env based python 2.7
3.  Install packages using requirement.txt
4.  Run the application python application.py
5.  Access the app on http://127.0.0.1:5000/

### Screen Shots
#### Home Page
![Alt text](templates/homepage.png?raw=true "Home Page Screen")

#### Registeration Page
![Alt text](templates/register.png?raw=true "Registeration Page Screen")

#### Login Page
![Alt text](templates/loginpage.png?raw=true "Login Page Screen")

#### Users Home Page
![Alt text](templates/homepage.png?raw=true "User Home Page Screen")

#### DownloadFile
![Alt text](templates/download.png?raw=true "Download Page Screen")
