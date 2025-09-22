Let's start with the authentication endpoint. I am having following request and response structure of authentication API -

URL -> http://localhost:8000/v1/authenticate
Request Body -> 
{
    "txn": "123",
    "appkey": "a2fb2912248f01c144c6c9f32a465148da903c68817a4ee9378212165aec5417",
    "username": "testp19@jisasoftech.com",
    "password": "849f1575ccfbf3a4d6cf00e6c5641b7fd4da2ed3e212c2d79ba9161a5a432ff0"
}

Response Body ->
{
    "ret_data": "<<JWT Toekn>>",
    "remark": "SUCCESS : JWT Token is generated successfully",
    "errMsg": "NULL",
    "errCode": "NULL",
    "status": "1",
    "txn": "123"
}

I want to implement role based authentication (RBAC). There will be two types of user permissions -
1. tokenization_allowed
2. detokenization_allowed

The the users with tokenization_allowed permissiion can access the following API endpoints -
1. Tokenization - http://localhost:8000/v1/tokenize
2. Bulk Tokenization - http://localhost:8000/v1/bulk_tokenize

The users with detokenization allowed permission can access the following endpoints -
1. De-Tokenization - http://localhost:8000/v1/detokenize

We will maintain all user credentials in database table. We are using oracle db and I have already created schema with name SCM_TKN. We need to create table within this schema with name "TBL_IAM". Please create table to store username, password and respective permissions.

For performance perspective we will cache TBL_IAM users in memory to avoid unnecessary database calls.

From the API request body you will get username and password to identify the user. Based on this create JWT token and return in the response structure. Let me know if you need additional inputs to further enhance the mechanism.

later we will implement authentication middleware to validate the permissions.