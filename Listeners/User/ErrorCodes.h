#pragma once

#define F_INCORRECT_NO_OF_QUERY_PARAMS 2001
#define F_INCORRECT_NO_OF_QUERY_PARAMS_MESSAGE "Incorrect number of query parameters"
#define F_INCORRECT_NO_OF_QUERY_PARAMS_DESCRIPTION "Number of query parameters passed is either zero or more than one..."

#define F_INCORRECT_QUERY_PARAMS 2002
#define F_INCORRECT_QUERY_PARAMS_MESSAGE "Incorrect query parameters"
#define F_INCORRECT_QUERY_PARAMS_DESCRIPTION "Query parameters passed is incorrect, please check query parameters and try again..."

#define F_INVALID_USERID 2003
#define F_INVALID_USERID_MESSAGE "Invalid userid"
#define F_INVALID_USERID_DESCRIPTION "Userid passed does not match criteria, please enter valid userid..."

#define F_INVALID_EMAIL 2004
#define F_INVALID_EMAIL_MESSAGE "Invalid email"
#define F_INVALID_EMAIL_DESCRIPTION "Emailid passed is not valid, please enter valid email..."

#define F_INVALID_USERNAME 2005
#define F_INVALID_USERNAME_MESSAGE "Invalid username"
#define F_INVALID_USERNAME_DESCRIPTION "Username cannot be empty, please enter valid username..."

#define F_INVALID_PASSWORD 2006 
#define F_INVALID_PASSWORD_MESSAGE "Invalid password"
#define F_INVALID_PASSWORD_DESCRIPTION "Password does not match criteria, please enter valid password..."

#define F_INVALID_BIRTHDATE 2007
#define F_INVALID_BIRTHDATE_MESSAGE "Invalid birthdate"
#define F_INVALID_BIRTHDATE_DESCRIPTION "Birthdate is not valid, please enter valid birthdate in mm-dd-yyy format..."

#define F_USERID_TAKEN 2008
#define F_USERID_TAKEN_MESSAGE "Userid is already taken"
#define F_USERID_TAKEN_DESCRIPTION "Userid is not available, Please try with different userid..."

#define F_INVALID_REGISTRATION_TOKEN 2009
#define F_INVALID_REGISTRATION_TOKEN_MESSAGE "Registration token is invalid"
#define F_INVALID_REGISTRATION_TOKEN_DESCRIPTION "Registration token passed is not valid, kindly check registration token..."

#define F_ACCOUNT_ALREADY_EXISTS 2010
#define F_ACCOUNT_ALREADY_EXISTS_MESSAGE "Email id already registered"
#define F_ACCOUNT_ALREADY_EXISTS_DESCRIPTION "Entered email id is already registered with us,kindly check or login with this email id..."

#define F_INVALID_ONETIMETOKEN 2011
#define F_INVALID_ONETIMETOKEN_MESSAGE "One time token is invalid"
#define F_INVALID_ONETIMETOKEN_DESCRIPTION "OTP entered is either expired or incorrect..."