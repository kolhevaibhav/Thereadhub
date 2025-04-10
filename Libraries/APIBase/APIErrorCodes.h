#pragma once

#define F_SOMETHING_WENT_WRONG 1001
#define F_SOMETHING_WENT_WRONG_MESSAGE "Something went wrong"
#define F_SOMETHING_WENT_WRONG_DESCRIPTION "Something went wrong, please try again..."

#define F_DATABASE_EXCEPTION 1003
#define F_DATABASE_EXCEPTION_MESSAGE "Issue with database"
#define F_DATABASE_EXCEPTION_DESCRIPTION "We have some issue while interacting to the database, please try again and if issue persists, try after sometime..."

#define F_BAD_REQUEST 1004
#define F_BAD_REQUEST_MESSAGE "Request parameters error"
#define F_BAD_REQUEST_DESCRIPTION "Incorrect request parameters, check request parameters passed"

#define F_NOT_IMPLEMENTED 1005 
#define F_NOT_IMPLEMENTED_MESSAGE "Request not implemented"
#define F_NOT_IMPLEMENTED_DESCRIPTION "Request with specified uri path is not implemented,Check uri path..."