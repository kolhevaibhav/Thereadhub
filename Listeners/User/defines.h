#pragma once

#define D_EMAIL_SUBJECT_OTP_FOR_REGISTRATION "OTP for registration"
#define D_EMAIL_BODY_OTP_FOR_REGISTRATION "OTP to register your email is:\n"
#define D_EMAIL_BODY_OTP_FOR_REGISTRATION(otp) "OTP to register your email is:\n"+utility::conversions::to_utf8string(otp)
#define D_MSG_SUCCESS_POST_REGDETAILS "OTP has been sent to the email id provided"