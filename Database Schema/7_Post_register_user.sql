DELIMITER $$

CREATE PROCEDURE prc_register_user(
    IN inputUserId VARCHAR(8)
)
BEGIN
    START TRANSACTION;

    INSERT INTO user_details (UserId,UserName,Passwrd,EmailId,DateOfBirth,About,ProfilePic)
    SELECT UserId,UserName,Passwrd,EmailId,BirthDate,About,ProfilePic 
    FROM user_registration_details
    WHERE UserId=inputUserId;

    DELETE FROM user_registration_details
    WHERE UserId=inputUserId;

    COMMIT;
END$$

DELIMITER ;
