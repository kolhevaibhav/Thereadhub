DELIMITER $$
CREATE PROCEDURE prc_post_user_registration_details(
    IN inputUserId VARCHAR(8),
    IN inputUserName VARCHAR(50),
    IN inputPasswrd VARCHAR(20),
    IN inputEmailId VARCHAR(254),
    IN inputBirthDate VARCHAR(10),
    IN inputAbout TEXT,
    IN inputProfilePic BLOB,
    IN inputOneTimeToken VARCHAR(32)
)
BEGIN
    DECLARE formatedBirthDate DATE;
    DECLARE currentTime TIMESTAMP;

    START TRANSACTION;

    SET formatedBirthDate = STR_TO_DATE(inputBirthDate, '%m-%d-%Y');
    SET currentTime = NOW();

    INSERT INTO user_registration_details (UserId,UserName,Passwrd,EmailId,BirthDate,About,ProfilePic,OneTimeToken,InsertTime)
    VALUES(
        inputUserId,
        inputUserName,
        inputPasswrd,
        inputEmailId,
        formatedBirthDate,
        inputAbout,
        inputProfilePic,
        inputOneTimeToken,
        currentTime
    )
    ON DUPLICATE KEY UPDATE
        UserName = VALUES(UserName),
        Passwrd = VALUES(Passwrd),
        EmailId = VALUES(EmailId),
        BirthDate = VALUES(BirthDate),
        About = VALUES(About),
        ProfilePic = VALUES(ProfilePic),
        OneTimeToken = VALUES(OneTimeToken),
        InsertTime = VALUES(InsertTime);
        
    COMMIT;
END$$

DELIMITER ;
