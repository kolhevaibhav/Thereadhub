DELIMITER $$
CREATE PROCEDURE prc_get_onetimetoken(
    IN inputUserId VARCHAR(8)
)
BEGIN
    DECLARE var_insertTime TIMESTAMP;
    DECLARE var_oneTimeToken VARCHAR(32);

    SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
    
    START TRANSACTION;

    SELECT InsertTime, OneTimeToken INTO var_insertTime, var_oneTimeToken
    FROM user_registration_details
    WHERE UserId = inputUserId;

    IF var_insertTime IS NOT NULL AND var_oneTimeToken IS NOT NULL THEN
        IF TIMESTAMPDIFF(MINUTE,var_insertTime,NOW())<5 THEN
            UPDATE user_registration_details SET InsertTime=NOW() WHERE UserId = inputUserId;
            SELECT var_oneTimeToken AS OneTimeToken;
        ELSE
            DELETE FROM user_registration_details WHERE UserId = inputUserId;
            SELECT "" AS OneTimeToken;
        END IF; 
    ELSE 
        SELECT "" AS OneTimeToken;
    END IF;
    
    COMMIT;
END$$

DELIMITER ;
