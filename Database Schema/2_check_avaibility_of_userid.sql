DELIMITER $$
CREATE PROCEDURE prc_check_userid_availability(
    IN inputUserId VARCHAR(8)
)
BEGIN 
    SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
    
    START TRANSACTION;

    SELECT 
    NOT EXISTS(
        SELECT 1 FROM user_details WHERE UserId = inputUserId
    ) 
    AND NOT EXISTS(
        SELECT 1 FROM user_registration_details WHERE UserId = inputUserId
    ) AS isAvailable;

    COMMIT;
END$$

DELIMITER ;