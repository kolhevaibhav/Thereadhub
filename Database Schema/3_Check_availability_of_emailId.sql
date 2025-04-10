DELIMITER $$

CREATE PROCEDURE prc_check_emailid_availability(
    IN inputEmailId VARCHAR(254)
)
BEGIN 
    SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
    
    START TRANSACTION;

    SELECT EXISTS(
        SELECT TRUE
        FROM user_details
        WHERE EmailId = inputEmailId
    )AS alreadyRegistered;

    COMMIT;
END$$

DELIMITER ;
