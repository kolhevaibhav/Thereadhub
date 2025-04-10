CREATE TABLE user_registration_details(
    UserId VARCHAR(8) PRIMARY KEY,
    UserName VARCHAR(50) NOT NULL,
    Passwrd VARCHAR(20) NOT NULL,
    EmailId VARCHAR(254) NOT NULL UNIQUE,
    BirthDate DATE NOT NULL,
    About TEXT,
    ProfilePic BLOB,
    OneTimeToken VARCHAR(32),
    InsertTime TIMESTAMP,
    CHECK (LENGTH(UserId) >= 5 and LENGTH(UserId) <= 8)
);