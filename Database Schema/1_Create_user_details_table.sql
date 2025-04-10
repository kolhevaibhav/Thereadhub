CREATE TABLE user_details(
    UserId VARCHAR(8) PRIMARY KEY,
    UserName VARCHAR(50) NOT NULL,
    About TEXT,
    Passwrd VARCHAR(20) NOT NULL,
    DateOfBirth DATE NOT NULL,
    EmailId VARCHAR(254) NOT NULL UNIQUE,
    ProfilePic BLOB,
    ProfileRating FLOAT(2,1) DEFAULT 0.0,
    TotalRatings INT UNSIGNED DEFAULT 0,
    CHECK (LENGTH(UserId) >= 5 and LENGTH(UserId) <= 8)
);