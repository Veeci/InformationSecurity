USE master;
GO

IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'AuthenticatedDataBase')
BEGIN
  CREATE DATABASE AuthenticatedDataBase;
END;
GO

USE AuthenticatedDataBase;
GO

-- Create the User table if it does not exist
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG = SCHEMA_NAME() AND TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'User')
BEGIN
  CREATE TABLE [User] (
    UserID INT IDENTITY(1,1) PRIMARY KEY, -- Auto-increment primary key
    Username VARBINARY(260) NOT NULL, -- Username stored as binary data
    [Password] VARBINARY(MAX) NOT NULL, -- Password stored as binary data
    FullName NVARCHAR(256) NOT NULL, -- Full name of the user
    Gender NVARCHAR(10) NULL, -- Gender of the user
    Image NVARCHAR(256) NULL, -- Image path or URL
    Role NVARCHAR(256) NOT NULL, -- Role of the user
    Department NVARCHAR(256) NOT NULL -- Department of the user
  );
  CREATE UNIQUE INDEX IX_User_Username ON [User] (Username); -- Ensures unique usernames for users
END;
GO

-- Create the Admin table if it does not exist
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG = SCHEMA_NAME() AND TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Admin')
BEGIN
  CREATE TABLE [Admin] (
    AdminID INT IDENTITY(1,1) PRIMARY KEY, -- Auto-increment primary key
    Username VARBINARY(260) NOT NULL, -- Username stored as binary data
    [Password] VARBINARY(MAX) NOT NULL, -- Password stored as binary data
    FullName NVARCHAR(256) NOT NULL -- Full name of the admin
  );
  CREATE UNIQUE INDEX IX_Admin_Username ON [Admin] (Username); -- Ensures unique usernames for admins
END;
GO
