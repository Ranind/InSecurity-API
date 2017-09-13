CREATE DATABASE `InSecurity`;

USE `InSecurity`;

CREATE TABLE Scan (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  scanType VARCHAR(13) NOT NULL,
  creator VARCHAR(15) NOT NULL,
  status VARCHAR(11) NOT NULL DEFAULT 'In-Progress',
  started DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed DATETIME,
  progress TINYINT NOT NULL DEFAULT 0,
  report LONGTEXT
);

CREATE TABLE Devices (
  id INT NOT NULL,
  ip VARCHAR(15) NOT NULL,
  FOREIGN KEY (id) REFERENCES Scan(id)
);

CREATE TABLE ActivityLog (
  id INT NOT NULL,
  eventTime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  message VARCHAR(80) NOT NULL,
  FOREIGN KEY (id) REFERENCES Scan(id)
);
