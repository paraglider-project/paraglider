DROP TABLE IF EXISTS tags;
CREATE TABLE tags (
  parent     VARCHAR(255) NOT NULL,
  child      VARCHAR(255) NOT NULL,
  PRIMARY KEY (`parent`)
);

