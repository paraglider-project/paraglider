DROP TABLE IF EXISTS tags;
CREATE TABLE tags (
  id         INT AUTO_INCREMENT NOT NULL,
  parent     VARCHAR(255) NOT NULL,
  child      VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`)
);

