CREATE TABLE user_profiles (
  id SERIAL PRIMARY KEY,
  account_id INT NOT NULL,
  name VARCHAR(255),
  surname VARCHAR(255),
  photo VARCHAR(255),
  phone_number VARCHAR(255),
  FOREIGN KEY (account_id) REFERENCES accounts(id)
)
