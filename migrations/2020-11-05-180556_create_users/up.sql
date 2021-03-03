CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    password CHAR(86) NOT NULL,
    algorithm VARCHAR(8) NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE
)