-- Runs once, when the database volume is first created.
-- Tests get their own database because they empty its tables before every test.
CREATE DATABASE vigil_test OWNER vigil;
