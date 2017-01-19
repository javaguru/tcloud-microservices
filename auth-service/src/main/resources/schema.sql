-- customized oauth_client_details table
-- client table
-- drop table if exists client;
create table if not exists client(
  id bigint auto_increment primary key,
  client_id varchar(256),
  secret varchar(256),
  scopes varchar(256),
  authorized_grant_types varchar(256),
  authorities varchar(256),
  auto_approve_scopes varchar(256),
  registered_redirect_uri varchar(1024)
);

-- drop table if exists oauth_client_details;
create table if not exists oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);

-- INSERT INTO `oauth_client_details` (`client_id`, `resource_ids`, `client_secret`, `scope`, `authorized_grant_types`, `web_server_redirect_uri`, `authorities`, `access_token_validity`, `refresh_token_validity`, `additional_information`, `autoapprove`)
-- VALUES ('acme', '', '$2a$10$z/8fQRJlWmEB2jU3kC2rueX0gtVi340X2/bri6U5Yxw4tdHG/vZJS', 'read,write', 'refresh_token,password', NULL, 'ROLE_USER,ROLE_ADMIN', 0, 0, 'SSO', 'true');

-- drop table if exists oauth_client_token;
create table if not exists oauth_client_token (
  token_id VARCHAR(256),
  token LONGVARBINARY,
  authentication_id VARCHAR(256) PRIMARY KEY,
  user_name VARCHAR(256),
  client_id VARCHAR(256)
);

-- drop table if exists oauth_access_token;
create table if not exists oauth_access_token (
  token_id VARCHAR(256),
  token LONGVARBINARY,
  authentication_id VARCHAR(256) PRIMARY KEY,
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication LONGVARBINARY,
  refresh_token VARCHAR(256)
);

-- drop table if exists oauth_refresh_token;
create table if not exists oauth_refresh_token (
  token_id VARCHAR(256),
  token LONGVARBINARY,
  authentication LONGVARBINARY
);

-- drop table if exists oauth_code;
create table if not exists oauth_code (
  code VARCHAR(256), authentication LONGVARBINARY
);

-- drop table if exists oauth_approvals;
create table if not exists oauth_approvals (
  userId VARCHAR(256),
  clientId VARCHAR(256),
  scope VARCHAR(256),
  status VARCHAR(10),
  expiresAt TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
  lastModifiedAt TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00'
);

-- users table
-- drop table if exists users;
create table if not exists users(
  id bigint auto_increment primary key,
  username varchar_ignorecase(50) not null unique,
  password varchar_ignorecase(255) not null,
  enabled boolean not null
);

-- authorities table
-- drop table if exists authorities;
create table if not exists authorities(
  id bigint auto_increment primary key,
  username varchar_ignorecase(50) not null,
  authority varchar_ignorecase(50) not null,
  constraint fk_authorities_users foreign key(username) references users(username)
);
create unique index if not exists ix_auth_username on authorities (username, authority);
