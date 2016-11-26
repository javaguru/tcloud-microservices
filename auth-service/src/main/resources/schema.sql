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