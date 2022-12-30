drop schema if exists rainbow cascade ;
create schema rainbow;

create table rainbow.users(id serial,username varchar(50) not null unique primary key ,password varchar(500) not null ,enabled bool not null default true);
create table rainbow.authorities(username varchar(50) not null ,authority varchar(50) not null default 'ROLE_USER',constraint fk_user foreign key (username) references rainbow.users(username));
