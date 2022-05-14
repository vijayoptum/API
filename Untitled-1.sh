// Connect 21cEE DB : 
/ as sys

// Get host Name : 
select utl_inaddr.get_host_name from dual;

// get SERVICE_NAME :
 select sys_context('USERENV', 'SERVICE_NAME') from dual;

 alter session set "_ORACLE_SCRIPT"=true;

CREATE USER HR IDENTIFIED BY hr

grant connect to vijay;
grant create view to vijay;
grant create table to vijay;
grant create trigger to vijay;

<span class="es rz ra hi sa b ch sb sc l sd" data-selectable-paragraph="" id="3eb0">docker run -d -p 1521:1521 -e ORACLE_PASSWORD=TheSuperSecret1509! gvenzl/oracle-xe</span>