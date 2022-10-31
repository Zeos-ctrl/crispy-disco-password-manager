# crispy-disco-password-manager

## To set up the database until the docker make file is written run these commands:

>export DATABASE_URL="mysql://root:password@localhost/passwords"
>
>sudo systemctl enable mariadb
>
>sudo systemctl start mariadb
>
>mysql -u root -p
>
>USE passwords;
>
>CREATE TABLE IF NOT EXISTS passwords (
>    username varchar(255) NOT NULL,
>    password varchar(255) NOT NULL
>);

Or migrate from the sql up file in the **Migrations** folder.
