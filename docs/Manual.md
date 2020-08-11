

# Installation and Setup

## requirements

- python 3.5
- virtualenv

## install and setup 

- git pull / download and extract


- run `./rayvyn` for an initial install and setup
- this will setup a basic virtualenv and required modules/dependencies
- in a second step necessray db-migrations and config_files are created



manual setup:
- copy any docs/FILE.yaml.tpl to FILE.yaml and edit accordingly
    - edit `config.yml` to adjust needed settings (system, see [#config_options](below) for options
    - edit `alert_emails.yml` to add alert_emails and [configure](#email_options) which notifications you'd like to receive for which email



## initial run

- run `./rayvyn` for an initial populating of the database (might take some seconds)

## adjust cronjob

- all 4hrs is ok

~~~

42 */4 * * * cd ~/rayvyn && ./rayvyn > logs/rvn.log

~~~



# DB - Migrations, if needed 



 
