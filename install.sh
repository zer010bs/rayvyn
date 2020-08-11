
#!/bin/bash
#
# installer for rayvyn 
#
#


vdir="venv" 


echo "

APP_INSTALLER 

"
echo "[i] Initializing " 

if [ -d "$vdir" ]; then
echo "  >  old venv found, creating new" 
    rm -Rf $vdir
fi
echo "  >  installing new virtual-env in $vdir" 

echo ">  installing virtualenv in $vdir" 
virtualenv -p python3 $vdir


. $vdir/bin/activate

echo ">  installing requirements" 

#pip3 install --upgrade -i https://pypi.python.org/simple/ pip3

pip3 install --upgrade simplejson
pip3 install --upgrade sqlalchemy
pip3 install --upgrade marshmallow
pip3 install --upgrade requests 
pip3 install --upgrade ipaddress  colorama click
pip3 install --upgrade python-dateutil
pip3 install --upgrade cpe
pip3 install --upgrade cvss
pip3 install --upgrade pygments 
pip3 install --upgrade shodan
pip3 install --upgrade marshmallow-sqlalchemy
pip3 install --upgrade flask
pip3 install --upgrade flask_sqlalchemy
pip3 install --upgrade flask_marshmallow
pip3 install --upgrade sqlalchemy_utils
pip3 install --upgrade datetime
pip3 install --upgrade flask_script
pip3 install --upgrade flask_migrate
pip3 install --upgrade PyYAML

mkdir database
mkdir -p migrations/versions
mkdir raw
mkdir logs

#mkdir data


#rm venv/lib/python2.7/no-global-site-packages.txt 






