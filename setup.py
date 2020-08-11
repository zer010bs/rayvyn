#!/usr/bin/env python3
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
from Model import db

try:
    db_path = "database/db.sqlite"
    engine = create_engine("sqlite:///%s" % db_path)

    if not database_exists(engine.url):
        create_database(engine.url)
    db.create_all()

    print(">> database create: %s :: %s " % (db_path, database_exists(engine.url)))
except:
    print('Database Creation Error')
