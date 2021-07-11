
mysql_create_db_user:
	sudo mysql -e "CREATE USER 'httpauthtest'@'localhost';"
	sudo mysql -e "GRANT ALL ON httpauth_test.* TO 'httpauthtest'@'localhost';" mysql
	sudo mysql -e "FLUSH PRIVILEGES;"

mysql_recreate_database:
	mysql -uhttpauthtest -e "DROP DATABASE IF EXISTS httpauth_test;"
	mysql -uhttpauthtest -e "CREATE DATABASE httpauth_test;"


# Integration test - spawn a local webserver

run_integration_test:
	test -f ./tests/integration_server
	test -f ./tests/integration
	./tests/integration

build_integration_test:
	nim c -p=. -d:ssl -d:mock_send_email tests/integration.nim

build_integration_server:
	# The server is expected to build without installing libraries for optional backends
	nim c -p=. -d:ssl -d:mock_send_email tests/integration_server.nim

integration: build_integration_server build_integration_test run_integration_test


# Database-only tests - httpauth.nim's logic is not tested


dbonly_sqlite_functional:
	DB_URI=sqlite:///tmp/httpauth_test.sqlite3 nim c -r -p=. tests/sql_backend_functional.nim

dbonly_mysql_functional:
	DB_URI=mysql://httpauthtest@127.0.0.1/httpauth_test nim c -r -p=. tests/sql_backend_functional.nim

functional_dbonly: dbonly_functional_sqlite dbonly_functional_mysql


# Functional tests
# The libraries for etcd, MongoDB and Redis are required


functional_sqlite:
	DB_URI=sqlite:///tmp/httpauth_test.sqlite3 nim c -r -p=. -d:mock_send_email -d:ssl tests/functional.nim

functional_mysql:
	DB_URI=mysql://httpauthtest@127.0.0.1/httpauth_test nim c -r -p=. -d:mock_send_email -d:ssl -d:mysql tests/functional.nim

functional_postgresql:
	DB_URI=postgresql://httpauthtest@127.0.0.1/httpauth_test nim c -r -p=. -d:mock_send_email -d:ssl -d:mysql tests/functional.nim
  
functional_etcd:
	DB_URI=etcd://127.0.0.1:2379/httpauth_test nim c -r -p=. -d:mock_send_email -d:ssl -d:etcd tests/functional.nim

functional_redis:
	DB_URI=redis://127.0.0.1:2884/httpauth_test nim c -r -p=. -d:mock_send_email -d:ssl -d:redis tests/functional.nim

functional_mongodb:
	# needs nimongo@#head as 20200502
	mongo httpauth_test --eval 'db.pending_registrations.drop()'
	mongo httpauth_test --eval 'db.roles.drop()'
	mongo httpauth_test --eval 'db.users.drop()'
	DB_URI=mongodb://127.0.0.1/httpauth_test nim c -p=. -d:mock_send_email -d:ssl -d:mongodb tests/functional.nim

unit:
	nim c -p=. -r tests/unit.nim

functional: unit functional_sqlite functional_mysql functional_etcd functional_mongodb

# CircleCI
# FIXME MySQL Etcd MongoDB
circleci: unit functional_sqlite functional_redis

start_databases:
	sudo systemctl start etcd.service
	sudo systemctl start mongodb.service
	sudo systemctl start mysql.service
	sudo systemctl start redis-server.service

stop_databases:
	sudo systemctl stop etcd.service
	sudo systemctl stop mongodb.service
	sudo systemctl stop mysql.service
	sudo systemctl stop redis-server.service
