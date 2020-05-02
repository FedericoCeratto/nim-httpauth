
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

build_dbonly_functional_tests:
	nim c -p=. tests/sql_backend_functional.nim

dbonly_sqlite_functional:
	./tests/sql_backend_functional sqlite:///tmp/httpauth_test.sqlite3

dbonly_mysql_functional:
	./tests/sql_backend_functional mysql://httpauthtest@127.0.0.1/httpauth_test

functional_dbonly: build_functional_dbonly_tests dbonly_functional_sqlite dbonly_functional_mysql


# Functional tests
# The libraries for etcd, MongoDB and Redis are required

build_functional_tests:
	nim c -p=. -d:mock_send_email -d:ssl -d:etcd -d:redis tests/functional.nim

build_functional_tests_mongodb:
	# needs nimongo@#head as 20200502
	nim c -p=. -d:mock_send_email -d:ssl -d:mongodb tests/functional.nim

functional_sqlite:
	./tests/functional sqlite:///tmp/httpauth_test.sqlite3

functional_mysql:
	./tests/functional mysql://httpauthtest@127.0.0.1/httpauth_test

functional_etcd:
	./tests/functional etcd://127.0.0.1:2379/httpauth_test

functional_redis:
	./tests/functional redis://127.0.0.1:2884/httpauth_test

functional_mongodb:
	mongo httpauth_test --eval 'db.pending_registrations.drop()'
	mongo httpauth_test --eval 'db.roles.drop()'
	mongo httpauth_test --eval 'db.users.drop()'
	./tests/functional mongodb://127.0.0.1/httpauth_test

unit:
	nim c -p=. -r tests/unit.nim

functional: unit build_functional_tests functional_sqlite functional_mysql functional_etcd build_functional_tests_mongodb functional_mongodb

# CircleCI
# FIXME MySQL Etcd Redis
circleci: unit build_functional_tests functional_sqlite build_functional_tests_mongodb functional_mongodb

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
